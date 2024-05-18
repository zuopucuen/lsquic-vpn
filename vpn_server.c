/*
 * vpn_server.c -- QUIC server that for peer to peer vpn
 */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>

#include <event2/event.h>

#include <lsquic.h>
#include <lsquic_hash.h>
#include <lsquic_logger.h>

#include "common.h"
#include "cert.h"
#include "prog.h"
#include "vpn.h"
#include "os.h"

struct vpn_server_ctx {
    TAILQ_HEAD(, lsquic_conn_ctx)   conn_ctxs;
    int n_conn;
    struct sport_head sports;
    struct prog *prog;
    vpn_t *vpn;
};

struct lsquic_conn_ctx {
    TAILQ_ENTRY(lsquic_conn_ctx)    next_connh;
    lsquic_conn_t       *conn;
    struct vpn_server_ctx   *server_ctx;
};

static lsquic_conn_ctx_t *
vpn_server_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct vpn_server_ctx *server_ctx = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = calloc(1, sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->server_ctx = server_ctx;

    TAILQ_INSERT_TAIL(&server_ctx->conn_ctxs, conn_h, next_connh);
    LSQ_NOTICE("New connection!");
    print_conn_info(conn);
    return conn_h;
}


static void
vpn_server_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    if (conn_h->server_ctx->n_conn)
    {
        --conn_h->server_ctx->n_conn;
        LSQ_NOTICE("Connection closed, remaining: %d", conn_h->server_ctx->n_conn);
        if (0 == conn_h->server_ctx->n_conn)
            prog_stop(conn_h->server_ctx->prog);
    }
    else
        LSQ_NOTICE("Connection closed");
    TAILQ_REMOVE(&conn_h->server_ctx->conn_ctxs, conn_h, next_connh);

    lsquic_conn_set_ctx(conn, NULL);
    free(conn_h);
}


struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct vpn_server_ctx   *server_ctx;
    vpn_ctx_t           *vpn_ctx;
    struct event        *read_tun_ev;
    char                 buf[BUFF_SIZE];
    size_t               buf_off;
};

static void tun_read_handler(int fd, short event, void *ctx){
    size_t len;
    lsquic_stream_ctx_t *st_h = ctx;

    len = vpn_tun_read(fd, st_h->buf, st_h->buf_off);

    if(len > 0){
        st_h->buf_off = len;
    }

    lsquic_stream_wantwrite(st_h->stream, 1);
    lsquic_engine_process_conns(st_h->server_ctx->prog->prog_engine);

    event_add(st_h->read_tun_ev, NULL);
}

static lsquic_stream_ctx_t *
vpn_server_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    struct vpn_server_ctx *server_ctx = stream_if_ctx;
    lsquic_stream_ctx_t *st_h = malloc(sizeof(*st_h));
    vpn_ctx_t *vpn_ctx = malloc(sizeof(*vpn_ctx));

    memset(st_h, 0, sizeof(*st_h));
    memset(vpn_ctx, 0, sizeof(*vpn_ctx));

    vpn_ctx->tun_fd = -1;
    vpn_ctx->addr_index = -1;
    vpn_ctx->vpn = server_ctx->vpn;
    vpn_ctx->packet_buf = vpn_ctx->buf;
    vpn_ctx->buf_off = 0;

    st_h->stream = stream;
    st_h->server_ctx = server_ctx;
    st_h->vpn_ctx = vpn_ctx;
    st_h->buf_off = 0;

    lsquic_stream_wantread(stream, 1);

    return st_h;
}

static struct lsquic_conn_ctx *
find_conn_h (const struct vpn_server_ctx *server_ctx, lsquic_stream_t *stream)
{
    struct lsquic_conn_ctx *conn_h;
    lsquic_conn_t *conn;

    conn = lsquic_stream_conn(stream);
    TAILQ_FOREACH(conn_h, &server_ctx->conn_ctxs, next_connh)
        if (conn_h->conn == conn)
            return conn_h;
    return NULL;
}

static void
vpn_server_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct lsquic_conn_ctx *conn_h;
    vpn_ctx_t *vpn_ctx;
    vpn_t *vpn;
    vpn_tun_addr_t *addr;
    size_t addr_index, len, buf_used;
    char * cur_buf;

    vpn_ctx = st_h->vpn_ctx;
    vpn = vpn_ctx->vpn;
    cur_buf = vpn_ctx->packet_buf + vpn_ctx->buf_off;
    buf_used =  vpn_ctx->packet_buf - vpn_ctx->buf + vpn_ctx->buf_off;

    len = lsquic_stream_read(stream, cur_buf, BUFF_SIZE - buf_used);
    if (len <= 0)
    {
        goto end;
    }

    LSQ_INFO("read from stream %llu: %zd bytes, bufsize: %zu", lsquic_stream_id(stream), len, BUFF_SIZE - buf_used);
    
    if(vpn_ctx->tun_fd == -1){
        LSQ_INFO("say Hello: %s", cur_buf+1);
        addr_index = 0;

        while(addr_index < vpn->max_conn && vpn->addrs[addr_index]->is_used == 1  ){
            addr_index++;
        }

        if(addr_index >= vpn->max_conn){
            LSQ_WARN("have no addr");
            goto end;
        }

        vpn_ctx->addr_index = addr_index - 1;
        vpn_ctx->local_tun_ip = vpn->addrs[addr_index]->local_ip;
        vpn_ctx->remote_tun_ip = vpn->addrs[addr_index]->remote_ip;

        LSQ_INFO("Initialization of the new link address was successful :index: %d,local ip: %s, remote_ip: %s",
            vpn_ctx->addr_index,
            vpn_ctx->local_tun_ip, 
            vpn_ctx->remote_tun_ip
        );
        len = sprintf(st_h->buf, "%s,%s\n", vpn_ctx->remote_tun_ip, vpn_ctx->local_tun_ip);
        st_h->buf_off = len;
        lsquic_stream_wantread(stream, 0);
        lsquic_stream_wantwrite(stream, 1);

        if(vpn_init(st_h->vpn_ctx, IS_SERVER) == -1) {
            LSQ_ERROR("cannot create tun");
            goto end;
        }

        vpn->addrs[addr_index]->is_used = 1;
        st_h->read_tun_ev = event_new(prog_eb(st_h->server_ctx->prog),
                                   vpn_ctx->tun_fd, EV_READ, tun_read_handler, st_h);
        event_add(st_h->read_tun_ev, NULL);

        goto out;
    }

    vpn_ctx->buf_off = vpn_ctx->buf_off + len;
    vpn_tun_write(vpn_ctx);

out:
    lsquic_stream_wantread(stream, 1);
    return;

end:
        LSQ_NOTICE("closing connection");
        lsquic_stream_shutdown(stream, 2);
        conn_h = find_conn_h(st_h->server_ctx, stream);
        lsquic_conn_close(conn_h->conn);
}

static void
vpn_server_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    size_t len;
    size_t total_written = 0;
    while (total_written < st_h->buf_off) {
        len = lsquic_stream_write(stream, st_h->buf + total_written , st_h->buf_off - total_written);

        if(len == 0){
            break;
        } else if(len<0) {
            int err = errno;
            if (err == EWOULDBLOCK || err == EAGAIN) {
                LSQ_WARN("Stream not ready for writing, try again later\n");
                break;
            }

            LSQ_ERROR("Error writing to stream: %s\n", strerror(err));
            lsquic_conn_close(lsquic_stream_conn(stream));
            return;
        } 
        
        LSQ_INFO("write to client %llu: %zd bytes, total : %zu bytes", lsquic_stream_id(stream), len, st_h->buf_off - total_written);
        total_written += len;
    }

    st_h->buf_off -= total_written;
    if(st_h->buf_off > 0){
        memmove(st_h->buf, st_h->buf + total_written, st_h->buf_off);
    }

    lsquic_stream_flush(stream);
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_wantread(stream, 1);
}


static void
vpn_server_on_stream_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct lsquic_conn_ctx *conn_h;
    vpn_ctx_t *vpn_ctx;
    vpn_t *vpn;
    vpn_ctx = st_h->vpn_ctx;
    vpn = st_h->vpn_ctx->vpn;

    if(vpn_ctx->addr_index != -1)
        vpn->addrs[vpn_ctx->addr_index]->is_used = 0;

    if(st_h->read_tun_ev)
        event_del(st_h->read_tun_ev);
    close(vpn_ctx->tun_fd);

    LSQ_NOTICE("%s called", __func__);
    conn_h = find_conn_h(st_h->server_ctx, stream);
    LSQ_WARN("%s: TODO: free connection handler %p", __func__, conn_h);
    free(vpn_ctx);
    free(st_h);
}

const struct lsquic_stream_if server_vpn_stream_if = {
    .on_new_conn            = vpn_server_on_new_conn,
    .on_conn_closed         = vpn_server_on_conn_closed,
    .on_new_stream          = vpn_server_on_new_stream,
    .on_read                = vpn_server_on_read,
    .on_write               = vpn_server_on_write,
    .on_close               = vpn_server_on_stream_close,
};

static void
usage (const char *prog)
{
    const char *const slash = strrchr(prog, '/');
    if (slash)
        prog = slash + 1;
    printf(
"Usage: %s [opts]\n"
"\n"
"Options:\n"
                , prog);
}

int
main (int argc, char **argv)
{
    int opt, s;
    struct prog prog;
    struct vpn_server_ctx server_ctx;
    vpn_t     vpn;

    memset(&server_ctx, 0, sizeof(server_ctx));
    server_ctx.prog = &prog;
    server_ctx.vpn= &vpn;
    TAILQ_INIT(&server_ctx.sports);
    TAILQ_INIT(&server_ctx.conn_ctxs);

    prog_init(&prog, LSENG_SERVER, &server_ctx.sports,
                                        &server_vpn_stream_if, &server_ctx);

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "hn:")))
    {
        switch (opt) {
        case 'n':
            server_ctx.n_conn = atoi(optarg);
            break;
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&prog, stdout);
            exit(0);
        default:
            if (0 != prog_set_opt(&prog, opt, optarg))
                exit(1);
        }
    }


    if(addr_init(&vpn, 5) <= 0){ 
        LSQ_ERROR("vpn init error");
        exit(EXIT_FAILURE);
    }

    add_alpn("echo");
    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");

    s = prog_run(&prog);
    prog_cleanup(&prog);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
