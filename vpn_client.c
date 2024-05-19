/*
 * vpn_client.c -- QUIC client that for peer to peer vpn
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#define Read read

#include <event2/event.h>

#include <lsquic.h>
#include <lsquic_logger.h>

#include "common.h"
#include "prog.h"
#include "vpn.h"
#include "os.h"


struct lsquic_conn_ctx;

struct vpn_client_ctx {
    struct lsquic_conn_ctx  *conn_h;
    struct prog                 *prog;
    vpn_ctx_t  *vpn_ctx;
};

struct lsquic_conn_ctx {
    lsquic_conn_t       *conn;
    struct vpn_client_ctx   *client_ctx;
};


static lsquic_conn_ctx_t *
vpn_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct vpn_client_ctx *client_ctx = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = malloc(sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->client_ctx = client_ctx;
    client_ctx->conn_h = conn_h;
    lsquic_conn_make_stream(conn);
    return conn_h;
}


static void
vpn_client_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    LSQ_NOTICE("Connection closed");
    prog_stop(conn_h->client_ctx->prog);

    lsquic_conn_set_ctx(conn, NULL);
    free(conn_h);
}


struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct vpn_client_ctx   *client_ctx;
    struct event        *read_tun_ev;
    char                 buf[BUFF_SIZE];
    size_t               buf_off;
};



static void tun_read_handler(int fd, short event, void *ctx){
    size_t len;
    lsquic_stream_ctx_t *st_h = ctx;

    LSQ_INFO("buf off before read tun: %zu bytes", st_h->buf_off);
    if(st_h->buf_off + BUFF_SIZE/2 > BUFF_SIZE){
        goto end;
    }

    len = vpn_tun_read(fd, st_h->buf, st_h->buf_off);

    if(len > 0){
        st_h->buf_off = len;
    }

    lsquic_stream_wantwrite(st_h->stream, 1);
    lsquic_engine_process_conns(st_h->client_ctx->prog->prog_engine);

end:
    event_add(st_h->read_tun_ev, NULL);
}

static void 
vpn_client_after_new_stream(lsquic_stream_ctx_t * st_h){
    char hello[] = "Hello";

    memcpy(&(st_h->buf[1]), hello, sizeof(hello));
    st_h->buf_off = st_h->buf_off + sizeof(hello);

    lsquic_stream_wantwrite(st_h->stream, 1);
}

static lsquic_stream_ctx_t *
vpn_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    lsquic_stream_ctx_t *st_h = calloc(1, sizeof(*st_h));
    st_h->stream = stream;
    st_h->client_ctx = stream_if_ctx;

    vpn_client_after_new_stream(st_h);
    
    st_h->read_tun_ev = event_new(prog_eb(st_h->client_ctx->prog),
                                    st_h->client_ctx->vpn_ctx->tun_fd, EV_READ, tun_read_handler, st_h);
    event_add(st_h->read_tun_ev, NULL);
    return st_h;
}


static void
vpn_client_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    size_t len, packet_size, buf_used;
    char *tmp, *cur_buf;
    vpn_ctx_t *vpn_ctx;

    vpn_ctx = st_h->client_ctx->vpn_ctx;
    cur_buf = vpn_ctx->packet_buf + vpn_ctx->buf_off;
    buf_used =  vpn_ctx->packet_buf - vpn_ctx->buf + vpn_ctx->buf_off;

    if((BUFF_SIZE - buf_used) <=1){
        exit(1);
    }

    len = lsquic_stream_read(stream, cur_buf, BUFF_SIZE - buf_used);
    if (len <= 0)
    {
        lsquic_stream_shutdown(stream, 2);
        exit(1);
    }

    LSQ_INFO("read from stream %llu: %zd bytes, bufsize: %zu", lsquic_stream_id(stream), len, BUFF_SIZE - buf_used);

    if(vpn_ctx->tun_fd == -1){
        vpn_ctx->local_tun_ip = cur_buf;

        vpn_ctx->remote_tun_ip = strchr(vpn_ctx->local_tun_ip, ',');
        *vpn_ctx->remote_tun_ip = '\0';
        vpn_ctx->remote_tun_ip++;
        tmp = strchr(vpn_ctx->remote_tun_ip, '\n');
        *tmp = '\0';

        LSQ_INFO("local_ip: %s, remote_ip: %s", vpn_ctx->local_tun_ip, vpn_ctx->remote_tun_ip);

        
        if(vpn_init(vpn_ctx, IS_CLIENT) == -1)
            exit(1);

        st_h->read_tun_ev = event_new(prog_eb(st_h->client_ctx->prog),
                                   vpn_ctx->tun_fd, EV_READ, tun_read_handler, st_h);
        goto end;
    }
    
    vpn_ctx->buf_off = vpn_ctx->buf_off + len;
    vpn_tun_write(vpn_ctx);

end:
    event_add(st_h->read_tun_ev, NULL);
    lsquic_stream_wantread(stream, 1);
}


static void
vpn_client_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    size_t len;
    size_t total_written = 0;

    while (total_written < st_h->buf_off) {
        len = lsquic_stream_write(stream, st_h->buf + total_written , st_h->buf_off - total_written);;

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

    if (total_written == st_h->buf_off) {
        st_h->buf_off = 0;
    } else if(total_written > 0) {
        st_h->buf_off -= total_written;
        memmove(st_h->buf, st_h->buf + total_written, st_h->buf_off);
    }

    lsquic_stream_flush(stream);
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_wantread(stream, 1);
}


static void
vpn_client_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    LSQ_NOTICE("%s called", __func__);
    if (st_h->read_tun_ev)
    {
        event_del(st_h->read_tun_ev);
        event_free(st_h->read_tun_ev);
    }
    lsquic_conn_close(lsquic_stream_conn(stream));
}


const struct lsquic_stream_if client_vpn_stream_if = {
    .on_new_conn            = vpn_client_on_new_conn,
    .on_conn_closed         = vpn_client_on_conn_closed,
    .on_new_stream          = vpn_client_on_new_stream,
    .on_read                = vpn_client_on_read,
    .on_write               = vpn_client_on_write,
    .on_close               = vpn_client_on_close,
};


static void
usage (const char *prog)
{
    const char *const slash = strrchr(prog, '/');
    if (slash)
        prog = slash + 1;
    LSQ_NOTICE(
"Usage: %s [opts]\n"
"\n"
"Options:\n"
            , prog);
}


int
main (int argc, char **argv)
{
    int opt, s;
    struct sport_head sports;
    struct prog prog;
    struct vpn_client_ctx client_ctx;
    vpn_ctx_t     vpn_ctx;

    memset(&client_ctx, 0, sizeof(client_ctx));
    memset(&vpn_ctx, 0, sizeof(vpn_ctx));
    vpn_ctx.tun_fd = -1;
    client_ctx.prog = &prog;
    client_ctx.vpn_ctx = &vpn_ctx;
    client_ctx.vpn_ctx->packet_buf = vpn_ctx.buf;
    client_ctx.vpn_ctx->buf_off = 0;

    TAILQ_INIT(&sports);
    prog_init(&prog, 0, &sports, &client_vpn_stream_if, &client_ctx);
    prog.prog_api.ea_alpn = "echo";

    while (-1 != (opt = getopt(argc, argv, PROG_OPTS "h")))
    {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&prog, stdout);
            exit(0);
        default:
            if (0 != prog_set_opt(&prog, opt, optarg))
                exit(1);
        }
    }

    int flags = fcntl(STDIN_FILENO, F_GETFL);
    flags |= O_NONBLOCK;
    if (0 != fcntl(STDIN_FILENO, F_SETFL, flags))
    {
        perror("fcntl");
        exit(1);
    }

    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }
    if (0 != prog_connect(&prog, NULL, 0))
    {
        LSQ_ERROR("could not connect");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");

    s = prog_run(&prog);
    prog_cleanup(&prog);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
