/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * vpn_client.c -- This is really a "line client:" it connects to QUIC server
 * and sends it stuff, line by line.  It works in tandem with vpn_server.
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
    ssize_t              len;
    lsquic_stream_ctx_t *st_h = ctx;

    len = tun_read(fd, st_h->buf, BUFF_SIZE);
    if (len <= 0) {
        perror("tun_read");
        return;
    }

    st_h->buf_off = len;
    LSQ_INFO("read from tun %zu bytes", len);

    lsquic_stream_wantwrite(st_h->stream, 1);
    lsquic_engine_process_conns(st_h->client_ctx->prog->prog_engine);

    event_add(st_h->read_tun_ev, NULL);
}

static void 
vpn_client_after_new_stream(lsquic_stream_ctx_t * st_h){
    char hello[] = "Hello";

    memcpy(st_h->buf, hello, sizeof(hello) + 1);
    st_h->buf_off = st_h->buf_off + sizeof(hello) + 1;

    lsquic_stream_wantwrite(st_h->stream, 1);
}

static lsquic_stream_ctx_t *
vpn_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    lsquic_stream_ctx_t *st_h = calloc(1, sizeof(*st_h));
    st_h->stream = stream;
    st_h->client_ctx = stream_if_ctx;
    st_h->buf_off = 0;

    vpn_client_after_new_stream(st_h);
    
    st_h->read_tun_ev = event_new(prog_eb(st_h->client_ctx->prog),
                                    st_h->client_ctx->vpn_ctx->tun_fd, EV_READ, tun_read_handler, st_h);
    event_add(st_h->read_tun_ev, NULL);
    return st_h;
}


static void
vpn_client_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    char c;
    size_t len;
    char *tmp;

    len = lsquic_stream_read(stream, st_h->buf, BUFF_SIZE);
    if (0 == len)
    {
        lsquic_stream_shutdown(stream, 2);
        return;
    }

    st_h->buf_off = len;
    LSQ_INFO("read from server channel %zu bytes", len);

    if(st_h->client_ctx->vpn_ctx->tun_fd == -1){
        st_h->client_ctx->vpn_ctx->local_tun_ip = &st_h->buf[0];
        st_h->client_ctx->vpn_ctx->remote_tun_ip = strchr(st_h->client_ctx->vpn_ctx->local_tun_ip, ',');
        *st_h->client_ctx->vpn_ctx->remote_tun_ip = '\0';
        st_h->client_ctx->vpn_ctx->remote_tun_ip++;
        tmp = strchr(st_h->client_ctx->vpn_ctx->remote_tun_ip, '\n');
        *tmp = '\0';

        LSQ_INFO("local_ip: %s, remote_ip: %s", st_h->client_ctx->vpn_ctx->local_tun_ip, st_h->client_ctx->vpn_ctx->remote_tun_ip);

        
        if(vpn_init(st_h->client_ctx->vpn_ctx, IS_CLIENT) == -1)
            exit(1);

        st_h->read_tun_ev = event_new(prog_eb(st_h->client_ctx->prog),
                                   st_h->client_ctx->vpn_ctx->tun_fd, EV_READ, tun_read_handler, st_h);
        goto end;
    }

    if (tun_write(st_h->client_ctx->vpn_ctx->tun_fd, st_h->buf, len) != len) {
        LSQ_ERROR("tun_write");
    }else{
        LSQ_DEBUG("tun_write %zu bytes", len);
    }

end:
    event_add(st_h->read_tun_ev, NULL);
    lsquic_stream_wantread(stream, 1);
}


static void
vpn_client_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    /* Here we make an assumption that we can write the whole buffer.
     * Don't do it in a real program.
     */
    lsquic_stream_write(stream, st_h->buf, st_h->buf_off);
    st_h->buf_off = 0;

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
    free(st_h);
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
