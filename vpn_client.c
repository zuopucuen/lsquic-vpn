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

#ifndef WIN32
#include <fcntl.h>
#include <unistd.h>
#define Read read
#else
#include "vc_compat.h"
#include "getopt.h"
#include <io.h>
#define Read _read
#define STDIN_FILENO 0
#endif

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
    Context  *vpn_ctx;
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


static lsquic_stream_ctx_t *
vpn_client_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    lsquic_stream_ctx_t *st_h = calloc(1, sizeof(*st_h));
    st_h->stream = stream;
    st_h->client_ctx = stream_if_ctx;
    st_h->buf_off = 0;
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

    len = lsquic_stream_read(stream, st_h->buf, BUFF_SIZE);
    if (0 == len)
    {
        lsquic_stream_shutdown(stream, 2);
        return;
    }

    st_h->buf_off = len;
    LSQ_INFO("read from server channel %zu bytes", len);

    if (tun_write(st_h->client_ctx->vpn_ctx->tun_fd, st_h->buf, len) != len) {
        LSQ_ERROR("tun_write");
    }else{
        LSQ_DEBUG("tun_write %zu bytes", len);
    }

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


const struct lsquic_stream_if client_echo_stream_if = {
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
    Context     context;

    memset(&context, 0, sizeof context);
    context.is_server = 0;
    context.server_ip_or_name  = "auto";
    context.server_port    = "auto";
    context.wanted_if_name = "";
    context.local_tun_ip = DEFAULT_CLIENT_IP;
    context.remote_tun_ip = DEFAULT_SERVER_IP;
    context.wanted_ext_gw_ip = "auto";

    if ((context.ext_if_name = get_default_ext_if_name()) == NULL && context.is_server) {
        fprintf(stderr, "Unable to automatically determine the external interface\n");
        return 1;
    }
    context.tun_fd = tun_create(context.if_name, context.wanted_if_name);
    
    if (context.tun_fd == -1) {
        perror("tun device creation");
        return 1;
    }

    printf("Interface: [%s]\n", context.if_name);
    if (tun_set_mtu(context.if_name, DEFAULT_MTU) != 0) {
        perror("mtu");
    }

    #ifdef __OpenBSD__
    pledge("stdio proc exec dns inet", NULL);
    #endif
    context.firewall_rules_set = -1;
    /*
    if (context.server_ip_or_name != NULL &&
        resolve_ip(context.server_ip, sizeof context.server_ip, context.server_ip_or_name) != 0) {
        firewall_rules(&context, 0, 1);
        return 1;
    }
    */
    if (context.is_server) {
        if (firewall_rules(&context, 1, 0) != 0) {
            return -1;
        }
#ifdef __OpenBSD__
        printf("\nAdd the following rule to /etc/pf.conf:\npass out from %s nat-to egress\n\n",
               context.remote_tun_ip);
#endif
    } else {
        firewall_rules(&context, 1, 1);
    }


#ifdef WIN32
    fprintf(stderr, "%s does not work on Windows, see\n"
        "https://github.com/litespeedtech/lsquic/issues/219\n", argv[0]);
    exit(EXIT_FAILURE);
#endif

    memset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.prog = &prog;
    client_ctx.vpn_ctx = &context;

    TAILQ_INIT(&sports);
    prog_init(&prog, 0, &sports, &client_echo_stream_if, &client_ctx);
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

#ifndef WIN32
    int flags = fcntl(STDIN_FILENO, F_GETFL);
    flags |= O_NONBLOCK;
    if (0 != fcntl(STDIN_FILENO, F_SETFL, flags))
    {
        perror("fcntl");
        exit(1);
    }
#else
    {
        u_long on = 1;
        ioctlsocket(STDIN_FILENO, FIONBIO, &on);
    }
#endif

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
