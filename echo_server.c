/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * echo_server.c -- QUIC server that echoes back input line by line
 */

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#include <netinet/in.h>
#else
#include "vc_compat.h"
#include "getopt.h"
#endif

#include <event2/event.h>

#include <lsquic.h>
#include <lsquic_hash.h>
#include <lsquic_logger.h>

#include "common.h"
#include "cert.h"
#include "prog.h"
#include "vpn.h"
#include "os.h"

struct lsquic_conn_ctx;

struct echo_server_ctx {
    TAILQ_HEAD(, lsquic_conn_ctx)   conn_ctxs;
    unsigned max_reqs;
    int n_conn;
    struct sport_head sports;
    struct prog *prog;
    Context *vpn_ctx;
};

struct lsquic_conn_ctx {
    TAILQ_ENTRY(lsquic_conn_ctx)    next_connh;
    lsquic_conn_t       *conn;
    struct echo_server_ctx   *server_ctx;
};


static lsquic_conn_ctx_t *
echo_server_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    struct echo_server_ctx *server_ctx = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = calloc(1, sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->server_ctx = server_ctx;
    TAILQ_INSERT_TAIL(&server_ctx->conn_ctxs, conn_h, next_connh);
    LSQ_NOTICE("New connection!");
    print_conn_info(conn);
    return conn_h;
}


static void
echo_server_on_conn_closed (lsquic_conn_t *conn)
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
    struct echo_server_ctx   *server_ctx;
    struct event        *read_tun_ev;
    char                 buf[0x100];
    size_t               buf_off;
};

static void tun_read_handler(int fd, short event, void *ctx){
    ssize_t              len;
    lsquic_stream_ctx_t *st_h = ctx;


    LSQ_INFO("read from tun!");

    len = tun_read(fd, st_h->buf + st_h->buf_off++, 1400);
    if (len <= 0) {
        perror("tun_read");
        return;
    }

    LSQ_DEBUG("read newline: wantwrite");
    lsquic_stream_wantwrite(st_h->stream, 1);
    lsquic_engine_process_conns(st_h->server_ctx->prog->prog_engine);
}

static lsquic_stream_ctx_t *
echo_server_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    lsquic_stream_ctx_t *st_h = malloc(sizeof(*st_h));
    st_h->stream = stream;
    st_h->server_ctx = stream_if_ctx;
    st_h->buf_off = 0;
    lsquic_stream_wantread(stream, 1);

    st_h->read_tun_ev = event_new(prog_eb(st_h->server_ctx->prog),
                                   st_h->server_ctx->vpn_ctx->tun_fd, EV_READ, tun_read_handler, st_h);
    event_add(st_h->read_tun_ev, NULL);

    return st_h;
}


static struct lsquic_conn_ctx *
find_conn_h (const struct echo_server_ctx *server_ctx, lsquic_stream_t *stream)
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
echo_server_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct lsquic_conn_ctx *conn_h;
    size_t nr;

    nr = lsquic_stream_read(stream, st_h->buf + st_h->buf_off++, 1);
    if (0 == nr)
    {
        LSQ_NOTICE("EOF: closing connection");
        lsquic_stream_shutdown(stream, 2);
        conn_h = find_conn_h(st_h->server_ctx, stream);
        lsquic_conn_close(conn_h->conn);
    }
    else if ('\n' == st_h->buf[ st_h->buf_off - 1 ])
    {
        /* Found end of line: echo it back */
        lsquic_stream_wantwrite(stream, 1);
        lsquic_stream_wantread(stream, 0);
    }
    else if (st_h->buf_off == sizeof(st_h->buf))
    {
        /* Out of buffer space: line too long */
        LSQ_NOTICE("run out of buffer space");
        lsquic_stream_shutdown(stream, 2);
    }
    else
    {
        /* Keep reading */;
    }
}


static void
echo_server_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    lsquic_stream_write(stream, st_h->buf, st_h->buf_off);
    st_h->buf_off = 0;
    lsquic_stream_flush(stream);
    lsquic_stream_wantwrite(stream, 0);
    lsquic_stream_wantread(stream, 1);
}


static void
echo_server_on_stream_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct lsquic_conn_ctx *conn_h;
    LSQ_NOTICE("%s called", __func__);
    conn_h = find_conn_h(st_h->server_ctx, stream);
    LSQ_WARN("%s: TODO: free connection handler %p", __func__, conn_h);
    free(st_h);
}


const struct lsquic_stream_if server_echo_stream_if = {
    .on_new_conn            = echo_server_on_new_conn,
    .on_conn_closed         = echo_server_on_conn_closed,
    .on_new_stream          = echo_server_on_new_stream,
    .on_read                = echo_server_on_read,
    .on_write               = echo_server_on_write,
    .on_close               = echo_server_on_stream_close,
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

static int resolve_ip(char *ip, size_t sizeof_ip, const char *ip_or_name)
{
    struct addrinfo hints, *res;
    int             eai;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags    = 0;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_addr     = NULL;
    if ((eai = getaddrinfo(ip_or_name, NULL, &hints, &res)) != 0 ||
        (res->ai_family != AF_INET && res->ai_family != AF_INET6) ||
        (eai = getnameinfo(res->ai_addr, res->ai_addrlen, ip, (socklen_t) sizeof_ip, NULL, 0,
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        fprintf(stderr, "Unable to resolve [%s]: [%s]\n", ip_or_name, gai_strerror(eai));
        return -1;
    }
    return 0;
}

int
main (int argc, char **argv)
{
    int opt, s;
    struct prog prog;
    struct echo_server_ctx server_ctx;
    Context     context;

    memset(&server_ctx, 0, sizeof(server_ctx));
    server_ctx.prog = &prog;
    server_ctx.vpn_ctx= &context;
    TAILQ_INIT(&server_ctx.sports);
    TAILQ_INIT(&server_ctx.conn_ctxs);

    prog_init(&prog, LSENG_SERVER, &server_ctx.sports,
                                        &server_echo_stream_if, &server_ctx);

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

    add_alpn("echo");
    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");

    memset(&context, 0, sizeof(context));
    context.is_server = 1;
    context.server_ip_or_name  = "auto";
    context.server_port    = "auto";
    context.wanted_if_name = "";
    context.local_tun_ip = DEFAULT_SERVER_IP;
    context.remote_tun_ip = DEFAULT_CLIENT_IP;
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
        firewall_rules(&context, 0, 1);
    }

    s = prog_run(&prog);
    prog_cleanup(&prog);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
