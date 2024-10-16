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

#include "vpn.h"

static lsquic_conn_ctx_t *
vpn_client_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    lsquic_vpn_ctx_t *lsquic_vpn_ctx = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = malloc(sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->lsquic_vpn_ctx = lsquic_vpn_ctx;
    lsquic_vpn_ctx->conn_h = conn_h;

    lsquic_conn_ctx_init(conn_h);
    lsquic_conn_make_stream(conn);
    return conn_h;
}


static void
vpn_client_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    vpn_ctx_t * vpn_ctx = conn_h->vpn_ctx;

    if (tun_route_set(vpn_ctx->tun, 0) != 0) {
        LSQ_ERROR("set Firewall rules faile");
    }

    LSQ_NOTICE("Connection closed");
    prog_stop(conn_h->lsquic_vpn_ctx->prog);

    lsquic_conn_set_ctx(conn, NULL);
    free(conn_h);
    exit(EXIT_SUCCESS);
}

void 
vpn_after_new_stream(lsquic_stream_ctx_t * st_h){
    memcpy(&(st_h->buf[0]), st_h->lsquic_vpn_ctx->tun->remote_tun_ip, strlen(st_h->lsquic_vpn_ctx->tun->remote_tun_ip));
    st_h->buf_off = st_h->buf_off + strlen(st_h->lsquic_vpn_ctx->tun->remote_tun_ip);
    
    lsquic_stream_wantwrite(st_h->stream, 1);
    lsquic_stream_wantread(st_h->stream, 1);
}

static void
vpn_client_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    ssize_t len, packet_size, buf_used;
    char *tmp, *cur_buf;
    lsquic_conn_ctx_t *conn_h = st_h->conn_h;
    vpn_ctx_t *vpn_ctx = conn_h->vpn_ctx;
    struct service_port *sport;

    cur_buf = vpn_ctx->packet_buf + vpn_ctx->buf_off;
    buf_used =  vpn_ctx->packet_buf - vpn_ctx->buf + vpn_ctx->buf_off;

    if((BUFF_SIZE - buf_used) <=1){
        LSQ_ERROR("BUFF_SIZE < buf_used: %d, %zu", BUFF_SIZE, buf_used);
        exit(1);
    }

    len = lsquic_stream_read(stream, cur_buf, BUFF_SIZE - buf_used);

    if (len <=0 && errno != EWOULDBLOCK)
    {
        lsquic_stream_shutdown(stream, 2);
        LSQ_ERROR("read from stream error");
        exit(1);
    }

    LSQ_INFO("read from stream %llu: %zd bytes, bufsize: %zu", lsquic_stream_id(stream), len, BUFF_SIZE - buf_used);

    if(vpn_ctx->tun_fd == -1){
        sport = TAILQ_LAST(st_h->lsquic_vpn_ctx->prog->prog_sports, sport_head);
        
        vpn_ctx->tun = st_h->lsquic_vpn_ctx->tun;
        vpn_ctx->tun->server_ip = sport->host;
        vpn_ctx->tun->ext_gw_ip = get_default_gw_ip();

        tun_init(vpn_ctx->tun);

        vpn_ctx->tun_fd = vpn_ctx->tun->fd;

        LSQ_INFO("server ip %s, gw ip %s ", vpn_ctx->tun->server_ip,  vpn_ctx->tun->ext_gw_ip);

        vpn_ctx->tun_read_ev = event_new(prog_eb(st_h->lsquic_vpn_ctx->prog),
                                   vpn_ctx->tun_fd, EV_READ, tun_read_handler, st_h);
        vpn_ctx->tun_write_ev = event_new(prog_eb(st_h->lsquic_vpn_ctx->prog),
                                   vpn_ctx->tun_fd, EV_WRITE, tun_write_handler, vpn_ctx);

        lsquic_stream_wantwrite(stream, 0);
        event_add(vpn_ctx->tun_read_ev, NULL);
    }

    vpn_tun_write(vpn_ctx);
    lsquic_stream_wantread(stream, 1);
}


static void
vpn_client_on_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    LSQ_NOTICE("%s called", __func__);
    lsquic_conn_close(lsquic_stream_conn(stream));
}


const struct lsquic_stream_if client_vpn_stream_if = {
    .on_new_conn            = vpn_client_on_new_conn,
    .on_conn_closed         = vpn_client_on_conn_closed,
    .on_new_stream          = vpn_on_new_stream,
    .on_read                = vpn_client_on_read,
    .on_write               = vpn_on_write,
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
    lsquic_vpn_ctx_t lsquic_vpn_ctx;

    memset(&lsquic_vpn_ctx, 0, sizeof(lsquic_vpn_ctx));
    lsquic_vpn_ctx.prog = &prog;


    TAILQ_INIT(&sports);
    prog_init(&prog, 0, &sports, &client_vpn_stream_if, &lsquic_vpn_ctx);
    prog.prog_api.ea_alpn = "echo";
    prog.lsquic_vpn_ctx = &lsquic_vpn_ctx;

    while (-1 != (opt = getopt(argc, argv, "hc:" )))
    {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            prog_print_common_options(&prog, stdout);
            exit(0);
        case 'c':
            prog_parse_config_file(&prog, optarg);
        }
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
