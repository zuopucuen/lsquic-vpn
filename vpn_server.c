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

#include "vpn.h"

// 自定义 IP 头部结构体
struct iphdr {
    unsigned char  ihl:4;      // IP header length
    unsigned char  version:4;  // IP version
    unsigned char  tos;         // Type of service
    unsigned short tot_len;     // Total length
    unsigned short id;          // Identification
    unsigned short frag_off;    // Fragment offset
    unsigned char  ttl;         // Time to live
    unsigned char  protocol;    // Protocol
    unsigned short check;       // Checksum
    struct in_addr saddr;       // Source address
    struct in_addr daddr;       // Destination address
};

// 自定义 ICMP 头部结构体
struct icmphdr {
    uint8_t type;               // ICMP message type
    uint8_t code;               // Type sub-code
    uint16_t checksum;          // Checksum
    uint16_t id;                // Identifier
    uint16_t sequence;          // Sequence number
};

// ICMP Echo Request type
#define ICMP_ECHO 8
#define ICMP_ECHO_REPLY 0

uint16_t checksum(void *b, int len) {
    uint16_t *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// 构建 IP 和 ICMP 报文
void build_ip_icmp_packet(const char *src_ip, const char *dest_ip, uint16_t id, uint16_t seq, void *buffer) {
    struct iphdr *ip = (struct iphdr *)buffer;
    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));

    // 填充 IP 头部
    ip->ihl = 5; // IP header length
    ip->version = 4; // IPv4
    ip->tos = 0; // Type of service
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr)); // Total length
    ip->id = htons(id); // Identification
    ip->frag_off = 0; // Fragment offset
    ip->ttl = 64; // Time to live
    ip->protocol = IPPROTO_ICMP; // Protocol
    ip->check = 0; // 校验和，先设为0，后面计算
    ip->saddr.s_addr = inet_addr(src_ip); // Source address
    ip->daddr.s_addr = inet_addr(dest_ip); // Destination address

    // 计算 IP 头的校验和
    ip->check = checksum((void *)ip, sizeof(struct iphdr));

    // 填充 ICMP 头部
    icmp->type = ICMP_ECHO; // ICMP Echo Request
    icmp->code = 0; // Code
    icmp->checksum = 0; // 校验和，先设为0，后面计算
    icmp->id = htons(id); // Identifier
    icmp->sequence = htons(seq); // Sequence number

    // 计算 ICMP 头的校验和
    icmp->checksum = checksum((void *)icmp, sizeof(struct icmphdr));
}

static void vpn_server_ping_client(lsquic_stream_ctx_t *st_h){
    lsquic_conn_ctx_t *conn_h;
    vpn_ctx_t *vpn_ctx;
    tun_t *tun;
    uint16_t id = 1234;
    uint16_t seq = 1;
    char buffer[1500]; // 缓冲区大小，可以根据需要调整
    memset(buffer, 0, sizeof(buffer)); // 清空缓冲区

    conn_h = st_h->conn_h;
    vpn_ctx = conn_h->vpn_ctx;
    tun = vpn_ctx->tun;

    build_ip_icmp_packet(tun->local_tun_ip, tun->remote_tun_ip, id, seq, buffer);
    
}

static lsquic_conn_ctx_t *
vpn_server_on_new_conn (void *stream_if_ctx, lsquic_conn_t *conn)
{
    lsquic_vpn_ctx_t *lsquic_vpn_ctx = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = calloc(1, sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->lsquic_vpn_ctx = lsquic_vpn_ctx;
    lsquic_conn_ctx_init(conn_h);

    TAILQ_INSERT_TAIL(&lsquic_vpn_ctx->conn_ctxs, conn_h, next_connh);
    
    LSQ_NOTICE("New connection!");
    print_conn_info(conn);
    return conn_h;
}


static void
vpn_server_on_conn_closed (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    vpn_ctx_t *vpn_ctx = conn_h->vpn_ctx;

    if (conn_h->lsquic_vpn_ctx->n_conn)
    {
        --conn_h->lsquic_vpn_ctx->n_conn;

        LSQ_NOTICE("Connection closed, remaining: %d", conn_h->lsquic_vpn_ctx->n_conn);
        if (0 == conn_h->lsquic_vpn_ctx->n_conn)
            prog_stop(conn_h->lsquic_vpn_ctx->prog);
    }
    else
        LSQ_NOTICE("Connection closed");
    TAILQ_REMOVE(&conn_h->lsquic_vpn_ctx->conn_ctxs, conn_h, next_connh);

    if(vpn_ctx->tun != NULL)
        vpn_ctx->tun->is_used = 0;

    if (vpn_ctx->tun_read_ev)
    {
        event_del(vpn_ctx->tun_read_ev);
        event_free(vpn_ctx->tun_read_ev);
    }

    if (vpn_ctx->tun_write_ev) {
        event_del(vpn_ctx->tun_write_ev);
        event_free(vpn_ctx->tun_write_ev);
    }

    if (conn_h->write_conn_ev)
    {
        event_del(conn_h->write_conn_ev);
        event_free(conn_h->write_conn_ev);
    }

    lsquic_conn_set_ctx(conn, NULL);
    free(vpn_ctx);
    free(conn_h);
}

void 
vpn_after_new_stream(lsquic_stream_ctx_t * st_h){
    lsquic_stream_wantwrite(st_h->stream, 0);
    lsquic_stream_wantread(st_h->stream, 1);
    return;
}

static struct lsquic_conn_ctx *
find_conn_h (const lsquic_vpn_ctx_t *lsquic_vpn_ctx, lsquic_stream_t *stream)
{
    struct lsquic_conn_ctx *conn_h;
    lsquic_conn_t *conn;

    conn = lsquic_stream_conn(stream);
    TAILQ_FOREACH(conn_h, &lsquic_vpn_ctx->conn_ctxs, next_connh)
        if (conn_h->conn == conn)
            return conn_h;
    return NULL;
}

static void
vpn_server_on_read (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    lsquic_conn_ctx_t *conn_h;
    vpn_ctx_t *vpn_ctx;
    tun_t *tun;
    ssize_t len, buf_used;
    char * cur_buf;
    int fd;

    conn_h = st_h->conn_h;
    vpn_ctx = conn_h->vpn_ctx;
    cur_buf = vpn_ctx->packet_buf + vpn_ctx->buf_off;
    buf_used =  vpn_ctx->packet_buf - vpn_ctx->buf + vpn_ctx->buf_off;

    len = lsquic_stream_read(stream, cur_buf, BUFF_SIZE - buf_used);
    
    if (len <=0 && errno != EWOULDBLOCK)
    {
        LSQ_ERROR("read from stream error");
        goto end;
    }

    LSQ_INFO("read from stream %llu: %zd bytes, bufsize: %zu", lsquic_stream_id(stream), len, BUFF_SIZE - buf_used);
    
    if(vpn_ctx->tun == NULL){
        LSQ_INFO("client for %s", cur_buf);

        tun = st_h->lsquic_vpn_ctx->tun;

        while(tun != NULL){
            if (strcmp(tun->local_tun_ip, cur_buf) == 0 && tun->is_used == 0){
                break;
            }
            tun = tun->next;
        }

        if(tun == NULL) {
            goto end;
        }

        vpn_ctx->tun = tun;
        tun->is_used = 1;

        LSQ_INFO("Initialization of the new link address was successful :local ip: %s, remote_ip: %s",
            tun->local_tun_ip, 
            tun->remote_tun_ip
        );

        vpn_ctx->tun_fd = tun->fd;
        vpn_ctx->tun_read_ev = event_new(prog_eb(st_h->lsquic_vpn_ctx->prog),
                                   vpn_ctx->tun_fd, EV_READ, tun_read_handler, st_h);
        vpn_ctx->tun_write_ev = event_new(prog_eb(st_h->lsquic_vpn_ctx->prog),
                                   vpn_ctx->tun_fd, EV_WRITE, tun_write_handler, vpn_ctx);

        event_add(vpn_ctx->tun_read_ev, NULL);
        lsquic_stream_wantwrite(stream, 0);

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
    conn_h = find_conn_h(st_h->lsquic_vpn_ctx, stream);
    lsquic_conn_close(conn_h->conn);
}

static void
vpn_server_on_stream_close (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    struct lsquic_conn_ctx *conn_h;

    LSQ_NOTICE("%s called", __func__);
    conn_h = find_conn_h(st_h->lsquic_vpn_ctx, stream);
    LSQ_WARN("%s: TODO: free connection handler %p", __func__, conn_h);
    free(st_h);
}

const struct lsquic_stream_if server_vpn_stream_if = {
    .on_new_conn            = vpn_server_on_new_conn,
    .on_conn_closed         = vpn_server_on_conn_closed,
    .on_new_stream          = vpn_on_new_stream,
    .on_read                = vpn_server_on_read,
    .on_write               = vpn_on_write,
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
    lsquic_vpn_ctx_t lsquic_vpn_ctx;

    memset(&lsquic_vpn_ctx, 0, sizeof(lsquic_vpn_ctx));
    lsquic_vpn_ctx.prog = &prog;
    lsquic_vpn_ctx.is_server = 1;
    TAILQ_INIT(&lsquic_vpn_ctx.sports);
    TAILQ_INIT(&lsquic_vpn_ctx.conn_ctxs);

    prog_init(&prog, LSENG_SERVER, &lsquic_vpn_ctx.sports,
                                        &server_vpn_stream_if, &lsquic_vpn_ctx);
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

    add_alpn("echo");
    if (0 != prog_prep(&prog))
    {
        LSQ_ERROR("could not prep");
        exit(EXIT_FAILURE);
    }

    LSQ_DEBUG("entering event loop");

    //daemonize();

    s = prog_run(&prog);
    prog_cleanup(&prog);

    exit(0 == s ? EXIT_SUCCESS : EXIT_FAILURE);
}
