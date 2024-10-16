#ifndef vpn_H
#define vpn_H 1

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if_tun.h>
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

#include <event2/event.h>

#include <lsquic.h>
#include <lsquic_hash.h>
#include <lsquic_logger.h>

#include "common.h"
#include "cert.h"
#include "prog.h"

#define DEFAULT_MTU 1500
#define BUFF_SIZE 4096
#define IS_CLIENT 0
#define IS_SERVER 1
#define MAX_TUN_SUM 10
#define BEGIN_DEFAULT_IP 0xC0A8FF01 // 192.168.255.1
#define VPN_HEAD_SIZE 2
#define STREAM_WRITE_RETRY 3
#define STREAM_WRITE_RETRY_TIME 1000 // ms

// ICMP Echo Request type
#define ICMP_ECHO 8
#define ICMP_ECHO_REPLY 0

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

typedef struct vpn_ping_s {
    char ping_packet[64];
    ssize_t ping_packet_len;
} vpn_ping_t;

typedef struct tun_s {
    char *local_tun_ip;
    char *remote_tun_ip;
    char *server_ip;
    const char *ext_gw_ip;
    int fd;
    char if_name[IFNAMSIZ];
    int route_set;
    int is_server;
    int change_default_gw;
    int is_used;
    vpn_ping_t vpn_ping;
    void *next;
} tun_t;

typedef struct vpn_ctx_s {
    int is_server;
    int tun_fd;
    tun_t *tun;
    char *packet_buf;
    char buf[BUFF_SIZE];
    ssize_t buf_off;
    struct event *tun_read_ev;
    struct event *tun_write_ev;
    struct event *ping_ev;
    lsquic_conn_ctx_t *conn_h;
} vpn_ctx_t;

typedef struct lsquic_vpn_ctx_s {
    TAILQ_HEAD(, lsquic_conn_ctx) conn_ctxs;
    struct lsquic_conn_ctx *conn_h;
    int n_conn;
    struct sport_head sports;
    struct prog *prog;
    tun_t *tun;
    int change_default_gw;
    int is_server;
} lsquic_vpn_ctx_t;

typedef struct lsquic_conn_ctx {
    TAILQ_ENTRY(lsquic_conn_ctx) next_connh;
    lsquic_conn_t *conn;
    lsquic_vpn_ctx_t *lsquic_vpn_ctx;
    vpn_ctx_t *vpn_ctx;
    struct event *write_conn_ev;
    struct timeval write_conn_ev_timeout;
} lsquic_conn_ctx_t;

typedef struct lsquic_stream_ctx {
    lsquic_stream_t *stream;
    lsquic_conn_ctx_t *conn_h;
    lsquic_vpn_ctx_t *lsquic_vpn_ctx;
    char buf[BUFF_SIZE];
    ssize_t buf_off;
    char *packet_buf;
    ssize_t packet_remaining;
    int retry;
} lsquic_stream_ctx_t;

void build_ip_icmp_packet(const char *src_ip, const char *dest_ip, uint16_t id, uint16_t seq, void *buffer);
const char *get_default_gw_ip(void);
const char *get_default_ext_if_name(void);
int tun_route_set(tun_t *tun, int set);
int tun_init(tun_t *tun);
void lsquic_conn_ctx_init(struct lsquic_conn_ctx *conn_h);
void vpn_tun_write(vpn_ctx_t *vpn_ctx);
void tun_read_handler(int fd, short event, void *ctx);
void tun_write_handler(int fd, short event, void *ctx);
void vpn_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h);
lsquic_stream_ctx_t *vpn_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream);
void vpn_stream_write_handler(int fd, short event, void *ctx);

extern volatile sig_atomic_t exit_signal_received;
extern void vpn_after_new_stream(lsquic_stream_ctx_t *st_h);
#endif // vpn_H