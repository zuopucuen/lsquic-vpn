#ifndef vpn_H
#define vpn_H 1

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/time.h>

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

typedef struct vpn_tun_addr_s {
    char local_ip[16];
    char remote_ip[16];
    int is_used;
} vpn_tun_addr_t;

typedef struct vpn_s {
    vpn_tun_addr_t *addrs[MAX_TUN_SUM];
    int max_conn;
} vpn_t;

typedef struct vpn_ctx_s {
    const char *  wanted_if_name;
    char *  local_tun_ip;
    char *  remote_tun_ip;
    char          if_name[IFNAMSIZ];
    int           is_server;
    int           tun_fd;
    int           firewall_rules_set;
    int           addr_index;
    char * packet_buf;
    char          buf[BUFF_SIZE];
    ssize_t        buf_off;
    struct event        *tun_read_ev;
    struct event        *tun_write_ev;
    vpn_t         * vpn;
} vpn_ctx_t;

typedef struct lsquic_vpn_ctx_s {
    TAILQ_HEAD(, lsquic_conn_ctx)   conn_ctxs;
    struct lsquic_conn_ctx  *conn_h;
    int n_conn;
    struct sport_head sports;
    struct prog *prog;
    vpn_t *vpn;
} lsquic_vpn_ctx_t;


struct lsquic_conn_ctx {
    TAILQ_ENTRY(lsquic_conn_ctx)    next_connh;
    lsquic_conn_t       *conn;
    lsquic_vpn_ctx_t   *lsquic_vpn_ctx;
    vpn_ctx_t           *vpn_ctx;
};

struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    lsquic_conn_ctx_t   *conn_h;
    lsquic_vpn_ctx_t    *lsquic_vpn_ctx;
    char                 buf[BUFF_SIZE];
    ssize_t              buf_off;
    ssize_t              packet_remaining;
};

int addr_init(vpn_t *vpn, int tun_sum);
int vpn_init(vpn_ctx_t *vpn, int server_flag);
void lsquic_conn_ctx_init(struct lsquic_conn_ctx   *conn_h);
void vpn_tun_write(vpn_ctx_t *vpn_ctx);
void tun_read_handler(int fd, short event, void *ctx);
void tun_write_handler(int fd, short event, void *ctx);
void vpn_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h);
lsquic_stream_ctx_t *vpn_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream);

extern volatile sig_atomic_t exit_signal_received;
extern void vpn_after_new_stream(lsquic_stream_ctx_t * st_h);

#endif