#ifndef vpn_H
#define vpn_H 1

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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

#define VERSION_STRING "0.1.4"
#define DEFAULT_MTU 1500
#define TIMEOUT (60 * 1000)
#define BUFF_SIZE 8092
#define IS_CLIENT 0
#define IS_SERVER 1
#define MAX_TUN_SUM 10
#define BEGIN_DEFAULT_IP 0xC0A8FF01 // 192.168.255.1
#define VPN_HEAD_SIZE 4

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
    size_t        buf_off;
    vpn_t         * vpn;
} vpn_ctx_t;

int addr_init(vpn_t *vpn, int tun_sum);
int vpn_init(vpn_ctx_t *vpn, int server_flag);
extern volatile sig_atomic_t exit_signal_received;

#endif