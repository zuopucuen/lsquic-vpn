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

#ifdef __NetBSD__
#define DEFAULT_MTU 1500
#else
#define DEFAULT_MTU 9000
#endif
#define RECONNECT_ATTEMPTS 100
#define TAG_LEN 6
#define MAX_PACKET_LEN 65536
#define TS_TOLERANCE 7200
#define TIMEOUT (60 * 1000)
#define ACCEPT_TIMEOUT (10 * 1000)
#define OUTER_CONGESTION_CONTROL_ALG "bbr"
#define BUFFERBLOAT_CONTROL 1
#define NOTSENT_LOWAT (128 * 1024)
#define BEGIN_SERVER_IP 0xC0A865FE // 192.168.101.254
#define BEGIN_CLIENT_IP 0xC0A86501 // 192.168.101.1

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && !defined(NATIVE_BIG_ENDIAN)
#define NATIVE_BIG_ENDIAN
#endif

#ifdef NATIVE_BIG_ENDIAN
#define endian_swap16(x) __builtin_bswap16(x)
#define endian_swap32(x) __builtin_bswap32(x)
#define endian_swap64(x) __builtin_bswap64(x)
#else
#define endian_swap16(x) (x)
#define endian_swap32(x) (x)
#define endian_swap64(x) (x)
#endif

#define BUFF_SIZE 4096
#define IS_CLIENT 0
#define IS_SERVER 1
#define MAX_TUN_SUM 100

typedef struct vpn_tun_addr_s {
    char local_ip[16];
    char remote_ip[16];
    int is_used;
} vpn_tun_addr_t;

typedef struct vpn_s {
    vpn_tun_addr_t addrs[4];
    int max_conn;
} vpn_t;

typedef struct vpn_ctx_s {
    const char *  wanted_if_name;
    char *  local_tun_ip;
    char *  remote_tun_ip;
    const char *  local_tun_ip6;
    const char *  remote_tun_ip6;
    const char *  server_ip_or_name;
    const char *  server_port;
    const char *  ext_if_name;
    const char *  wanted_ext_gw_ip;
    char          client_ip[NI_MAXHOST];
    char          ext_gw_ip[64];
    char          server_ip[64];
    char          if_name[IFNAMSIZ];
    int           is_server;
    int           tun_fd;
    int           client_fd;
    int           listen_fd;
    int           congestion;
    int           firewall_rules_set;
    int           addr_index;
    vpn_t         * vpn;
} vpn_ctx_t;

int addr_init(vpn_t *vpn, int tun_sum);
int vpn_init(vpn_ctx_t *vpn, int server_flag);
extern volatile sig_atomic_t exit_signal_received;

#endif