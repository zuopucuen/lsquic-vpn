#ifndef os_H
#define os_H 1

#include "vpn.h"
ssize_t safe_read_partial(const int fd, void *const buf_, const size_t max_count);

typedef struct Cmds {
    const char *const *set;
    const char *const *unset;
} Cmds;

Cmds firewall_rules_cmds(int is_server, int set_route);

int firewall_rules(vpn_ctx_t *context, int set, int silent, int set_route);

int shell_cmd(const char *substs[][2], const char *args_str, int silent);

const char *get_default_gw_ip(void);

const char *get_default_ext_if_name(void);

int tun_create(char if_name[IFNAMSIZ], const char *wanted_name);

int tun_set_mtu(const char *if_name, int mtu);

ssize_t tun_read(int fd, void *data, size_t size);

ssize_t tun_write(int fd, const void *data, size_t size);

#endif
