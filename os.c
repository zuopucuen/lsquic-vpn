#include <lsquic.h>
#include <lsquic_logger.h>
#include "os.h"
#include "vpn.h"

ssize_t safe_write(const int fd, const void *const buf_, size_t count, const int timeout)
{
    struct pollfd pfd;
    const char *  buf = (const char *) buf_;
    ssize_t       written;

    while (count > (size_t) 0) {
        while ((written = write(fd, buf, count)) < (ssize_t) 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                pfd.fd     = fd;
                pfd.events = POLLOUT;
                if (poll(&pfd, (nfds_t) 1, timeout) <= 0) {
                    return (ssize_t) -1;
                }
            } else if (errno != EINTR) {
                return (ssize_t) 0;
            } else{
                return -1;
            }
        }
        buf += written;
        count -= written;
    }
    return (ssize_t)(buf - (const char *) buf_);
}

ssize_t safe_read_partial(const int fd, void *const buf_, const size_t max_count)
{
    unsigned char *const buf = (unsigned char *) buf_;
    ssize_t              readnb;

    while ((readnb = read(fd, buf, max_count)) < (ssize_t) 0 && errno == EINTR);
    return readnb;
}

#ifdef __linux__
int tun_create(char if_name[IFNAMSIZ], const char *wanted_name)
{
    struct ifreq ifr;
    int          fd;
    int          err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "tun module not present. See https://sk.tl/2RdReigK\n");
        return -1;
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", wanted_name == NULL ? "" : wanted_name);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "%s", ifr.ifr_name);

    return fd;
}
#elif defined(__APPLE__)
static int tun_create_by_id(char if_name[IFNAMSIZ], unsigned int id)
{
    struct ctl_info     ci;
    struct sockaddr_ctl sc;
    int                 err;
    int                 fd;

    if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1) {
        return -1;
    }
    memset(&ci, 0, sizeof ci);
    snprintf(ci.ctl_name, sizeof ci.ctl_name, "%s", UTUN_CONTROL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &ci)) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    memset(&sc, 0, sizeof sc);
    sc = (struct sockaddr_ctl){
        .sc_id      = ci.ctl_id,
        .sc_len     = sizeof sc,
        .sc_family  = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_unit    = id + 1,
    };
    if (connect(fd, (struct sockaddr *) &sc, sizeof sc) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "utun%u", id);

    return fd;
}

int tun_create(char if_name[IFNAMSIZ], const char *wanted_name)
{
    unsigned int id;
    int          fd;

    if (wanted_name == NULL || *wanted_name == 0) {
        for (id = 0; id < 32; id++) {
            if ((fd = tun_create_by_id(if_name, id)) != -1) {
                return fd;
            }
        }
        return -1;
    }
    if (sscanf(wanted_name, "utun%u", &id) != 1) {
        errno = EINVAL;
        return -1;
    }
    return tun_create_by_id(if_name, id);
}
#endif

int tun_set_mtu(const char *if_name, int mtu)
{
    struct ifreq ifr;
    int          fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return -1;
    }
    ifr.ifr_mtu = mtu;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", if_name);
    if (ioctl(fd, SIOCSIFMTU, &ifr) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

#if defined(__linux__)
ssize_t tun_read(int fd, void *data, size_t size)
{
    return safe_read_partial(fd, data, size);
}

ssize_t tun_write(int fd, const void *data, size_t size)
{
    return safe_write(fd, data, size, TIMEOUT);
}
#else
ssize_t tun_read(int fd, void *data, size_t size)
{
    ssize_t  ret;
    uint32_t family;

    struct iovec iov[2] = {
        {
            .iov_base = &family,
            .iov_len  = sizeof family,
        },
        {
            .iov_base = data,
            .iov_len  = size,
        },
    };

    ret = readv(fd, iov, 2);
    if (ret <= (ssize_t) 0) {
        return -1;
    }
    if (ret <= (ssize_t) sizeof family) {
        return 0;
    }
    return ret - sizeof family;
}

ssize_t tun_write(int fd, const void *data, size_t size)
{
    uint32_t family;
    ssize_t  ret;

    if (size < 20) {
        return 0;
    }

    family = htonl(AF_INET);

    struct iovec iov[2] = {
        {
            .iov_base = &family,
            .iov_len  = sizeof family,
        },
        {
            .iov_base = (void *) data,
            .iov_len  = size,
        },
    };
    ret = writev(fd, iov, 2);
    if (ret <= (ssize_t) 0) {
        return ret;
    }
    if (ret <= (ssize_t) sizeof family) {
        return 0;
    }
    return ret - sizeof family;
}
#endif

static char *read_from_shell_command(char *result, size_t sizeof_result, const char *command)
{
    FILE *fp;
    char *pnt;

    if ((fp = popen(command, "r")) == NULL) {
        return NULL;
    }
    if (fgets(result, (int) sizeof_result, fp) == NULL) {
        pclose(fp);
        fprintf(stderr, "Command [%s] failed]\n", command);
        return NULL;
    }
    if ((pnt = strrchr(result, '\n')) != NULL) {
        *pnt = 0;
    }
    (void) pclose(fp);

    return *result == 0 ? NULL : result;
}

const char *get_default_gw_ip(void)
{
    static char gw[64];
#if defined(__APPLE__)
    return read_from_shell_command(
        gw, sizeof gw, "route -n get default 2>/dev/null|awk '/gateway:/{print $2;exit}'");
#elif defined(__linux__)
    return read_from_shell_command(gw, sizeof gw,
                                   "ip route show default 2>/dev/null|awk '/default/{print $3}'");
#else
    return NULL;
#endif
}

const char *get_default_ext_if_name(void)
{
    static char if_name[64];
#if defined(__APPLE__)
    return read_from_shell_command(if_name, sizeof if_name,
                                   "route -n get default 2>/dev/null|awk "
                                   "'/interface:/{print $2;exit}'");
#elif defined(__linux__)
    return read_from_shell_command(if_name, sizeof if_name,
                                   "ip route show default 2>/dev/null|awk '/default/{print $5}'");
#else
    return NULL;
#endif
}

int shell_cmd(const char *substs[][2], const char *args_str, int silent)
{
    char * args[64];
    char   cmdbuf[4096];
    pid_t  child;
    size_t args_i = 0, cmdbuf_i = 0, args_str_i, i;
    int    c, exit_status, is_space = 1;

    errno = ENOSPC;
    for (args_str_i = 0; (c = args_str[args_str_i]) != 0; args_str_i++) {
        if (isspace((unsigned char) c)) {
            if (!is_space) {
                if (cmdbuf_i >= sizeof cmdbuf) {
                    return -1;
                }
                cmdbuf[cmdbuf_i++] = 0;
            }
            is_space = 1;
            continue;
        }
        if (is_space) {
            if (args_i >= sizeof args / sizeof args[0]) {
                return -1;
            }
            args[args_i++] = &cmdbuf[cmdbuf_i];
        }
        is_space = 0;
        for (i = 0; substs[i][0] != NULL; i++) {
            size_t pat_len = strlen(substs[i][0]), sub_len;
            if (!strncmp(substs[i][0], &args_str[args_str_i], pat_len)) {
                sub_len = strlen(substs[i][1]);
                if (sizeof cmdbuf - cmdbuf_i <= sub_len) {
                    return -1;
                }
                memcpy(&cmdbuf[cmdbuf_i], substs[i][1], sub_len);
                args_str_i += pat_len - 1;
                cmdbuf_i += sub_len;
                break;
            }
        }
        if (substs[i][0] == NULL) {
            if (cmdbuf_i >= sizeof cmdbuf) {
                return -1;
            }
            cmdbuf[cmdbuf_i++] = c;
        }
    }
    if (!is_space) {
        if (cmdbuf_i >= sizeof cmdbuf) {
            return -1;
        }
        cmdbuf[cmdbuf_i++] = 0;
    }
    if (args_i >= sizeof args / sizeof args[0] || args_i == 0) {
        return -1;
    }
    args[args_i] = NULL;
    if ((child = fork()) == (pid_t) -1) {
        return -1;
    } else if (child == (pid_t) 0) {
        if (silent) {
            dup2(dup2(open("/dev/null", O_WRONLY), 2), 1);
        }
        execvp(args[0], args);
        _exit(1);
    } else if (waitpid(child, &exit_status, 0) == (pid_t) -1 || !WIFEXITED(exit_status)) {
        return -1;
    }
    return 0;
}

Cmds firewall_rules_cmds(int is_server)
{
    if (is_server) {
#ifdef __linux__
        static const char
            *set_cmds[] =
                { "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
                  "ip link set dev $IF_NAME up",
                  NULL },
            *unset_cmds[] = {
                NULL
            };
#elif defined(__APPLE__)
        static const char *set_cmds[] = { 
            "ifconfig $IF_NAME $LOCAL_TUN_IP $REMOTE_TUN_IP up", NULL },
                          *unset_cmds[] = { NULL, NULL };
#endif
        return (Cmds){ set_cmds, unset_cmds };
    } else {
#if defined(__APPLE__) 
        static const char *set_cmds[] =
            { "ifconfig $IF_NAME $LOCAL_TUN_IP $REMOTE_TUN_IP up", NULL },
                          *unset_cmds[] = { NULL,};
#elif defined(__linux__)
        static const char
            *set_cmds[] =
                { "ip link set dev $IF_NAME up",
                  "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
                  NULL },
            *unset_cmds[] = { NULL };
#else
        static const char *const *set_cmds = NULL, *const *unset_cmds = NULL;
#endif
        return (Cmds){ set_cmds, unset_cmds };
    }
}

int firewall_rules(vpn_ctx_t *vpn, int set, int silent)
{
    const char *       substs[][2] = { { "$LOCAL_TUN_IP", vpn->local_tun_ip },
                                { "$REMOTE_TUN_IP", vpn->remote_tun_ip },
                                { "$IF_NAME", vpn->if_name },
                                { NULL, NULL } };
    const char *const *cmds;
    size_t             i;

    if (vpn->firewall_rules_set == set) {
        return 0;
    }
    if ((cmds = (set ? firewall_rules_cmds(vpn->is_server).set
                     : firewall_rules_cmds(vpn->is_server).unset)) == NULL) {
        LSQ_ERROR("Routing commands for that operating system have not been "
                "added yet.\n");
        return 0;
    }
    for (i = 0; cmds[i] != NULL; i++) {
        if (shell_cmd(substs, cmds[i], silent) != 0) {
            LSQ_ERROR("Unable to run [%s]: [%s]\n", cmds[i], strerror(errno));
            return -1;
        }
    }
    vpn->firewall_rules_set = set;
    return 0;
}