#include "vpn.h"
#include "cmd.h"

const char *get_default_gw_ip(void)
{
    static char default_gw_ip[32];
#if defined(__APPLE__)
    char *cmd = "route -n get default 2>/dev/null|awk '/gateway:/{print $2;exit}'";
#else
    char *cmd = "ip route show default 2>/dev/null|awk '/default/{print $3;exit}'";
#endif

    if (execute_command(cmd, default_gw_ip, sizeof(default_gw_ip)) == 0) {
        return default_gw_ip;
    }

    return NULL;
}

const char *get_default_ext_if_name(void)
{
    static char if_name[64];
#if defined(__APPLE__)
    char *cmd = "route -n get default 2>/dev/null|awk '/interface:/{print $2;exit}'";
#else
    char *cmd = "ip route show default 2>/dev/null|awk '/default/{print $5}'";
#endif

    if (execute_command(cmd, if_name, sizeof(if_name)) == 0) {
        return if_name;
    }

    return NULL;
}

int tun_route_set(tun_t *tun, int set)
{
    int i;
    command_array_t cmd_array;

    if (tun->route_set == set) {
        return 0;
    }

    init_command_array(&cmd_array, 10);

    if (set) {
        if (tun->is_server) {
#if defined(__APPLE__)
            add_command_to_array(&cmd_array, "ifconfig %s %s %s up", tun->if_name, tun->local_tun_ip, tun->remote_tun_ip);
#else
            add_command_to_array(&cmd_array, "ip link set dev %s up", tun->if_name);
            add_command_to_array(&cmd_array, "ip addr add %s peer %s dev %s", tun->local_tun_ip, tun->remote_tun_ip, tun->if_name);    
#endif
        } else {
#if defined(__APPLE__)
            add_command_to_array(&cmd_array, "ifconfig %s %s %s up", tun->if_name, tun->local_tun_ip, tun->remote_tun_ip);
#else
            add_command_to_array(&cmd_array, "ip link set dev %s up", tun->if_name);
            add_command_to_array(&cmd_array, "ip addr add %s peer %s dev %s", tun->local_tun_ip, tun->remote_tun_ip, tun->if_name);    
#endif
            if (tun->change_default_gw){
#if defined(__APPLE__)
                add_command_to_array(&cmd_array,"route add %s %s", tun->server_ip, tun->ext_gw_ip);
                add_command_to_array(&cmd_array, "route change default %s", tun->remote_tun_ip);
#else
                add_command_to_array(&cmd_array, "route add -host %s gw %s", tun->server_ip, tun->ext_gw_ip);
                add_command_to_array(&cmd_array, "route add default gw %s metric 0", tun->remote_tun_ip);
#endif
            }
        }
    } else if (!tun->is_server && tun->change_default_gw) {
#if defined(__APPLE__)
        add_command_to_array(&cmd_array, "route delete %s", tun->server_ip);
        add_command_to_array(&cmd_array, "route change default  %s", tun->ext_gw_ip);
#else
        add_command_to_array(&cmd_array, "route delete -host %s", tun->server_ip);
        add_command_to_array(&cmd_array, "route delete default gw %s", tun->remote_tun_ip);
#endif
    }

    execute_commands_in_order(&cmd_array);
    free_command_array(&cmd_array);

    tun->route_set = set;

    return 0;
}

ssize_t safe_read_partial(const int fd, void *const buf_, const size_t max_count)
{
    unsigned char *const buf = (unsigned char *) buf_;
    ssize_t              readnb;

    while ((readnb = read(fd, buf, max_count)) < (ssize_t) 0 && errno == EINTR);
    return readnb;
}

#ifdef __linux__
int tun_create(char if_name[IFNAMSIZ])
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
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", "");
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        close(fd);
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL)");
        close(fd);
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

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        close(fd);
        return -1;
    }
    
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL)");
        close(fd);
        return -1;
    }

    snprintf(if_name, IFNAMSIZ, "utun%u", id);

    return fd;
}

int tun_create(char if_name[IFNAMSIZ])
{
    unsigned int id;
    int          fd;


    for (id = 0; id < 32; id++) {
        if ((fd = tun_create_by_id(if_name, id)) != -1) {
            return fd;
        }
    }
    return -1;
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
ssize_t tun_read(int fd, void *buf, size_t size)
{
    ssize_t len;

    while ((len = read(fd, buf, size)) < (ssize_t) 0 && errno == EINTR);
    return len;
}

ssize_t tun_write(int fd, const void *buf, size_t size)
{
    ssize_t len;
    
    while ((len = write(fd, buf, size)) < (ssize_t) 0 && errno == EINTR);
    return len;
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

int tun_init(tun_t *tun) {
    tun->fd = tun_create(tun->if_name);
    
    if (tun->fd == -1) {
        LSQ_ERROR("tun device creation");
        return -1;
    }

    LSQ_INFO("tun:%s, local_ip:%s, remote_ip:%s", 
             tun->if_name,
             tun->local_tun_ip, 
             tun->remote_tun_ip);

    if (tun_set_mtu(tun->if_name, DEFAULT_MTU) != 0) {
        LSQ_ERROR("cannot set mtu: %d", DEFAULT_MTU);
    }

    tun->route_set = -1;

    if (tun_route_set(tun, 1) != 0) {
        LSQ_ERROR("set Firewall rules failed");
        return -1;
    }

    return 1;
}

void lsquic_conn_ctx_init(struct lsquic_conn_ctx *conn_h) {
    vpn_ctx_t *vpn_ctx;
    lsquic_vpn_ctx_t *lsquic_vpn_ctx;
   
    vpn_ctx = malloc(sizeof(*vpn_ctx));
    memset(vpn_ctx, 0, sizeof(*vpn_ctx));
    lsquic_vpn_ctx = conn_h->lsquic_vpn_ctx;

    vpn_ctx->tun_fd = -1;
    vpn_ctx->packet_buf = vpn_ctx->buf;
    vpn_ctx->buf_off = 0;
    vpn_ctx->conn_h = conn_h;

    conn_h->vpn_ctx = vpn_ctx;
    conn_h->write_conn_ev_timeout.tv_sec = 0;
    conn_h->write_conn_ev_timeout.tv_usec = STREAM_WRITE_RETRY_TIME;
}

void vpn_tun_write(vpn_ctx_t *vpn_ctx) {
    size_t packet_size, buf_used;

    memcpy(&packet_size, vpn_ctx->packet_buf, VPN_HEAD_SIZE);
    packet_size = ntohs(packet_size);
    while (0 < packet_size && packet_size + VPN_HEAD_SIZE <= vpn_ctx->buf_off) {   
        LSQ_INFO("packet size: %zu, off: %zu", packet_size, vpn_ctx->buf_off);

        if (tun_write(vpn_ctx->tun_fd, vpn_ctx->packet_buf + VPN_HEAD_SIZE, packet_size) != packet_size) {
            LSQ_ERROR("write to tun failed");
            goto end;
        } else {
            LSQ_INFO("write to tun %zu bytes", packet_size);
        }

        vpn_ctx->buf_off = vpn_ctx->buf_off - packet_size - VPN_HEAD_SIZE;
        vpn_ctx->packet_buf = vpn_ctx->packet_buf + packet_size + VPN_HEAD_SIZE;
        if (vpn_ctx->buf_off > VPN_HEAD_SIZE) {
            memcpy(&packet_size, vpn_ctx->packet_buf, VPN_HEAD_SIZE);
            packet_size = ntohs(packet_size);
        } else {
            break;
        }

        LSQ_INFO("last packet size: %zu, buf_off: %zu", packet_size, vpn_ctx->buf_off);
    }

    if (vpn_ctx->buf_off == 0) {
        goto complete;
    }

    memmove(vpn_ctx->buf, vpn_ctx->packet_buf, vpn_ctx->buf_off);

complete:
    vpn_ctx->packet_buf = vpn_ctx->buf;
    return;

end:
    event_add(vpn_ctx->tun_write_ev, NULL);
}

void tun_read_handler(int fd, short event, void *ctx) {
    lsquic_stream_ctx_t *st_h;
    lsquic_conn_ctx_t *conn_h;
    ssize_t len, llen;
    char *cur_buf;


    st_h = ctx;
    conn_h = st_h->conn_h;
    len = 1;
    cur_buf = st_h->buf;

    while (st_h->buf_off + VPN_HEAD_SIZE + DEFAULT_MTU <= BUFF_SIZE && len > 0) {
        LSQ_INFO("tun read free buf: %zu", BUFF_SIZE - st_h->buf_off - VPN_HEAD_SIZE);
        cur_buf = st_h->buf + st_h->buf_off + VPN_HEAD_SIZE;
        len = tun_read(fd, cur_buf, BUFF_SIZE - st_h->buf_off - VPN_HEAD_SIZE);
        if (len < 0) {
            LSQ_INFO("tun_read error: %zd", len);
            break;
        } else if (len > DEFAULT_MTU) {
            LSQ_WARN("The data read(%zd) is greater than mtu(%d)", len, DEFAULT_MTU);
            continue;
        }
    
        cur_buf -= VPN_HEAD_SIZE;
        llen = htons(len);
        memcpy(cur_buf, &llen, VPN_HEAD_SIZE);
        st_h->buf_off = st_h->buf_off + len + VPN_HEAD_SIZE;
        LSQ_INFO("read from tun: %zu bytes", len);
    }

    vpn_stream_write_handler(-1, -1, st_h);    
}

void tun_write_handler(int fd, short event, void *ctx) {
    vpn_ctx_t *vpn_ctx = ctx;
    vpn_tun_write(ctx);
}

void vpn_stream_write_handler(int fd, short event, void *ctx) {
    lsquic_stream_ctx_t *st_h = ctx;
    lsquic_conn_ctx_t *conn_h;

    vpn_on_write(st_h->stream, st_h);
    lsquic_stream_wantread(st_h->stream, 0);
    prog_process_conns(st_h->lsquic_vpn_ctx->prog);
    lsquic_stream_wantread(st_h->stream, 1);
}

lsquic_stream_ctx_t *vpn_on_new_stream(void *stream_if_ctx, lsquic_stream_t *stream) {
    lsquic_vpn_ctx_t *lsquic_vpn_ctx;
    lsquic_stream_ctx_t *st_h;
    lsquic_conn_t *conn;
    lsquic_conn_ctx_t *conn_h;
    struct service_port *sport;

    lsquic_vpn_ctx = stream_if_ctx;
    st_h = malloc(sizeof(*st_h));
    conn = lsquic_stream_conn(stream);
    conn_h = lsquic_conn_get_ctx(conn);

    memset(st_h, 0, sizeof(*st_h));

    st_h->stream = stream;
    st_h->conn_h = conn_h;
    st_h->lsquic_vpn_ctx = lsquic_vpn_ctx;
    st_h->buf_off = 0;
    st_h->packet_buf = st_h->buf;
    st_h->packet_remaining = 0;

    conn_h->write_conn_ev = event_new(prog_eb(st_h->lsquic_vpn_ctx->prog),
                                      -1, EV_TIMEOUT, vpn_stream_write_handler, st_h);

    lsquic_stream_wantwrite(st_h->stream, 0);
    vpn_after_new_stream(st_h);

    return st_h;
}

void vpn_on_write(lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h) {
    size_t len, packets_size, total_written;
    lsquic_conn_ctx_t *conn_h;
    
    conn_h = st_h->conn_h;
    len = lsquic_stream_write(stream, st_h->packet_buf, st_h->buf_off);
    
    if (len < 0) {
        LSQ_ERROR("Error writing to stream: %s\n", strerror(errno));
        exit(1);
    }

    LSQ_INFO("write to stream %llu: %zd bytes, total : %zu bytes", lsquic_stream_id(stream), len, st_h->buf_off);
    lsquic_stream_flush(stream);

    st_h->buf_off -= len;

    if (st_h->buf_off == 0) {
        st_h->packet_remaining = 0;
        st_h->retry = STREAM_WRITE_RETRY;
        st_h->packet_buf = st_h->buf;

        lsquic_stream_wantwrite(stream, 0);
    
        goto out;
    }
    
    if (--st_h->retry > 0) {
        if (st_h->buf_off > 0 && st_h->conn_h->write_conn_ev) {
            event_add(conn_h->write_conn_ev, &conn_h->write_conn_ev_timeout);
        }

        st_h->packet_buf += len;

        return;
    } else {
        packets_size = st_h->packet_remaining;
        total_written = st_h->packet_buf - st_h->buf + len;

        while (packets_size < total_written) {
            packets_size += ntohs(*(unsigned short *) &st_h->buf[packets_size]) + VPN_HEAD_SIZE;
        }
        
        st_h->buf_off = packets_size - total_written;
        st_h->packet_remaining = st_h->buf_off;
        memmove(st_h->buf, st_h->packet_buf + len, st_h->buf_off);
        st_h->packet_buf = st_h->buf;

        st_h->retry = STREAM_WRITE_RETRY;
    }

out:
    if (conn_h->vpn_ctx->tun_read_ev) {
        event_add(conn_h->vpn_ctx->tun_read_ev, NULL);
    }
}