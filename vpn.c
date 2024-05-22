#include "vpn.h"
#include "os.h"

static void hex_to_ip(u_int32_t hex, char *ip){
    snprintf(ip, 16, "%d.%d.%d.%d",
             (hex >> 24) & 0xFF,
             (hex >> 16) & 0xFF,
             (hex >> 8) & 0xFF,
             hex & 0xFF);
}

int vpn_init(vpn_ctx_t *vpn, int server_flag) {
    vpn->is_server = server_flag;

    vpn->tun_fd = tun_create(vpn->if_name, vpn->wanted_if_name);
    
    if (vpn->tun_fd == -1) {
        LSQ_ERROR("tun device creation");
        return -1;
    }

    LSQ_INFO("tun:%s, local_ip:%s, remote_ip:%s", 
        vpn->if_name,
        vpn->local_tun_ip, 
        vpn->remote_tun_ip);

    if (tun_set_mtu(vpn->if_name, DEFAULT_MTU) != 0) {
        LSQ_ERROR("cannot set mtu: %d", DEFAULT_MTU);
    }

    vpn->firewall_rules_set = -1;

    if (firewall_rules(vpn, 1, 0) != 0) {
        LSQ_ERROR("set Firewall rules faile");
        return -1;
    }

    return 1;
}

void lsquic_conn_ctx_init(struct lsquic_conn_ctx  *conn_h){
    vpn_ctx_t *vpn_ctx;
    lsquic_vpn_ctx_t *lsquic_vpn_ctx;
   
    vpn_ctx = malloc(sizeof(*vpn_ctx));
    memset(vpn_ctx, 0, sizeof(*vpn_ctx));
    lsquic_vpn_ctx = conn_h->lsquic_vpn_ctx;

    vpn_ctx->tun_fd = -1;
    vpn_ctx->addr_index = -1;
    vpn_ctx->vpn = lsquic_vpn_ctx->vpn;
    vpn_ctx->packet_buf = vpn_ctx->buf;
    vpn_ctx->buf_off = 0;

    conn_h->vpn_ctx = vpn_ctx;
}

int addr_init(vpn_t *vpn, int tun_sum) {
    int i;
    u_int32_t local_ip, remote_ip;

    local_ip = BEGIN_DEFAULT_IP;
    remote_ip = local_ip + 1;

    tun_sum = tun_sum > MAX_TUN_SUM ? MAX_TUN_SUM : tun_sum;

    for(i=0;i<tun_sum;i++){
        vpn->addrs[i] = malloc(sizeof(vpn_tun_addr_t));
        memset(vpn->addrs[i], 0, sizeof(vpn_tun_addr_t));
        hex_to_ip(local_ip, vpn->addrs[i]->local_ip);
        hex_to_ip(remote_ip, vpn->addrs[i]->remote_ip);
        vpn->addrs[i]->is_used = 0;
        LSQ_INFO("local %s, remote %s", vpn->addrs[i]->local_ip, vpn->addrs[i]->remote_ip);

        local_ip = local_ip + 10;
        remote_ip = remote_ip + 10;

    }
    vpn->max_conn = tun_sum;

    return 1;
}

void
vpn_tun_write(vpn_ctx_t *vpn_ctx){
    size_t packet_size, buf_used;

    memcpy(&packet_size, vpn_ctx->packet_buf, VPN_HEAD_SIZE);
    packet_size = ntohs(packet_size);
    while(0 < packet_size  &&  packet_size <= (vpn_ctx->buf_off - VPN_HEAD_SIZE)){   
        LSQ_INFO("packet size: %zu, off: %zu", packet_size, vpn_ctx->buf_off);

        if (tun_write(vpn_ctx->tun_fd, vpn_ctx->packet_buf + VPN_HEAD_SIZE, packet_size) != packet_size) {
            LSQ_ERROR("twrite to tun faile");
            break;
        }else{
            LSQ_INFO("write to tun  %zu bytes",  packet_size);
        }

        vpn_ctx->buf_off = vpn_ctx->buf_off - packet_size - VPN_HEAD_SIZE;
        vpn_ctx->packet_buf = vpn_ctx->packet_buf + packet_size + VPN_HEAD_SIZE;
        if(vpn_ctx->buf_off  > VPN_HEAD_SIZE) {
            memcpy(&packet_size, vpn_ctx->packet_buf, VPN_HEAD_SIZE);
            packet_size = ntohs(packet_size);
        }else{
            break;
        }

        LSQ_INFO("last packet size: %zu, buf_off: %zu", packet_size, vpn_ctx->buf_off);
    }

    memmove(vpn_ctx->buf, vpn_ctx->packet_buf, vpn_ctx->buf_off);
    vpn_ctx->packet_buf = vpn_ctx->buf;
}

size_t vpn_tun_read(int fd, char *buf, size_t buf_off){
    size_t              len, llen;
    char *cur_buf;

    LSQ_INFO("tun read free buf: %zu", BUFF_SIZE - buf_off - VPN_HEAD_SIZE);
    cur_buf = buf + buf_off + VPN_HEAD_SIZE;
    len = tun_read(fd, cur_buf, BUFF_SIZE - buf_off - VPN_HEAD_SIZE);
    if (len < 0) {
        LSQ_WARN("tun_read error: %zu", len);
        return 0;
    }else if(len > DEFAULT_MTU){
        LSQ_WARN("The data read(%zu) is greater than mtu(%d)", len, DEFAULT_MTU);
        exit(1);
        return 0;
    }
    
    cur_buf -= VPN_HEAD_SIZE;
    llen = htons(len);
    memcpy(cur_buf, &llen, VPN_HEAD_SIZE);
    buf_off = buf_off + len + VPN_HEAD_SIZE;
    LSQ_INFO("read from tun: %zu bytes", len);

    return buf_off;
}

void tun_read_handler(int fd, short event, void *ctx){
    size_t len;
    lsquic_stream_ctx_t *st_h = ctx;
    lsquic_conn_ctx_t *conn_h = st_h->conn_h;

    LSQ_INFO("buf off before read tun: %zu bytes", st_h->buf_off);
    len = vpn_tun_read(fd, st_h->buf, st_h->buf_off);

    if(len > 0){
        st_h->buf_off = len;
    }

    lsquic_stream_wantwrite(st_h->stream, 1);
    lsquic_engine_process_conns(st_h->lsquic_vpn_ctx->prog->prog_engine);

    //event_add(conn_h->read_tun_ev, NULL);
}

lsquic_stream_ctx_t *
vpn_on_new_stream (void *stream_if_ctx, lsquic_stream_t *stream)
{
    lsquic_vpn_ctx_t *lsquic_vpn_ctx;
    lsquic_stream_ctx_t *st_h;
    lsquic_conn_t *conn;
    lsquic_conn_ctx_t *conn_h;
    struct service_port *sport;

    lsquic_vpn_ctx = stream_if_ctx;
    st_h = malloc(sizeof(*st_h));
    conn= lsquic_stream_conn(stream);
    conn_h = lsquic_conn_get_ctx(conn);

    memset(st_h, 0, sizeof(*st_h));;

    st_h->stream = stream;
    st_h->conn_h = conn_h;
    st_h->lsquic_vpn_ctx = lsquic_vpn_ctx;
    st_h->buf_off = 0;

    sport = TAILQ_FIRST(st_h->lsquic_vpn_ctx->prog->prog_sports);
    conn_h->write_conn_ev = event_new(prog_eb(st_h->lsquic_vpn_ctx->prog),
                        sport->fd, EV_WRITE, vpn_stream_handler, st_h);

    vpn_after_new_stream(st_h);

    return st_h;
}

void vpn_stream_handler(int fd, short event, void *ctx){
    lsquic_stream_ctx_t *st_h = ctx;
    lsquic_engine_process_conns(st_h->lsquic_vpn_ctx->prog->prog_engine);
}

void
vpn_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    size_t len;
    size_t total_written = 0;
    while (total_written < st_h->buf_off) {
        len = lsquic_stream_write(stream, st_h->buf + total_written , st_h->buf_off - total_written);

        if(len == 0){
            break;
        } else if(len<0) {
            int err = errno;
            if (err == EWOULDBLOCK || err == EAGAIN) {
                LSQ_WARN("Stream not ready for writing, try again later\n");
                break;
            }

            LSQ_ERROR("Error writing to stream: %s\n", strerror(err));
            lsquic_conn_close(lsquic_stream_conn(stream));
            return;
        } 
        
        LSQ_INFO("write to client %llu: %zd bytes, total : %zu bytes", lsquic_stream_id(stream), len, st_h->buf_off - total_written);
        total_written += len;
    }

    st_h->buf_off -= total_written;
    if(st_h->buf_off > 0){
        memmove(st_h->buf, st_h->buf + total_written, st_h->buf_off);
        event_add(st_h->conn_h->write_conn_ev, NULL);
    } else {
        lsquic_stream_flush(stream);
        lsquic_stream_wantwrite(stream, 0);
        lsquic_stream_wantread(stream, 1);

        if(st_h->conn_h->read_tun_ev)
            event_add(st_h->conn_h->read_tun_ev, NULL);
    }
}