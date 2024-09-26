#include "vpn.h"
#include "os.h"

static void hex_to_ip(u_int32_t hex, char *ip){
    snprintf(ip, 16, "%d.%d.%d.%d",
             (hex >> 24) & 0xFF,
             (hex >> 16) & 0xFF,
             (hex >> 8) & 0xFF,
             hex & 0xFF);
}

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


    tun->firewall_rules_set = -1;

    if (firewall_rules(tun, 1, 0) != 0) {
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
    vpn_ctx->packet_buf = vpn_ctx->buf;
    vpn_ctx->buf_off = 0;
    vpn_ctx->conn_h = conn_h;

    conn_h->vpn_ctx = vpn_ctx;
    conn_h->write_conn_ev_timeout.tv_sec = 0;
    conn_h->write_conn_ev_timeout.tv_usec = STREAM_WRITE_RETRY_TIME;
}

void
vpn_tun_write(vpn_ctx_t *vpn_ctx){
    size_t packet_size, buf_used;

    memcpy(&packet_size, vpn_ctx->packet_buf, VPN_HEAD_SIZE);
    packet_size = ntohs(packet_size);
    while(0 < packet_size  &&  packet_size +  VPN_HEAD_SIZE <= vpn_ctx->buf_off){   
        LSQ_INFO("packet size: %zu, off: %zu", packet_size, vpn_ctx->buf_off);

        if (tun_write(vpn_ctx->tun_fd, vpn_ctx->packet_buf + VPN_HEAD_SIZE, packet_size) != packet_size) {
            LSQ_ERROR("twrite to tun faile");
            goto end;
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

    if(vpn_ctx->buf_off == 0){
        goto complete;
    }

    memmove(vpn_ctx->buf, vpn_ctx->packet_buf, vpn_ctx->buf_off);

complete:
    vpn_ctx->packet_buf = vpn_ctx->buf;
    return;

end:
    event_add(vpn_ctx->tun_write_ev, NULL);
}

void tun_read_handler(int fd, short event, void *ctx){
    lsquic_stream_ctx_t *st_h;
    lsquic_conn_ctx_t *conn_h;
    ssize_t len, llen;
    char *cur_buf;


    st_h = ctx;
    conn_h = st_h->conn_h;
    len = 1;
    cur_buf = st_h->buf;

    while(st_h->buf_off + VPN_HEAD_SIZE + DEFAULT_MTU <= BUFF_SIZE && len > 0){
        LSQ_INFO("tun read free buf: %zu", BUFF_SIZE - st_h->buf_off - VPN_HEAD_SIZE);
        cur_buf = st_h->buf + st_h->buf_off + VPN_HEAD_SIZE;
        len = tun_read(fd, cur_buf, BUFF_SIZE - st_h->buf_off - VPN_HEAD_SIZE);
        if (len < 0) {
            LSQ_INFO("tun_read error: %zd", len);
            break;
        }else if(len > DEFAULT_MTU){
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

void tun_write_handler(int fd, short event, void *ctx){
    vpn_ctx_t *vpn_ctx = ctx;
    vpn_tun_write(ctx);
}

void vpn_stream_write_handler(int fd, short event, void *ctx){
    lsquic_stream_ctx_t *st_h = ctx;
    lsquic_conn_ctx_t *conn_h;

    vpn_on_write(st_h->stream, st_h);
    lsquic_stream_wantread(st_h->stream, 0);
    prog_process_conns(st_h->lsquic_vpn_ctx->prog);
    lsquic_stream_wantread(st_h->stream, 1);
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
    st_h->packet_buf = st_h->buf;
    st_h->packet_remaining = 0;

    conn_h->write_conn_ev = event_new(prog_eb(st_h->lsquic_vpn_ctx->prog),
                  -1, EV_TIMEOUT, vpn_stream_write_handler, st_h);

    lsquic_stream_wantwrite(st_h->stream, 0);
    vpn_after_new_stream(st_h);

    return st_h;
}

void
vpn_on_write (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    size_t len, packets_size, total_writen;
    lsquic_conn_ctx_t *conn_h;
    
    conn_h = st_h->conn_h;
    len = lsquic_stream_write(stream, st_h->packet_buf, st_h->buf_off);
    
    if(len<0) {
        LSQ_ERROR("Error writing to stream: %s\n", strerror(errno));
        exit(1);
    }

    LSQ_INFO("write to stream %llu: %zd bytes, total : %zu bytes", lsquic_stream_id(stream), len, st_h->buf_off);
    lsquic_stream_flush(stream);

    st_h->buf_off -= len;

    if (st_h->buf_off == 0){
        st_h->packet_remaining = 0;
        st_h->retry = STREAM_WRITE_RETRY;
        st_h->packet_buf = st_h->buf;

        lsquic_stream_wantwrite(stream, 0);
    
        goto out;
    }
    
    if (--st_h->retry > 0){
        if(st_h->buf_off > 0 && st_h->conn_h->write_conn_ev){
            event_add(conn_h->write_conn_ev, &conn_h->write_conn_ev_timeout);
        }

        st_h->packet_buf += len;

        return;
    } else {
        packets_size = st_h->packet_remaining;
        total_writen = st_h->packet_buf - st_h->buf + len;

        while(packets_size < total_writen){
            packets_size += ntohs(*(unsigned short *) &st_h->buf[packets_size]) + VPN_HEAD_SIZE;
        }
        
        st_h->buf_off = packets_size - total_writen;
        st_h->packet_remaining = st_h->buf_off;
        memmove(st_h->buf, st_h->packet_buf + len, st_h->buf_off);
        st_h->packet_buf = st_h->buf;

        st_h->retry = STREAM_WRITE_RETRY;
    }

out:
    if (conn_h->vpn_ctx->tun_read_ev){
        event_add(conn_h->vpn_ctx->tun_read_ev, NULL);
    }
}
