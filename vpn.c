#include <lsquic.h>
#include <lsquic_logger.h>
#include "os.h"
#include "vpn.h"

static void hex_to_ip(u_int32_t hex, char *ip){
    snprintf(ip, 16, "%d.%d.%d.%d",
             (hex >> 24) & 0xFF,
             (hex >> 16) & 0xFF,
             (hex >> 8) & 0xFF,
             hex & 0xFF);
}

int vpn_init(vpn_ctx_t *vpn, int server_flag) {
    memset(vpn, 0, sizeof(*vpn));
    vpn->is_server = server_flag;
    vpn->server_ip_or_name  = "auto";
    vpn->server_port    = "auto";
    vpn->wanted_if_name = "";
    vpn->wanted_ext_gw_ip = "auto";

    if ((vpn->ext_if_name = get_default_ext_if_name()) == NULL && vpn->is_server) {
        LSQ_ERROR("Unable to automatically determine the external interface\n");
        return -1;
    }
    vpn->tun_fd = tun_create(vpn->if_name, vpn->wanted_if_name);
    
    if (vpn->tun_fd == -1) {
        LSQ_ERROR("tun device creation");
        return -1;
    }

    printf("Interface: [%s]\n", vpn->if_name);
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

int addr_init(vpn_t *vpn, int tun_sum) {
    int i;
    u_int32_t local_ip, remote_ip;

    local_ip = BEGIN_CLIENT_IP;
    remote_ip = BEGIN_SERVER_IP;

    tun_sum = tun_sum > MAX_TUN_SUM ? MAX_TUN_SUM : tun_sum;

    for(i=0;i<tun_sum;i++){
        vpn->addrs[i] = malloc(sizeof(vpn_tun_addr_t));
        hex_to_ip(local_ip, vpn->addrs[i]->local_ip);
        hex_to_ip(remote_ip, vpn->addrs[i]->remote_ip);
        vpn->addrs[i]->is_used = 0;
        LSQ_INFO("local %s, remote %s", vpn->addrs[i]->local_ip, vpn->addrs[i]->remote_ip);

        local_ip = local_ip + (1<<8);
        remote_ip = remote_ip + (1<<8);

    }
    vpn->max_conn = tun_sum;

    return 1;
}