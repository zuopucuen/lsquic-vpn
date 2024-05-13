#include <lsquic.h>
#include <lsquic_logger.h>
#include "os.h"
#include "vpn.h"

int vpn_init(vpn_t *vpn, int server_flag) {
    memset(vpn, 0, sizeof(*vpn));
    vpn->is_server = server_flag;
    vpn->server_ip_or_name  = "auto";
    vpn->server_port    = "auto";
    vpn->wanted_if_name = "";
    vpn->local_tun_ip = vpn->is_server? DEFAULT_SERVER_IP : DEFAULT_CLIENT_IP;
    vpn->remote_tun_ip = vpn->is_server? DEFAULT_CLIENT_IP : DEFAULT_SERVER_IP;
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