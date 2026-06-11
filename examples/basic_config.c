#include <usque/usque.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config.json>\n", argv[0]);
        return 1;
    }

    printf("usque-a v%s\n", usque_version_string());

    char errbuf[256] = {0};
    usque_config_t *cfg = NULL;

    usque_error_t err = usque_config_load_file(argv[1], &cfg, errbuf, sizeof(errbuf));
    if (err != USQUE_OK) {
        fprintf(stderr, "Failed to load config: %s (%s)\n", usque_error_name(err), errbuf);
        return 1;
    }

    printf("\n=== Account ===\n");
    printf("  ID:       %s\n", usque_config_account_id(cfg));
    printf("  IPv4:     %s\n", usque_config_account_ipv4(cfg));
    printf("  IPv6:     %s\n", usque_config_account_ipv6(cfg));
    printf("  Endpoint: %s / %s\n",
           usque_config_account_endpoint_v4(cfg),
           usque_config_account_endpoint_v6(cfg));

    printf("\n=== TUN Inbound ===\n");
    printf("  Name:      %s\n", usque_config_tun_name(cfg));
    printf("  MTU:       %d\n", usque_config_tun_mtu(cfg));
    printf("  Auto route: %s\n", usque_config_tun_auto_route(cfg) ? "yes" : "no");
    printf("  DNS:");
    for (int i = 0; i < usque_config_tun_dns_count(cfg); i++) {
        printf(" %s", usque_config_tun_dns_at(cfg, i));
    }
    printf("\n");

    printf("\n=== Outbound ===\n");
    printf("  Tag:        %s\n", usque_config_outbound_tag(cfg));
    printf("  Port:       %d\n", usque_config_outbound_port(cfg));
    printf("  SNI:        %s\n", usque_config_outbound_sni_address(cfg));
    printf("  Keepalive:  %lldms\n", (long long)usque_config_outbound_keepalive_period_ms(cfg));
    printf("  Reconnect:  %lldms\n", (long long)usque_config_outbound_reconnect_delay_ms(cfg));

    const char *cc_type = "unknown";
    switch (usque_config_congestion_type(cfg)) {
        case USQUE_CONGESTION_RENO:   cc_type = "reno"; break;
        case USQUE_CONGESTION_BBR:    cc_type = "bbr"; break;
        case USQUE_CONGESTION_BRUTAL: cc_type = "brutal"; break;
    }
    printf("  Congestion: %s\n", cc_type);

    printf("\n=== Build Tunnel Config ===\n");
    usque_tunnel_config_t tc;
    err = usque_config_build_tunnel_config(cfg, &tc, errbuf, sizeof(errbuf));
    if (err != USQUE_OK) {
        fprintf(stderr, "Failed to build tunnel config: %s\n", errbuf);
        usque_config_destroy(cfg);
        return 1;
    }
    printf("  Tunnel ready: port=%d, keepalive=%lldms, dns_count=%d\n",
           tc.outbound.port,
           (long long)tc.outbound.keepalive_period_ms,
           tc.tun.dns_count);

    usque_config_destroy(cfg);
    printf("\nDone.\n");
    return 0;
}
