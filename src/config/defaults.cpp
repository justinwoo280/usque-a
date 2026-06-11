#include "defaults.h"

namespace usque {

void apply_defaults(FullConfig &cfg) {
    auto &ob = cfg.outbound;

    if (ob.port == 0) ob.port = 443;
    if (ob.keepalive_period_ms == 0) ob.keepalive_period_ms = 30000;
    if (ob.reconnect_delay_ms == 0) ob.reconnect_delay_ms = 1000;
    if (ob.sni_address.empty()) ob.sni_address = "consumer-masque.cloudflareclient.com";

    if (ob.congestion.type == CongestionType::BBR &&
        ob.congestion.bbr_profile == BBRProfile::Standard &&
        ob.congestion.brutal_bps == 0) {
        // standard is the default BBR profile, already set
    }

    auto &tun = cfg.tun;
    if (tun.mtu == 0) tun.mtu = 1280;
    if (tun.dns.empty()) {
        tun.dns.push_back("1.1.1.1");
        tun.dns.push_back("2606:4700:4700::1111");
    }
}

} // namespace usque
