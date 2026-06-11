#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace usque {

struct AccountConfig {
    std::string private_key;
    std::string endpoint_v4;
    std::string endpoint_v6;
    std::string endpoint_h2_v4;
    std::string endpoint_h2_v6;
    std::string endpoint_pub_key;
    std::string license;
    std::string id;
    std::string access_token;
    std::string ipv4;
    std::string ipv6;
};

struct TunInboundSettings {
    std::string name;
    int         mtu        = 1280;
    bool        ipv4       = true;
    bool        ipv6       = true;
    bool        persist    = false;
    int         tun_fd     = 0;
    bool        auto_route = true;
    std::vector<std::string> dns;
};

enum class CongestionType { Reno, BBR, Brutal };
enum class BBRProfile { Conservative, Standard, Aggressive };

struct CongestionConfig {
    CongestionType type        = CongestionType::BBR;
    uint64_t       brutal_bps  = 0;
    BBRProfile     bbr_profile = BBRProfile::Standard;
};

struct NoiseConfig {
    bool    enabled      = false;
    int     count        = 0;
    int     min_size     = 0;
    int     max_size     = 0;
    int64_t delay_min_ms = 0;
    int64_t delay_max_ms = 0;
};

struct OutboundSettings {
    std::string tag                 = "warp";
    int         port                = 443;
    bool        use_ipv6            = false;
    bool        use_http2           = false;
    std::string sni_address         = "consumer-masque.cloudflareclient.com";
    int64_t     keepalive_period_ms = 30000;
    uint16_t    initial_packet_size = 0;
    int64_t     reconnect_delay_ms  = 1000;
    bool        always_reconnect    = false;
    bool        insecure            = false;
    std::string on_connect;
    std::string on_disconnect;
    CongestionConfig congestion;
    NoiseConfig    noise;
    NoiseConfig    pre_noise;
};

class FullConfig {
public:
    AccountConfig      account;
    TunInboundSettings tun;
    OutboundSettings   outbound;
};

} // namespace usque

struct usque_config {
    usque::FullConfig data;
};
