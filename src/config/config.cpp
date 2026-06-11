#include "usque/config.h"
#include "config_impl.h"
#include "parse.h"
#include "validate.h"

#include <cstring>
#include <string>

static void set_errbuf(char *errbuf, size_t len, const std::string &msg) {
    if (!errbuf || len == 0) return;
    size_t n = msg.size();
    if (n >= len) n = len - 1;
    std::memcpy(errbuf, msg.c_str(), n);
    errbuf[n] = '\0';
}

static void safe_copy(char *dst, const std::string &src, size_t max) {
    if (max == 0) return;
    size_t n = src.size() < max - 1 ? src.size() : max - 1;
    std::memcpy(dst, src.c_str(), n);
    dst[n] = '\0';
}

extern "C" usque_error_t usque_config_load_file(const char *path,
                                                 usque_config_t **out,
                                                 char *errbuf, size_t errbuf_len) {
    if (!path || !out) {
        set_errbuf(errbuf, errbuf_len, "null argument");
        return USQUE_ERR_INVALID_ARG;
    }

    auto result = usque::parse_file(path);
    if (!result.success) {
        set_errbuf(errbuf, errbuf_len, result.error);
        return USQUE_ERR_PARSE;
    }

    *out = new usque_config{std::move(result.config)};
    return USQUE_OK;
}

extern "C" usque_error_t usque_config_load_string(const char *json, size_t json_len,
                                                   usque_config_t **out,
                                                   char *errbuf, size_t errbuf_len) {
    if (!json || !out) {
        set_errbuf(errbuf, errbuf_len, "null argument");
        return USQUE_ERR_INVALID_ARG;
    }

    auto result = usque::parse_json(json, json_len);
    if (!result.success) {
        set_errbuf(errbuf, errbuf_len, result.error);
        return USQUE_ERR_PARSE;
    }

    *out = new usque_config{std::move(result.config)};
    return USQUE_OK;
}

extern "C" void usque_config_destroy(usque_config_t *cfg) {
    delete cfg;
}

/* ---- Account ---- */

extern "C" const char* usque_config_account_private_key(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.private_key.c_str() : "";
}
extern "C" const char* usque_config_account_endpoint_v4(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.endpoint_v4.c_str() : "";
}
extern "C" const char* usque_config_account_endpoint_v6(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.endpoint_v6.c_str() : "";
}
extern "C" const char* usque_config_account_endpoint_h2_v4(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.endpoint_h2_v4.c_str() : "";
}
extern "C" const char* usque_config_account_endpoint_h2_v6(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.endpoint_h2_v6.c_str() : "";
}
extern "C" const char* usque_config_account_endpoint_pub_key(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.endpoint_pub_key.c_str() : "";
}
extern "C" const char* usque_config_account_license(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.license.c_str() : "";
}
extern "C" const char* usque_config_account_id(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.id.c_str() : "";
}
extern "C" const char* usque_config_account_access_token(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.access_token.c_str() : "";
}
extern "C" const char* usque_config_account_ipv4(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.ipv4.c_str() : "";
}
extern "C" const char* usque_config_account_ipv6(const usque_config_t *cfg) {
    return cfg ? cfg->data.account.ipv6.c_str() : "";
}

/* ---- TUN Inbound ---- */

extern "C" const char* usque_config_tun_name(const usque_config_t *cfg) {
    return cfg ? cfg->data.tun.name.c_str() : "";
}
extern "C" int usque_config_tun_mtu(const usque_config_t *cfg) {
    return cfg ? cfg->data.tun.mtu : 0;
}
extern "C" bool usque_config_tun_ipv4(const usque_config_t *cfg) {
    return cfg ? cfg->data.tun.ipv4 : false;
}
extern "C" bool usque_config_tun_ipv6(const usque_config_t *cfg) {
    return cfg ? cfg->data.tun.ipv6 : false;
}
extern "C" bool usque_config_tun_persist(const usque_config_t *cfg) {
    return cfg ? cfg->data.tun.persist : false;
}
extern "C" int usque_config_tun_fd(const usque_config_t *cfg) {
    return cfg ? cfg->data.tun.tun_fd : 0;
}
extern "C" bool usque_config_tun_auto_route(const usque_config_t *cfg) {
    return cfg ? cfg->data.tun.auto_route : false;
}
extern "C" int usque_config_tun_dns_count(const usque_config_t *cfg) {
    return cfg ? static_cast<int>(cfg->data.tun.dns.size()) : 0;
}
extern "C" const char* usque_config_tun_dns_at(const usque_config_t *cfg, int index) {
    if (!cfg || index < 0 || index >= static_cast<int>(cfg->data.tun.dns.size()))
        return nullptr;
    return cfg->data.tun.dns[index].c_str();
}

/* ---- Outbound ---- */

extern "C" const char* usque_config_outbound_tag(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.tag.c_str() : "";
}
extern "C" int usque_config_outbound_port(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.port : 0;
}
extern "C" bool usque_config_outbound_use_ipv6(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.use_ipv6 : false;
}
extern "C" bool usque_config_outbound_use_http2(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.use_http2 : false;
}
extern "C" const char* usque_config_outbound_sni_address(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.sni_address.c_str() : "";
}
extern "C" int64_t usque_config_outbound_keepalive_period_ms(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.keepalive_period_ms : 0;
}
extern "C" uint16_t usque_config_outbound_initial_packet_size(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.initial_packet_size : 0;
}
extern "C" int64_t usque_config_outbound_reconnect_delay_ms(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.reconnect_delay_ms : 0;
}
extern "C" bool usque_config_outbound_always_reconnect(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.always_reconnect : false;
}
extern "C" bool usque_config_outbound_insecure(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.insecure : false;
}
extern "C" const char* usque_config_outbound_on_connect(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.on_connect.c_str() : "";
}
extern "C" const char* usque_config_outbound_on_disconnect(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.on_disconnect.c_str() : "";
}

/* ---- Congestion ---- */

extern "C" usque_congestion_type_t usque_config_congestion_type(const usque_config_t *cfg) {
    if (!cfg) return USQUE_CONGESTION_RENO;
    switch (cfg->data.outbound.congestion.type) {
        case usque::CongestionType::Reno:   return USQUE_CONGESTION_RENO;
        case usque::CongestionType::BBR:    return USQUE_CONGESTION_BBR;
        case usque::CongestionType::Brutal: return USQUE_CONGESTION_BRUTAL;
    }
    return USQUE_CONGESTION_BBR;
}
extern "C" uint64_t usque_config_congestion_brutal_bps(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.congestion.brutal_bps : 0;
}
extern "C" usque_bbr_profile_t usque_config_congestion_bbr_profile(const usque_config_t *cfg) {
    if (!cfg) return USQUE_BBR_STANDARD;
    switch (cfg->data.outbound.congestion.bbr_profile) {
        case usque::BBRProfile::Conservative: return USQUE_BBR_CONSERVATIVE;
        case usque::BBRProfile::Standard:     return USQUE_BBR_STANDARD;
        case usque::BBRProfile::Aggressive:   return USQUE_BBR_AGGRESSIVE;
    }
    return USQUE_BBR_STANDARD;
}

/* ---- Noise ---- */

extern "C" bool    usque_config_noise_enabled(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.noise.enabled : false;
}
extern "C" int     usque_config_noise_count(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.noise.count : 0;
}
extern "C" int     usque_config_noise_min_size(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.noise.min_size : 0;
}
extern "C" int     usque_config_noise_max_size(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.noise.max_size : 0;
}
extern "C" int64_t usque_config_noise_delay_min_ms(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.noise.delay_min_ms : 0;
}
extern "C" int64_t usque_config_noise_delay_max_ms(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.noise.delay_max_ms : 0;
}

/* ---- Pre-noise ---- */

extern "C" bool    usque_config_pre_noise_enabled(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.pre_noise.enabled : false;
}
extern "C" int     usque_config_pre_noise_count(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.pre_noise.count : 0;
}
extern "C" int     usque_config_pre_noise_min_size(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.pre_noise.min_size : 0;
}
extern "C" int     usque_config_pre_noise_max_size(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.pre_noise.max_size : 0;
}
extern "C" int64_t usque_config_pre_noise_delay_min_ms(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.pre_noise.delay_min_ms : 0;
}
extern "C" int64_t usque_config_pre_noise_delay_max_ms(const usque_config_t *cfg) {
    return cfg ? cfg->data.outbound.pre_noise.delay_max_ms : 0;
}

/* ---- Build tunnel config ---- */

extern "C" usque_error_t usque_config_build_tunnel_config(
    const usque_config_t *cfg,
    usque_tunnel_config_t *out,
    char *errbuf, size_t errbuf_len)
{
    if (!cfg || !out) {
        set_errbuf(errbuf, errbuf_len, "null argument");
        return USQUE_ERR_INVALID_ARG;
    }

    std::memset(out, 0, sizeof(*out));

    const auto &a = cfg->data.account;
    safe_copy(out->account.private_key,     a.private_key,     USQUE_MAX_KEY_LEN);
    safe_copy(out->account.endpoint_v4,     a.endpoint_v4,     USQUE_MAX_IP_LEN);
    safe_copy(out->account.endpoint_v6,     a.endpoint_v6,     USQUE_MAX_IP_LEN);
    safe_copy(out->account.endpoint_h2_v4,  a.endpoint_h2_v4,  USQUE_MAX_IP_LEN);
    safe_copy(out->account.endpoint_h2_v6,  a.endpoint_h2_v6,  USQUE_MAX_IP_LEN);
    safe_copy(out->account.endpoint_pub_key, a.endpoint_pub_key, USQUE_MAX_KEY_LEN);
    safe_copy(out->account.license,         a.license,         USQUE_MAX_KEY_LEN);
    safe_copy(out->account.id,              a.id,              USQUE_MAX_UUID_LEN);
    safe_copy(out->account.access_token,    a.access_token,    USQUE_MAX_KEY_LEN);
    safe_copy(out->account.ipv4,            a.ipv4,            USQUE_MAX_IP_LEN);
    safe_copy(out->account.ipv6,            a.ipv6,            USQUE_MAX_IP_LEN);

    const auto &t = cfg->data.tun;
    safe_copy(out->tun.name, t.name, USQUE_MAX_IFACE_LEN);
    out->tun.mtu        = t.mtu;
    out->tun.ipv4       = t.ipv4;
    out->tun.ipv6       = t.ipv6;
    out->tun.persist    = t.persist;
    out->tun.tun_fd     = t.tun_fd;
    out->tun.auto_route = t.auto_route;
    out->tun.dns_count  = static_cast<int>(t.dns.size());
    if (out->tun.dns_count > USQUE_MAX_DNS_COUNT)
        out->tun.dns_count = USQUE_MAX_DNS_COUNT;
    for (int i = 0; i < out->tun.dns_count; i++) {
        safe_copy(out->tun.dns[i], t.dns[i], USQUE_MAX_IP_LEN);
    }

    const auto &ob = cfg->data.outbound;
    safe_copy(out->outbound.tag,           ob.tag,           USQUE_MAX_TAG_LEN);
    safe_copy(out->outbound.sni_address,   ob.sni_address,   USQUE_MAX_SNI_LEN);
    safe_copy(out->outbound.on_connect,    ob.on_connect,    USQUE_MAX_PATH_LEN);
    safe_copy(out->outbound.on_disconnect, ob.on_disconnect, USQUE_MAX_PATH_LEN);
    out->outbound.port                = ob.port;
    out->outbound.use_ipv6            = ob.use_ipv6;
    out->outbound.use_http2           = ob.use_http2;
    out->outbound.keepalive_period_ms = ob.keepalive_period_ms;
    out->outbound.initial_packet_size = ob.initial_packet_size;
    out->outbound.reconnect_delay_ms  = ob.reconnect_delay_ms;
    out->outbound.always_reconnect    = ob.always_reconnect;
    out->outbound.insecure            = ob.insecure;

    switch (ob.congestion.type) {
        case usque::CongestionType::Reno:   out->outbound.congestion.type = USQUE_CONGESTION_RENO; break;
        case usque::CongestionType::BBR:    out->outbound.congestion.type = USQUE_CONGESTION_BBR; break;
        case usque::CongestionType::Brutal: out->outbound.congestion.type = USQUE_CONGESTION_BRUTAL; break;
    }
    out->outbound.congestion.brutal_bps = ob.congestion.brutal_bps;
    switch (ob.congestion.bbr_profile) {
        case usque::BBRProfile::Conservative: out->outbound.congestion.bbr_profile = USQUE_BBR_CONSERVATIVE; break;
        case usque::BBRProfile::Standard:     out->outbound.congestion.bbr_profile = USQUE_BBR_STANDARD; break;
        case usque::BBRProfile::Aggressive:   out->outbound.congestion.bbr_profile = USQUE_BBR_AGGRESSIVE; break;
    }

    const auto &n = ob.noise;
    out->outbound.noise.enabled      = n.enabled;
    out->outbound.noise.count        = n.count;
    out->outbound.noise.min_size     = n.min_size;
    out->outbound.noise.max_size     = n.max_size;
    out->outbound.noise.delay_min_ms = n.delay_min_ms;
    out->outbound.noise.delay_max_ms = n.delay_max_ms;

    const auto &pn = ob.pre_noise;
    out->outbound.pre_noise.enabled      = pn.enabled;
    out->outbound.pre_noise.count        = pn.count;
    out->outbound.pre_noise.min_size     = pn.min_size;
    out->outbound.pre_noise.max_size     = pn.max_size;
    out->outbound.pre_noise.delay_min_ms = pn.delay_min_ms;
    out->outbound.pre_noise.delay_max_ms = pn.delay_max_ms;

    return USQUE_OK;
}
