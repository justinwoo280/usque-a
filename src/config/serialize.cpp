#include "usque/config.h"
#include "config_impl.h"
#include "duration.h"

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace usque {

static void set_string(rapidjson::Value &obj, rapidjson::Document::AllocatorType &alloc,
                       const char *key, const std::string &val) {
    obj.AddMember(rapidjson::Value(key, alloc),
                  rapidjson::Value(val.c_str(), alloc),
                  alloc);
}

static void add_noise(rapidjson::Value &obj, rapidjson::Document::AllocatorType &alloc,
                      const char *key, const NoiseConfig &nc) {
    rapidjson::Value noise(rapidjson::kObjectType);
    noise.AddMember("enabled", nc.enabled, alloc);
    noise.AddMember("count", nc.count, alloc);
    noise.AddMember("min_size", nc.min_size, alloc);
    noise.AddMember("max_size", nc.max_size, alloc);
    set_string(noise, alloc, "delay_min", format_duration_ms(nc.delay_min_ms));
    set_string(noise, alloc, "delay_max", format_duration_ms(nc.delay_max_ms));
    obj.AddMember(rapidjson::Value(key, alloc), noise, alloc);
}

static std::string congestion_type_str(CongestionType t) {
    switch (t) {
        case CongestionType::Reno:   return "reno";
        case CongestionType::Brutal: return "brutal";
        case CongestionType::BBR:    return "bbr";
    }
    return "bbr";
}

static std::string bbr_profile_str(BBRProfile p) {
    switch (p) {
        case BBRProfile::Conservative: return "conservative";
        case BBRProfile::Aggressive:   return "aggressive";
        case BBRProfile::Standard:     return "standard";
    }
    return "standard";
}

} // namespace usque

static void set_errbuf(char *errbuf, size_t len, const std::string &msg) {
    if (!errbuf || len == 0) return;
    size_t n = msg.size();
    if (n >= len) n = len - 1;
    std::memcpy(errbuf, msg.c_str(), n);
    errbuf[n] = '\0';
}

extern "C" usque_error_t usque_config_save_file(const usque_config_t *cfg,
                                                  const char *path,
                                                  char *errbuf, size_t errbuf_len) {
    if (!cfg || !path) {
        set_errbuf(errbuf, errbuf_len, "null argument");
        return USQUE_ERR_INVALID_ARG;
    }

    using namespace rapidjson;
    Document doc(kObjectType);
    auto &alloc = doc.GetAllocator();
    const auto &fc = cfg->data;

    // Account
    Value account(kObjectType);
    usque::set_string(account, alloc, "private_key",     fc.account.private_key);
    usque::set_string(account, alloc, "endpoint_v4",     fc.account.endpoint_v4);
    usque::set_string(account, alloc, "endpoint_v6",     fc.account.endpoint_v6);
    usque::set_string(account, alloc, "endpoint_h2_v4",  fc.account.endpoint_h2_v4);
    usque::set_string(account, alloc, "endpoint_h2_v6",  fc.account.endpoint_h2_v6);
    usque::set_string(account, alloc, "endpoint_pub_key", fc.account.endpoint_pub_key);
    usque::set_string(account, alloc, "license",         fc.account.license);
    usque::set_string(account, alloc, "id",              fc.account.id);
    usque::set_string(account, alloc, "access_token",    fc.account.access_token);
    usque::set_string(account, alloc, "ipv4",            fc.account.ipv4);
    usque::set_string(account, alloc, "ipv6",            fc.account.ipv6);
    doc.AddMember("account", account, alloc);

    // Inbound
    Value inbound(kObjectType);
    usque::set_string(inbound, alloc, "type", "tun");

    Value tun_settings(kObjectType);
    usque::set_string(tun_settings, alloc, "name", fc.tun.name);
    tun_settings.AddMember("mtu",        fc.tun.mtu, alloc);
    tun_settings.AddMember("ipv4",       fc.tun.ipv4, alloc);
    tun_settings.AddMember("ipv6",       fc.tun.ipv6, alloc);
    tun_settings.AddMember("persist",    fc.tun.persist, alloc);
    tun_settings.AddMember("tun_fd",     fc.tun.tun_fd, alloc);
    tun_settings.AddMember("auto_route", fc.tun.auto_route, alloc);

    Value dns_arr(kArrayType);
    for (const auto &d : fc.tun.dns) {
        dns_arr.PushBack(Value(d.c_str(), alloc), alloc);
    }
    tun_settings.AddMember("dns", dns_arr, alloc);
    inbound.AddMember("settings", tun_settings, alloc);
    doc.AddMember("inbound", inbound, alloc);

    // Outbound
    Value outbound(kObjectType);
    usque::set_string(outbound, alloc, "tag", fc.outbound.tag);

    Value ob_settings(kObjectType);
    ob_settings.AddMember("port",                fc.outbound.port, alloc);
    ob_settings.AddMember("use_ipv6",            fc.outbound.use_ipv6, alloc);
    ob_settings.AddMember("use_http2",           fc.outbound.use_http2, alloc);
    usque::set_string(ob_settings, alloc, "sni_address", fc.outbound.sni_address);
    usque::set_string(ob_settings, alloc, "keepalive_period",
                      usque::format_duration_ms(fc.outbound.keepalive_period_ms));
    ob_settings.AddMember("initial_packet_size", fc.outbound.initial_packet_size, alloc);
    usque::set_string(ob_settings, alloc, "reconnect_delay",
                      usque::format_duration_ms(fc.outbound.reconnect_delay_ms));
    ob_settings.AddMember("always_reconnect",    fc.outbound.always_reconnect, alloc);
    ob_settings.AddMember("insecure",            fc.outbound.insecure, alloc);
    usque::set_string(ob_settings, alloc, "on_connect",    fc.outbound.on_connect);
    usque::set_string(ob_settings, alloc, "on_disconnect", fc.outbound.on_disconnect);

    Value congestion(kObjectType);
    usque::set_string(congestion, alloc, "type",
                      usque::congestion_type_str(fc.outbound.congestion.type));
    congestion.AddMember("brutal_bps", fc.outbound.congestion.brutal_bps, alloc);
    usque::set_string(congestion, alloc, "bbr_profile",
                      usque::bbr_profile_str(fc.outbound.congestion.bbr_profile));
    ob_settings.AddMember("congestion", congestion, alloc);

    usque::add_noise(ob_settings, alloc, "noise",     fc.outbound.noise);
    usque::add_noise(ob_settings, alloc, "pre_noise", fc.outbound.pre_noise);

    outbound.AddMember("settings", ob_settings, alloc);
    doc.AddMember("outbound", outbound, alloc);

    // Write
    StringBuffer buf;
    PrettyWriter<StringBuffer> writer(buf);
    doc.Accept(writer);

    FILE *fp = std::fopen(path, "w");
    if (!fp) {
        set_errbuf(errbuf, errbuf_len, std::string("cannot open file for writing: ") + path);
        return USQUE_ERR_IO;
    }

    size_t written = std::fwrite(buf.GetString(), 1, buf.GetSize(), fp);
    std::fclose(fp);

    if (written != buf.GetSize()) {
        set_errbuf(errbuf, errbuf_len, "failed to write complete config");
        return USQUE_ERR_IO;
    }

    return USQUE_OK;
}
