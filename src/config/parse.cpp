#include "parse.h"
#include "duration.h"
#include "defaults.h"
#include "validate.h"

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/filereadstream.h>
#include <rapidjson/encodedstream.h>

#include <cstdio>
#include <cstring>

namespace usque {

static std::string get_string(const rapidjson::Value &obj, const char *key, const std::string &def = "") {
    if (!obj.IsObject()) return def;
    auto it = obj.FindMember(key);
    if (it == obj.MemberEnd() || !it->value.IsString()) return def;
    return it->value.GetString();
}

static int get_int(const rapidjson::Value &obj, const char *key, int def = 0) {
    if (!obj.IsObject()) return def;
    auto it = obj.FindMember(key);
    if (it == obj.MemberEnd()) return def;
    if (it->value.IsInt()) return it->value.GetInt();
    if (it->value.IsUint()) return static_cast<int>(it->value.GetUint());
    return def;
}

static uint16_t get_uint16(const rapidjson::Value &obj, const char *key, uint16_t def = 0) {
    if (!obj.IsObject()) return def;
    auto it = obj.FindMember(key);
    if (it == obj.MemberEnd()) return def;
    if (it->value.IsUint()) return static_cast<uint16_t>(it->value.GetUint());
    if (it->value.IsInt() && it->value.GetInt() >= 0) return static_cast<uint16_t>(it->value.GetInt());
    return def;
}

static uint64_t get_uint64(const rapidjson::Value &obj, const char *key, uint64_t def = 0) {
    if (!obj.IsObject()) return def;
    auto it = obj.FindMember(key);
    if (it == obj.MemberEnd()) return def;
    if (it->value.IsUint64()) return it->value.GetUint64();
    if (it->value.IsUint()) return it->value.GetUint();
    return def;
}

static bool get_bool(const rapidjson::Value &obj, const char *key, bool def = false) {
    if (!obj.IsObject()) return def;
    auto it = obj.FindMember(key);
    if (it == obj.MemberEnd() || !it->value.IsBool()) return def;
    return it->value.GetBool();
}

static int64_t get_duration_ms(const rapidjson::Value &obj, const char *key, int64_t def = 0) {
    std::string s = get_string(obj, key);
    if (s.empty()) return def;
    return parse_duration_ms(s, def);
}

static NoiseConfig parse_noise(const rapidjson::Value &obj) {
    NoiseConfig nc;
    nc.enabled      = get_bool(obj, "enabled");
    nc.count        = get_int(obj, "count");
    nc.min_size     = get_int(obj, "min_size");
    nc.max_size     = get_int(obj, "max_size");
    nc.delay_min_ms = get_duration_ms(obj, "delay_min");
    nc.delay_max_ms = get_duration_ms(obj, "delay_max");
    return nc;
}

static CongestionConfig parse_congestion(const rapidjson::Value &obj) {
    CongestionConfig cc;
    std::string type_str = get_string(obj, "type", "bbr");

    if (type_str == "reno")       cc.type = CongestionType::Reno;
    else if (type_str == "brutal") cc.type = CongestionType::Brutal;
    else                           cc.type = CongestionType::BBR;

    cc.brutal_bps = get_uint64(obj, "brutal_bps");

    std::string profile = get_string(obj, "bbr_profile", "standard");
    if (profile == "conservative")      cc.bbr_profile = BBRProfile::Conservative;
    else if (profile == "aggressive")   cc.bbr_profile = BBRProfile::Aggressive;
    else                                cc.bbr_profile = BBRProfile::Standard;

    return cc;
}

static void parse_account(const rapidjson::Value &obj, AccountConfig &acct) {
    acct.private_key     = get_string(obj, "private_key");
    acct.endpoint_v4     = get_string(obj, "endpoint_v4");
    acct.endpoint_v6     = get_string(obj, "endpoint_v6");
    acct.endpoint_h2_v4  = get_string(obj, "endpoint_h2_v4");
    acct.endpoint_h2_v6  = get_string(obj, "endpoint_h2_v6");
    acct.endpoint_pub_key = get_string(obj, "endpoint_pub_key");
    acct.license         = get_string(obj, "license");
    acct.id              = get_string(obj, "id");
    acct.access_token    = get_string(obj, "access_token");
    acct.ipv4            = get_string(obj, "ipv4");
    acct.ipv6            = get_string(obj, "ipv6");
}

static void parse_tun_settings(const rapidjson::Value &obj, TunInboundSettings &tun) {
    tun.name       = get_string(obj, "name");
    tun.mtu        = get_int(obj, "mtu", 1280);
    tun.ipv4       = get_bool(obj, "ipv4", true);
    tun.ipv6       = get_bool(obj, "ipv6", true);
    tun.persist    = get_bool(obj, "persist");
    tun.tun_fd     = get_int(obj, "tun_fd");
    tun.auto_route = get_bool(obj, "auto_route", true);

    auto it = obj.FindMember("dns");
    if (it != obj.MemberEnd() && it->value.IsArray()) {
        for (auto &v : it->value.GetArray()) {
            if (v.IsString()) {
                tun.dns.push_back(v.GetString());
            }
        }
    }
}

static void parse_outbound_settings(const rapidjson::Value &obj, OutboundSettings &ob) {
    ob.tag                 = get_string(obj, "tag", "warp");
    ob.port                = get_int(obj, "port", 443);
    ob.use_ipv6            = get_bool(obj, "use_ipv6");
    ob.use_http2           = get_bool(obj, "use_http2");
    ob.sni_address         = get_string(obj, "sni_address");
    ob.keepalive_period_ms = get_duration_ms(obj, "keepalive_period", 30000);
    ob.initial_packet_size = get_uint16(obj, "initial_packet_size");
    ob.reconnect_delay_ms  = get_duration_ms(obj, "reconnect_delay", 1000);
    ob.always_reconnect    = get_bool(obj, "always_reconnect");
    ob.insecure            = get_bool(obj, "insecure");
    ob.on_connect          = get_string(obj, "on_connect");
    ob.on_disconnect       = get_string(obj, "on_disconnect");

    auto cong_it = obj.FindMember("congestion");
    if (cong_it != obj.MemberEnd() && cong_it->value.IsObject()) {
        ob.congestion = parse_congestion(cong_it->value);
    }

    auto noise_it = obj.FindMember("noise");
    if (noise_it != obj.MemberEnd() && noise_it->value.IsObject()) {
        ob.noise = parse_noise(noise_it->value);
    }

    auto pre_it = obj.FindMember("pre_noise");
    if (pre_it != obj.MemberEnd() && pre_it->value.IsObject()) {
        ob.pre_noise = parse_noise(pre_it->value);
    }
}

static ParseResult parse_document(const rapidjson::Document &doc) {
    ParseResult result{};

    if (!doc.IsObject()) {
        result.success = false;
        result.error = "config must be a JSON object";
        return result;
    }

    // Account
    auto acct_it = doc.FindMember("account");
    if (acct_it == doc.MemberEnd() || !acct_it->value.IsObject()) {
        result.success = false;
        result.error = "missing or invalid 'account' section";
        return result;
    }
    parse_account(acct_it->value, result.config.account);

    // Inbound
    auto in_it = doc.FindMember("inbound");
    if (in_it == doc.MemberEnd() || !in_it->value.IsObject()) {
        result.success = false;
        result.error = "missing or invalid 'inbound' section";
        return result;
    }

    const auto &inbound = in_it->value;
    std::string in_type = get_string(inbound, "type");
    if (in_type != "tun") {
        result.success = false;
        result.error = "unsupported inbound type: " + in_type + " (only 'tun' is supported)";
        return result;
    }

    auto settings_it = inbound.FindMember("settings");
    if (settings_it != inbound.MemberEnd() && settings_it->value.IsObject()) {
        parse_tun_settings(settings_it->value, result.config.tun);
    }

    // Outbound
    auto out_it = doc.FindMember("outbound");
    if (out_it != doc.MemberEnd() && out_it->value.IsObject()) {
        const auto &outbound = out_it->value;
        auto ob_settings_it = outbound.FindMember("settings");
        if (ob_settings_it != outbound.MemberEnd() && ob_settings_it->value.IsObject()) {
            parse_outbound_settings(ob_settings_it->value, result.config.outbound);
        }
        std::string tag = get_string(outbound, "tag");
        if (!tag.empty()) {
            result.config.outbound.tag = tag;
        }
    }

    apply_defaults(result.config);

    std::string verr = validate(result.config);
    if (!verr.empty()) {
        result.success = false;
        result.error = verr;
        return result;
    }

    result.success = true;
    return result;
}

ParseResult parse_json(const char *data, size_t len) {
    rapidjson::Document doc;
    doc.Parse(data, len);

    if (doc.HasParseError()) {
        ParseResult result{};
        result.success = false;
        result.error = std::string("JSON parse error at offset ") +
                       std::to_string(doc.GetErrorOffset()) + ": " +
                       rapidjson::GetParseError_En(doc.GetParseError());
        return result;
    }

    return parse_document(doc);
}

ParseResult parse_file(const char *path) {
    FILE *fp = std::fopen(path, "rb");
    if (!fp) {
        ParseResult result{};
        result.success = false;
        result.error = std::string("cannot open file: ") + path;
        return result;
    }

    char buf[65536];
    rapidjson::FileReadStream is(fp, buf, sizeof(buf));
    rapidjson::AutoUTFInputStream<unsigned, rapidjson::FileReadStream> uis(is);

    rapidjson::Document doc;
    doc.ParseStream(uis);
    std::fclose(fp);

    if (doc.HasParseError()) {
        ParseResult result{};
        result.success = false;
        result.error = std::string("JSON parse error at offset ") +
                       std::to_string(doc.GetErrorOffset()) + ": " +
                       rapidjson::GetParseError_En(doc.GetParseError());
        return result;
    }

    return parse_document(doc);
}

} // namespace usque
