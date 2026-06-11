#include "validate.h"

namespace usque {

static std::string validate_congestion(const CongestionConfig &cc) {
    switch (cc.type) {
        case CongestionType::Reno:
            if (cc.brutal_bps != 0)
                return "congestion: reno must not set brutal_bps";
            break;
        case CongestionType::Brutal:
            if (cc.brutal_bps == 0)
                return "congestion: brutal requires brutal_bps > 0";
            break;
        case CongestionType::BBR:
            if (cc.brutal_bps != 0)
                return "congestion: bbr must not set brutal_bps";
            break;
    }
    return "";
}

static std::string validate_noise(const NoiseConfig &nc, const char *label) {
    if (!nc.enabled) return "";
    if (nc.count < 0) {
        return std::string(label) + ": count must be >= 0";
    }
    if (nc.min_size > nc.max_size) {
        return std::string(label) + ": min_size must be <= max_size";
    }
    if (nc.delay_min_ms > nc.delay_max_ms) {
        return std::string(label) + ": delay_min must be <= delay_max";
    }
    return "";
}

std::string validate(const FullConfig &cfg) {
    if (cfg.account.private_key.empty())
        return "account: private_key is required";

    if (cfg.tun.mtu <= 0)
        return "inbound: mtu must be positive";

    std::string err = validate_congestion(cfg.outbound.congestion);
    if (!err.empty()) return err;

    err = validate_noise(cfg.outbound.noise, "noise");
    if (!err.empty()) return err;

    err = validate_noise(cfg.outbound.pre_noise, "pre_noise");
    if (!err.empty()) return err;

    return "";
}

} // namespace usque
