#pragma once

#include <string>

namespace usque {

struct RegistrationResult {
    bool        success = false;
    std::string error;

    // Account data from API
    std::string device_id;
    std::string access_token;
    std::string license;
    std::string endpoint_v4;
    std::string endpoint_v6;
    std::string endpoint_pub_key;  // PEM
    std::string ipv4;
    std::string ipv6;

    // Client key (base64 DER)
    std::string private_key_b64;
};

// Register a new device with Cloudflare WARP.
// jwt: optional ZeroTrust team token (empty for regular WARP)
// device_name: optional device name
RegistrationResult register_device(const std::string &jwt = "",
                                   const std::string &device_name = "");

} // namespace usque
