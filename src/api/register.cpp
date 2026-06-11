#include "register.h"
#include "https_client.h"

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <cstring>
#include <ctime>
#include <sstream>
#include <vector>

namespace usque {

static const char *API_HOST = "api.cloudflareclient.com";
static const int   API_PORT = 443;
static const char *API_VERSION = "v0a4471";

static std::string base64_encode(const uint8_t *data, size_t len) {
    size_t out_len;
    if (!EVP_EncodedLength(&out_len, len)) return "";
    std::string result(out_len, '\0');
    int n = EVP_EncodeBlock((uint8_t *)result.data(), data, (int)len);
    if (n < 0) return "";
    result.resize((size_t)n);
    return result;
}

static std::string random_hex(int bytes) {
    std::vector<uint8_t> buf((size_t)bytes);
    RAND_bytes(buf.data(), bytes);
    std::string hex;
    hex.reserve((size_t)(bytes * 2));
    for (int i = 0; i < bytes; i++) {
        char tmp[3];
        snprintf(tmp, sizeof(tmp), "%02x", buf[i]);
        hex += tmp;
    }
    return hex;
}

// Simple JSON string extraction (no full parser needed for these responses)
static std::string json_get_string(const std::string &json, const std::string &key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";
    size_t end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

// Get nested string: find outer key, then inner key within that object
static std::string json_get_nested_string(const std::string &json,
                                          const std::string &outer,
                                          const std::string &inner) {
    std::string search = "\"" + outer + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    size_t brace = json.find('{', pos);
    if (brace == std::string::npos) return "";
    // Find matching closing brace
    int depth = 1;
    size_t end_brace = brace + 1;
    while (end_brace < json.size() && depth > 0) {
        if (json[end_brace] == '{') depth++;
        else if (json[end_brace] == '}') depth--;
        end_brace++;
    }
    std::string sub = json.substr(brace, end_brace - brace);
    return json_get_string(sub, inner);
}

// Get deeply nested: account -> config -> peers[0] -> endpoint -> v4
static std::string json_get_peers_endpoint(const std::string &json,
                                           const std::string &field) {
    // Find "peers" array
    size_t peers_pos = json.find("\"peers\"");
    if (peers_pos == std::string::npos) return "";
    size_t bracket = json.find('[', peers_pos);
    if (bracket == std::string::npos) return "";
    size_t obj_start = json.find('{', bracket);
    if (obj_start == std::string::npos) return "";
    // Find the endpoint object within the first peer
    size_t ep_pos = json.find("\"endpoint\"", obj_start);
    if (ep_pos == std::string::npos) return "";
    size_t ep_brace = json.find('{', ep_pos);
    if (ep_brace == std::string::npos) return "";
    int depth = 1;
    size_t ep_end = ep_brace + 1;
    while (ep_end < json.size() && depth > 0) {
        if (json[ep_end] == '{') depth++;
        else if (json[ep_end] == '}') depth--;
        ep_end++;
    }
    std::string ep_obj = json.substr(ep_brace, ep_end - ep_brace);
    return json_get_string(ep_obj, field);
}

static std::string json_get_interface_address(const std::string &json,
                                              const std::string &field) {
    size_t iface_pos = json.find("\"interface\"");
    if (iface_pos == std::string::npos) return "";
    size_t addr_pos = json.find("\"addresses\"", iface_pos);
    if (addr_pos == std::string::npos) return "";
    size_t addr_brace = json.find('{', addr_pos);
    if (addr_brace == std::string::npos) return "";
    int depth = 1;
    size_t addr_end = addr_brace + 1;
    while (addr_end < json.size() && depth > 0) {
        if (json[addr_end] == '{') depth++;
        else if (json[addr_end] == '}') depth--;
        addr_end++;
    }
    std::string addr_obj = json.substr(addr_brace, addr_end - addr_brace);
    return json_get_string(addr_obj, field);
}

RegistrationResult register_device(const std::string &jwt,
                                   const std::string &device_name) {
    RegistrationResult result;

    // Step 1: Generate fake WG key (32 random bytes, base64)
    uint8_t fake_key[32];
    RAND_bytes(fake_key, sizeof(fake_key));
    std::string fake_key_b64 = base64_encode(fake_key, sizeof(fake_key));

    // Generate serial
    std::string serial = random_hex(8);

    // Build registration JSON
    time_t now = time(nullptr);
    struct tm *tm = gmtime(&now);
    char tos[64];
    strftime(tos, sizeof(tos), "%Y-%m-%dT%H:%M:%S.000Z", tm);

    std::ostringstream reg_json;
    reg_json << "{"
        << "\"key\":\"" << fake_key_b64 << "\","
        << "\"install_id\":\"\","
        << "\"fcm_token\":\"\","
        << "\"tos\":\"" << tos << "\","
        << "\"model\":\"PC\","
        << "\"serial_number\":\"" << serial << "\","
        << "\"os_version\":\"\","
        << "\"key_type\":\"curve25519\","
        << "\"tunnel_type\":\"wireguard\","
        << "\"locale\":\"en_US\""
        << "}";

    // Step 2: POST /reg
    std::string headers = "User-Agent: WARP for Android\r\n"
                          "CF-Client-Version: a-6.35-4471\r\n"
                          "Content-Type: application/json; charset=UTF-8\r\n";
    if (!jwt.empty()) {
        headers += "CF-Access-Jwt-Assertion: " + jwt + "\r\n";
    }

    std::string path = std::string("/") + API_VERSION + "/reg";
    std::string body = reg_json.str();

    auto resp = https_request(API_HOST, API_PORT, "POST", path.c_str(),
                              headers.c_str(), body.data(), body.size());
    if (resp.status_code != 200) {
        result.error = "POST /reg failed: HTTP " + std::to_string(resp.status_code) +
                       " - " + resp.body;
        return result;
    }

    std::string device_id = json_get_string(resp.body, "id");
    std::string token = json_get_string(resp.body, "token");
    if (device_id.empty() || token.empty()) {
        result.error = "POST /reg: missing id or token in response";
        return result;
    }

    // Step 3: Generate ECDSA P-256 keypair
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key || EC_KEY_generate_key(ec_key) != 1) {
        EC_KEY_free(ec_key);
        result.error = "ECDSA key generation failed";
        return result;
    }

    // Encode private key as DER (SEC1)
    uint8_t *priv_der = nullptr;
    int priv_len = i2d_ECPrivateKey(ec_key, &priv_der);
    if (priv_len <= 0) {
        EC_KEY_free(ec_key);
        result.error = "ECDSA private key encoding failed";
        return result;
    }
    result.private_key_b64 = base64_encode(priv_der, (size_t)priv_len);
    OPENSSL_free(priv_der);

    // Encode public key as PKIX DER
    uint8_t *pub_der = nullptr;
    int pub_len = i2d_EC_PUBKEY(ec_key, &pub_der);
    if (pub_len <= 0) {
        EC_KEY_free(ec_key);
        result.error = "ECDSA public key encoding failed";
        return result;
    }
    std::string pub_key_b64 = base64_encode(pub_der, (size_t)pub_len);
    OPENSSL_free(pub_der);
    EC_KEY_free(ec_key);

    // Step 4: PATCH /reg/{id}
    std::ostringstream patch_json;
    patch_json << "{"
        << "\"key\":\"" << pub_key_b64 << "\","
        << "\"key_type\":\"secp256r1\","
        << "\"tunnel_type\":\"masque\"";
    if (!device_name.empty()) {
        patch_json << ",\"name\":\"" << device_name << "\"";
    }
    patch_json << "}";

    std::string patch_headers = headers;
    patch_headers += "Authorization: Bearer " + token + "\r\n";

    std::string patch_path = std::string("/") + API_VERSION + "/reg/" + device_id;
    std::string patch_body = patch_json.str();

    resp = https_request(API_HOST, API_PORT, "PATCH", patch_path.c_str(),
                         patch_headers.c_str(), patch_body.data(), patch_body.size());
    if (resp.status_code != 200) {
        result.error = "PATCH /reg failed: HTTP " + std::to_string(resp.status_code) +
                       " - " + resp.body;
        return result;
    }

    // Step 5: Parse response
    result.device_id = device_id;
    result.access_token = token;
    result.license = json_get_nested_string(resp.body, "account", "license");
    result.ipv4 = json_get_interface_address(resp.body, "v4");
    result.ipv6 = json_get_interface_address(resp.body, "v6");

    // Endpoint addresses (with port stripping like Go version)
    std::string ep_v4 = json_get_peers_endpoint(resp.body, "v4");
    std::string ep_v6 = json_get_peers_endpoint(resp.body, "v6");

    // Strip port: "162.159.198.1:0" → "162.159.198.1"
    if (ep_v4.size() > 2) {
        size_t colon = ep_v4.rfind(':');
        if (colon != std::string::npos) {
            result.endpoint_v4 = ep_v4.substr(0, colon);
        } else {
            result.endpoint_v4 = ep_v4;
        }
    }

    // Strip brackets + port: "[2606:4700:103::]:0" → "2606:4700:103::"
    if (ep_v6.size() > 4 && ep_v6[0] == '[') {
        size_t bracket_end = ep_v6.find(']');
        if (bracket_end != std::string::npos) {
            result.endpoint_v6 = ep_v6.substr(1, bracket_end - 1);
        }
    }

    // Endpoint public key (PEM)
    result.endpoint_pub_key = json_get_peers_endpoint(resp.body, "public_key");
    // The public_key field from the API might actually be at config.peers[0].public_key
    if (result.endpoint_pub_key.empty()) {
        // Try direct path
        size_t peers_pos = resp.body.find("\"peers\"");
        if (peers_pos != std::string::npos) {
            size_t obj_start = resp.body.find('{', peers_pos);
            if (obj_start != std::string::npos) {
                result.endpoint_pub_key = json_get_string(
                    resp.body.substr(obj_start), "public_key");
            }
        }
    }
    // Normalize: replace any literal backslash-n with actual newlines
    {
        std::string &pem = result.endpoint_pub_key;
        std::string normalized;
        normalized.reserve(pem.size());
        for (size_t i = 0; i < pem.size(); i++) {
            if (i + 1 < pem.size() && pem[i] == '\\' && pem[i + 1] == 'n') {
                normalized += '\n';
                i++;
            } else {
                normalized += pem[i];
            }
        }
        pem = normalized;
    }

    result.success = true;
    return result;
}

} // namespace usque
