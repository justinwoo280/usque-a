#include <usque/usque.h>

#include <cstdio>
#include <cstring>
#include <cassert>
#include <string>

static int failures = 0;
static const char *TESTDATA_DIR = nullptr;

static void check(const char *name, bool cond) {
    if (!cond) {
        std::printf("FAIL: %s\n", name);
        failures++;
    } else {
        std::printf("PASS: %s\n", name);
    }
}

static std::string testdata_path(const char *file) {
    return std::string(TESTDATA_DIR) + "/" + file;
}

static void test_full_config() {
    std::printf("\n--- Full config ---\n");
    char errbuf[256] = {};
    usque_config_t *cfg = nullptr;

    std::string path = testdata_path("full.json");
    usque_error_t err = usque_config_load_file(path.c_str(), &cfg, errbuf, sizeof(errbuf));
    check("load full.json", err == USQUE_OK);
    if (err != USQUE_OK) {
        std::printf("  error: %s\n", errbuf);
        return;
    }

    // Account
    check("account private_key non-empty", std::strlen(usque_config_account_private_key(cfg)) > 0);
    check("account endpoint_v4", std::strcmp(usque_config_account_endpoint_v4(cfg), "162.159.198.1") == 0);
    check("account endpoint_v6", std::strcmp(usque_config_account_endpoint_v6(cfg), "2606:4700:103::") == 0);
    check("account ipv4", std::strcmp(usque_config_account_ipv4(cfg), "100.96.0.3") == 0);
    check("account id", std::strcmp(usque_config_account_id(cfg), "abc-def-123-456") == 0);

    // TUN
    check("tun name", std::strcmp(usque_config_tun_name(cfg), "usque0") == 0);
    check("tun mtu", usque_config_tun_mtu(cfg) == 1280);
    check("tun ipv4", usque_config_tun_ipv4(cfg) == true);
    check("tun ipv6", usque_config_tun_ipv6(cfg) == true);
    check("tun auto_route", usque_config_tun_auto_route(cfg) == true);
    check("tun dns count", usque_config_tun_dns_count(cfg) == 2);
    check("tun dns[0]", std::strcmp(usque_config_tun_dns_at(cfg, 0), "1.1.1.1") == 0);
    check("tun dns[1]", std::strcmp(usque_config_tun_dns_at(cfg, 1), "2606:4700:4700::1111") == 0);
    check("tun dns out-of-range", usque_config_tun_dns_at(cfg, 5) == nullptr);

    // Outbound
    check("outbound port", usque_config_outbound_port(cfg) == 443);
    check("outbound sni", std::strcmp(usque_config_outbound_sni_address(cfg), "consumer-masque.cloudflareclient.com") == 0);
    check("outbound keepalive 30s", usque_config_outbound_keepalive_period_ms(cfg) == 30000);
    check("outbound reconnect 1s", usque_config_outbound_reconnect_delay_ms(cfg) == 1000);
    check("outbound initial_packet_size", usque_config_outbound_initial_packet_size(cfg) == 1242);
    check("outbound tag", std::strcmp(usque_config_outbound_tag(cfg), "warp") == 0);

    // Congestion
    check("congestion type BBR", usque_config_congestion_type(cfg) == USQUE_CONGESTION_BBR);
    check("congestion bbr_profile standard", usque_config_congestion_bbr_profile(cfg) == USQUE_BBR_STANDARD);
    check("congestion brutal_bps 0", usque_config_congestion_brutal_bps(cfg) == 0);

    // Noise
    check("noise enabled", usque_config_noise_enabled(cfg) == true);
    check("noise count", usque_config_noise_count(cfg) == 5);
    check("noise min_size", usque_config_noise_min_size(cfg) == 100);
    check("noise max_size", usque_config_noise_max_size(cfg) == 400);
    check("noise delay_min 10ms", usque_config_noise_delay_min_ms(cfg) == 10);
    check("noise delay_max 50ms", usque_config_noise_delay_max_ms(cfg) == 50);

    // Pre-noise
    check("pre_noise enabled", usque_config_pre_noise_enabled(cfg) == true);
    check("pre_noise count", usque_config_pre_noise_count(cfg) == 3);
    check("pre_noise delay_min 5ms", usque_config_pre_noise_delay_min_ms(cfg) == 5);

    // Build tunnel config
    usque_tunnel_config_t tc;
    err = usque_config_build_tunnel_config(cfg, &tc, errbuf, sizeof(errbuf));
    check("build tunnel config", err == USQUE_OK);
    check("tc port", tc.outbound.port == 443);
    check("tc keepalive", tc.outbound.keepalive_period_ms == 30000);
    check("tc congestion BBR", tc.outbound.congestion.type == USQUE_CONGESTION_BBR);
    check("tc account ipv4", std::strcmp(tc.account.ipv4, "100.96.0.3") == 0);
    check("tc dns_count", tc.tun.dns_count == 2);

    usque_config_destroy(cfg);
}

static void test_minimal_config() {
    std::printf("\n--- Minimal config (defaults) ---\n");
    char errbuf[256] = {};
    usque_config_t *cfg = nullptr;

    std::string path = testdata_path("minimal.json");
    usque_error_t err = usque_config_load_file(path.c_str(), &cfg, errbuf, sizeof(errbuf));
    check("load minimal.json", err == USQUE_OK);
    if (err != USQUE_OK) {
        std::printf("  error: %s\n", errbuf);
        return;
    }

    // Defaults should be applied
    check("default port 443", usque_config_outbound_port(cfg) == 443);
    check("default keepalive 30s", usque_config_outbound_keepalive_period_ms(cfg) == 30000);
    check("default reconnect 1s", usque_config_outbound_reconnect_delay_ms(cfg) == 1000);
    check("default sni", std::strcmp(usque_config_outbound_sni_address(cfg), "consumer-masque.cloudflareclient.com") == 0);
    check("default mtu 1280", usque_config_tun_mtu(cfg) == 1280);
    check("default dns count", usque_config_tun_dns_count(cfg) == 2);
    check("default dns[0]", std::strcmp(usque_config_tun_dns_at(cfg, 0), "1.1.1.1") == 0);
    check("default congestion BBR", usque_config_congestion_type(cfg) == USQUE_CONGESTION_BBR);

    usque_config_destroy(cfg);
}

static void test_parse_error() {
    std::printf("\n--- Parse error ---\n");
    char errbuf[256] = {};
    usque_config_t *cfg = nullptr;

    usque_error_t err = usque_config_load_string("{invalid json", 13, &cfg, errbuf, sizeof(errbuf));
    check("invalid JSON rejected", err == USQUE_ERR_PARSE);
    check("errbuf non-empty", std::strlen(errbuf) > 0);
    std::printf("  error: %s\n", errbuf);

    // Missing account
    err = usque_config_load_string("{}", 2, &cfg, errbuf, sizeof(errbuf));
    check("empty object rejected", err == USQUE_ERR_PARSE);

    // Wrong inbound type
    const char *bad_inbound = R"({"account":{"private_key":"x"},"inbound":{"type":"socks"}})";
    err = usque_config_load_string(bad_inbound, std::strlen(bad_inbound), &cfg, errbuf, sizeof(errbuf));
    check("socks inbound rejected", err == USQUE_ERR_PARSE);
    std::printf("  error: %s\n", errbuf);

    // Null args
    err = usque_config_load_file(nullptr, &cfg, errbuf, sizeof(errbuf));
    check("null path rejected", err == USQUE_ERR_INVALID_ARG);
}

static void test_save_roundtrip() {
    std::printf("\n--- Save/roundtrip ---\n");
    char errbuf[256] = {};
    usque_config_t *cfg = nullptr;

    std::string path = testdata_path("full.json");
    usque_error_t err = usque_config_load_file(path.c_str(), &cfg, errbuf, sizeof(errbuf));
    check("load for roundtrip", err == USQUE_OK);
    if (err != USQUE_OK) return;

    const char *out_path = "/tmp/usque_test_save.json";
    err = usque_config_save_file(cfg, out_path, errbuf, sizeof(errbuf));
    check("save file", err == USQUE_OK);
    usque_config_destroy(cfg);
    cfg = nullptr;

    // Reload
    err = usque_config_load_file(out_path, &cfg, errbuf, sizeof(errbuf));
    check("reload saved file", err == USQUE_OK);
    if (err != USQUE_OK) {
        std::printf("  error: %s\n", errbuf);
        return;
    }

    check("roundtrip port", usque_config_outbound_port(cfg) == 443);
    check("roundtrip endpoint_v4", std::strcmp(usque_config_account_endpoint_v4(cfg), "162.159.198.1") == 0);
    check("roundtrip keepalive", usque_config_outbound_keepalive_period_ms(cfg) == 30000);
    check("roundtrip noise count", usque_config_noise_count(cfg) == 5);

    usque_config_destroy(cfg);
    std::remove(out_path);
}

int main(int argc, char *argv[]) {
    TESTDATA_DIR = (argc > 1) ? argv[1] : "tests/testdata";

    test_full_config();
    test_minimal_config();
    test_parse_error();
    test_save_roundtrip();

    if (failures > 0) {
        std::printf("\n%d tests FAILED\n", failures);
        return 1;
    }
    std::printf("\nAll config tests passed\n");
    return 0;
}
