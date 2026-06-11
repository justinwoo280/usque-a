#include <usque/usque.h>

#include <cstdio>
#include <cstring>
#include <string>

static int failures = 0;

static void check(const char *name, bool cond) {
    if (!cond) {
        std::printf("FAIL: %s\n", name);
        failures++;
    } else {
        std::printf("PASS: %s\n", name);
    }
}

static usque_error_t try_load(const char *json, usque_config_t **cfg) {
    char errbuf[256] = {};
    usque_error_t err = usque_config_load_string(json, std::strlen(json), cfg, errbuf, sizeof(errbuf));
    if (err != USQUE_OK) {
        std::printf("  error: %s\n", errbuf);
    }
    return err;
}

static void test_empty_private_key_rejected() {
    std::printf("\n--- Validation: empty private_key ---\n");
    usque_config_t *cfg = nullptr;
    const char *json = R"({
        "account": {},
        "inbound": {"type": "tun"},
        "outbound": {"settings": {}}
    })";
    usque_error_t err = try_load(json, &cfg);
    check("empty private_key rejected", err == USQUE_ERR_PARSE);
}

static void test_brutal_requires_bps() {
    std::printf("\n--- Validation: brutal without bps ---\n");
    usque_config_t *cfg = nullptr;
    const char *json = R"({
        "account": {"private_key": "test-key"},
        "inbound": {"type": "tun"},
        "outbound": {"settings": {"congestion": {"type": "brutal", "brutal_bps": 0}}}
    })";
    usque_error_t err = try_load(json, &cfg);
    check("brutal without bps rejected", err == USQUE_ERR_PARSE);
}

static void test_brutal_with_bps_ok() {
    std::printf("\n--- Validation: brutal with bps ---\n");
    usque_config_t *cfg = nullptr;
    const char *json = R"({
        "account": {"private_key": "test-key"},
        "inbound": {"type": "tun"},
        "outbound": {"settings": {"congestion": {"type": "brutal", "brutal_bps": 10000000}}}
    })";
    usque_error_t err = try_load(json, &cfg);
    check("brutal with bps accepted", err == USQUE_OK);
    if (err == USQUE_OK) {
        check("brutal type", usque_config_congestion_type(cfg) == USQUE_CONGESTION_BRUTAL);
        check("brutal bps", usque_config_congestion_brutal_bps(cfg) == 10000000);
        usque_config_destroy(cfg);
    }
}

static void test_reno_no_extras() {
    std::printf("\n--- Validation: reno with brutal_bps ---\n");
    usque_config_t *cfg = nullptr;
    const char *json = R"({
        "account": {"private_key": "test-key"},
        "inbound": {"type": "tun"},
        "outbound": {"settings": {"congestion": {"type": "reno", "brutal_bps": 500}}}
    })";
    usque_error_t err = try_load(json, &cfg);
    check("reno with brutal_bps rejected", err == USQUE_ERR_PARSE);
}

static void test_noise_invalid_range() {
    std::printf("\n--- Validation: noise min > max ---\n");
    usque_config_t *cfg = nullptr;
    const char *json = R"({
        "account": {"private_key": "test-key"},
        "inbound": {"type": "tun"},
        "outbound": {"settings": {"noise": {"enabled": true, "count": 5, "min_size": 500, "max_size": 100, "delay_min": "10ms", "delay_max": "50ms"}}}
    })";
    usque_error_t err = try_load(json, &cfg);
    check("noise min > max rejected", err == USQUE_ERR_PARSE);
}

int main() {
    test_empty_private_key_rejected();
    test_brutal_requires_bps();
    test_brutal_with_bps_ok();
    test_reno_no_extras();
    test_noise_invalid_range();

    if (failures > 0) {
        std::printf("\n%d tests FAILED\n", failures);
        return 1;
    }
    std::printf("\nAll validate tests passed\n");
    return 0;
}
