#include "usque/usque.h"
#include "api/register.h"

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/filereadstream.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <string>

static usque_tunnel_t *g_tunnel = nullptr;

static void signal_handler(int sig) {
    (void)sig;
    if (g_tunnel) usque_tunnel_stop(g_tunnel);
}

static void print_usage(const char *prog) {
    fprintf(stderr, "usque-a %s — Cloudflare WARP MASQUE client\n\n", usque_version_string());
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s register [-c config.json] [--jwt TOKEN] [--name DEVICE]\n", prog);
    fprintf(stderr, "  %s run [-c config.json]\n", prog);
    fprintf(stderr, "  %s check [-c config.json]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c FILE   Config file path (default: config.json)\n");
    fprintf(stderr, "  --jwt     ZeroTrust team JWT token\n");
    fprintf(stderr, "  --name    Device name for registration\n");
}

static std::string get_arg(int argc, char **argv, const char *flag, const char *def = "") {
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], flag) == 0) return argv[i + 1];
    }
    return def;
}

static bool has_flag(int argc, char **argv, const char *flag) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], flag) == 0) return true;
    }
    return false;
}

static int cmd_register(int argc, char **argv) {
    std::string config_path = get_arg(argc, argv, "-c", "config.json");
    std::string jwt = get_arg(argc, argv, "--jwt");
    std::string name = get_arg(argc, argv, "--name");

    printf("Registering new device...\n");
    auto result = usque::register_device(jwt, name);
    if (!result.success) {
        fprintf(stderr, "Registration failed: %s\n", result.error.c_str());
        return 1;
    }

    printf("Device ID: %s\n", result.device_id.c_str());
    printf("IPv4: %s\n", result.ipv4.c_str());
    printf("IPv6: %s\n", result.ipv6.c_str());
    printf("Endpoint: %s / %s\n", result.endpoint_v4.c_str(), result.endpoint_v6.c_str());

    // Build and save config JSON
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    // Account
    rapidjson::Value account(rapidjson::kObjectType);
    account.AddMember("private_key",     rapidjson::Value(result.private_key_b64.c_str(), alloc), alloc);
    account.AddMember("endpoint_v4",     rapidjson::Value(result.endpoint_v4.c_str(), alloc), alloc);
    account.AddMember("endpoint_v6",     rapidjson::Value(result.endpoint_v6.c_str(), alloc), alloc);
    account.AddMember("endpoint_h2_v4",  "162.159.198.2", alloc);
    account.AddMember("endpoint_h2_v6",  "", alloc);
    account.AddMember("endpoint_pub_key", rapidjson::Value(result.endpoint_pub_key.c_str(), alloc), alloc);
    account.AddMember("license",         rapidjson::Value(result.license.c_str(), alloc), alloc);
    account.AddMember("id",              rapidjson::Value(result.device_id.c_str(), alloc), alloc);
    account.AddMember("access_token",    rapidjson::Value(result.access_token.c_str(), alloc), alloc);
    account.AddMember("ipv4",            rapidjson::Value(result.ipv4.c_str(), alloc), alloc);
    account.AddMember("ipv6",            rapidjson::Value(result.ipv6.c_str(), alloc), alloc);
    doc.AddMember("account", account, alloc);

    // Inbound
    rapidjson::Value inbound(rapidjson::kObjectType);
    inbound.AddMember("type", "tun", alloc);
    rapidjson::Value tun_settings(rapidjson::kObjectType);
    tun_settings.AddMember("mtu", 1280, alloc);
    tun_settings.AddMember("ipv4", true, alloc);
    tun_settings.AddMember("ipv6", true, alloc);
    tun_settings.AddMember("auto_route", true, alloc);
    rapidjson::Value dns(rapidjson::kArrayType);
    dns.PushBack("1.1.1.1", alloc);
    dns.PushBack("2606:4700:4700::1111", alloc);
    tun_settings.AddMember("dns", dns, alloc);
    inbound.AddMember("settings", tun_settings, alloc);
    doc.AddMember("inbound", inbound, alloc);

    // Outbound
    rapidjson::Value outbound(rapidjson::kObjectType);
    outbound.AddMember("tag", "warp", alloc);
    rapidjson::Value ob_settings(rapidjson::kObjectType);
    ob_settings.AddMember("port", 443, alloc);
    ob_settings.AddMember("keepalive_period", "30s", alloc);
    ob_settings.AddMember("reconnect_delay", "1s", alloc);
    ob_settings.AddMember("sni_address", "consumer-masque.cloudflareclient.com", alloc);
    rapidjson::Value congestion(rapidjson::kObjectType);
    congestion.AddMember("type", "bbr", alloc);
    congestion.AddMember("bbr_profile", "standard", alloc);
    congestion.AddMember("brutal_bps", (uint64_t)0, alloc);
    ob_settings.AddMember("congestion", congestion, alloc);
    rapidjson::Value noise(rapidjson::kObjectType);
    noise.AddMember("enabled", true, alloc);
    noise.AddMember("count", 5, alloc);
    noise.AddMember("min_size", 100, alloc);
    noise.AddMember("max_size", 400, alloc);
    noise.AddMember("delay_min", "10ms", alloc);
    noise.AddMember("delay_max", "50ms", alloc);
    ob_settings.AddMember("noise", noise, alloc);
    rapidjson::Value pre_noise(rapidjson::kObjectType);
    pre_noise.AddMember("enabled", true, alloc);
    pre_noise.AddMember("count", 3, alloc);
    pre_noise.AddMember("min_size", 64, alloc);
    pre_noise.AddMember("max_size", 128, alloc);
    pre_noise.AddMember("delay_min", "5ms", alloc);
    pre_noise.AddMember("delay_max", "15ms", alloc);
    ob_settings.AddMember("pre_noise", pre_noise, alloc);
    outbound.AddMember("settings", ob_settings, alloc);
    doc.AddMember("outbound", outbound, alloc);

    // Write to file
    rapidjson::StringBuffer buf;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buf);
    doc.Accept(writer);

    FILE *fp = fopen(config_path.c_str(), "w");
    if (!fp) {
        fprintf(stderr, "Cannot write %s\n", config_path.c_str());
        return 1;
    }
    fwrite(buf.GetString(), 1, buf.GetSize(), fp);
    fclose(fp);

    printf("Config saved to %s\n", config_path.c_str());
    return 0;
}

static int cmd_run(int argc, char **argv) {
    std::string config_path = get_arg(argc, argv, "-c", "config.json");

    // Load config
    char errbuf[512] = {};
    usque_config_t *cfg = nullptr;
    usque_error_t err = usque_config_load_file(config_path.c_str(), &cfg, errbuf, sizeof(errbuf));
    if (err != USQUE_OK) {
        fprintf(stderr, "Config error: %s (%s)\n", usque_error_name(err), errbuf);
        return 1;
    }

    usque_tunnel_config_t tc;
    err = usque_config_build_tunnel_config(cfg, &tc, errbuf, sizeof(errbuf));
    if (err != USQUE_OK) {
        fprintf(stderr, "Build tunnel config: %s\n", errbuf);
        usque_config_destroy(cfg);
        return 1;
    }
    usque_config_destroy(cfg);

    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create and run tunnel
    usque_tunnel_t *tunnel = nullptr;
    err = usque_tunnel_new(&tc, nullptr, nullptr, &tunnel, errbuf, sizeof(errbuf));
    if (err != USQUE_OK) {
        fprintf(stderr, "Tunnel create: %s (%s)\n", usque_error_name(err), errbuf);
        return 1;
    }

    g_tunnel = tunnel;
    printf("Starting tunnel...\n");
    usque_tunnel_run(tunnel);
    printf("Tunnel stopped.\n");

    usque_tunnel_destroy(tunnel);
    g_tunnel = nullptr;
    return 0;
}

static int cmd_check(int argc, char **argv) {
    std::string config_path = get_arg(argc, argv, "-c", "config.json");

    char errbuf[512] = {};
    usque_config_t *cfg = nullptr;
    usque_error_t err = usque_config_load_file(config_path.c_str(), &cfg, errbuf, sizeof(errbuf));
    if (err != USQUE_OK) {
        fprintf(stderr, "Config error: %s (%s)\n", usque_error_name(err), errbuf);
        return 1;
    }

    printf("Config OK: %s\n", config_path.c_str());
    printf("  Account ID: %s\n", usque_config_account_id(cfg));
    printf("  IPv4: %s\n", usque_config_account_ipv4(cfg));
    printf("  Endpoint: %s:%d\n",
           usque_config_account_endpoint_v4(cfg),
           usque_config_outbound_port(cfg));
    printf("  SNI: %s\n", usque_config_outbound_sni_address(cfg));
    printf("  MTU: %d\n", usque_config_tun_mtu(cfg));

    usque_config_destroy(cfg);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "register") == 0) {
        return cmd_register(argc, argv);
    } else if (strcmp(cmd, "run") == 0) {
        return cmd_run(argc, argv);
    } else if (strcmp(cmd, "check") == 0) {
        return cmd_check(argc, argv);
    } else if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
