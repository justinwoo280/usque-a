#include "usque/tunnel.h"
#include "transport/tls_setup.h"
#include "transport/quic_engine.h"
#include "transport/timestamp.h"
#include "connectip/connect_ip.h"
#include "usque/tun.h"
#include "usque/dns_hijack.h"

#ifdef __linux__
#include "usque/route_linux.h"
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
#include "usque/route_bsd.h"
#endif

#ifdef _WIN32
#include "usque/route_windows.h"
#endif

#include <ev.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

struct usque_tunnel {
    usque_tunnel_config_t  cfg;
    usque_recv_packet_cb   recv_cb;
    void                  *recv_userdata;
    struct ev_loop        *loop;
    usque::TlsContext     *tls_ctx;
    usque::QuicEngine      engine;

    // TUN device
    usque_tun_t           *tun;
    usque_dns_hijack_t    *dns_hj;

    // libev watchers
    ev_io                  udp_read;
    ev_io                  tun_read;
    ev_timer               quic_timer;
    ev_async               stop_async;
    ev_async               send_async;

    // Send buffer (for thread-safe send_packet)
    uint8_t                send_buf[65536];
    size_t                 send_len;
    bool                   send_pending;

    bool                   running;
    bool                   post_noise_sent;
};

// ---- Forward declarations ----
static void inject_post_noise(usque_tunnel *t);

// ---- libev callbacks ----

static void on_udp_read(EV_P_ ev_io *w, int revents) {
    (void)revents;
    auto *t = (usque_tunnel *)w->data;

    uint8_t buf[65536];
    ssize_t nread = recv(w->fd, buf, sizeof(buf), 0);
    if (nread <= 0) return;

    t->engine.on_read(buf, (size_t)nread);
    t->engine.on_write();

    // Update timer
    uint64_t expiry = t->engine.get_expiry();
    uint64_t now = usque_timestamp();
    ev_tstamp timeout;
    if (expiry <= now) {
        timeout = 0.001;
    } else {
        timeout = (ev_tstamp)(expiry - now) / 1e9;
    }
    ev_timer_set(&t->quic_timer, timeout, 0.0);
    ev_timer_again(EV_A_ &t->quic_timer);
}

static void on_timer(EV_P_ ev_timer *w, int revents) {
    (void)EV_A; (void)revents;
    auto *t = (usque_tunnel *)w->data;

    // Inject post-noise once when tunnel becomes ready
    if (t->engine.tunnel_ready && !t->post_noise_sent) {
        t->post_noise_sent = true;
        fprintf(stderr, "[tunnel] connected!\n");
        inject_post_noise(t);
    }

    t->engine.on_expiry();
}

static void on_stop(EV_P_ ev_async *w, int revents) {
    (void)revents;
    auto *t = (usque_tunnel *)w->data;
    ev_break(EV_A_ EVBREAK_ALL);
    t->running = false;
}

static void on_send(EV_P_ ev_async *w, int revents) {
    (void)EV_A; (void)revents;
    auto *t = (usque_tunnel *)w->data;
    if (t->send_pending && t->send_len > 0) {
        t->engine.send_packet(t->send_buf, t->send_len);
        t->send_pending = false;
        t->engine.on_write();
    }
}

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
static void on_tun_read(EV_P_ ev_io *w, int revents) {
    (void)revents;
    auto *t = (usque_tunnel *)w->data;

    uint8_t buf[65536];
    int nread = usque_tun_read(t->tun, buf, sizeof(buf));
    if (nread <= 0) return;

    // DNS hijack: rewrite outgoing DNS queries
    if (t->dns_hj) {
        usque_dns_hijack_rewrite_query(t->dns_hj, buf, nread);
    }

    // Send into tunnel
    t->engine.send_packet(buf, (size_t)nread);
    t->engine.on_write();
}
#endif

// ---- Pre-noise injection ----

static void inject_pre_noise(int fd, const struct sockaddr *addr, socklen_t addrlen,
                             const usque_noise_config_t *noise) {
    if (!noise->enabled || noise->count <= 0) return;

    for (int i = 0; i < noise->count; i++) {
        int size = noise->min_size;
        if (noise->max_size > noise->min_size) {
            size += rand() % (noise->max_size - noise->min_size);
        }
        std::vector<uint8_t> payload((size_t)size);
        for (int j = 0; j < size; j++) payload[j] = (uint8_t)(rand() & 0xff);
        sendto(fd, payload.data(), payload.size(), 0, addr, addrlen);

        if (i < noise->count - 1) {
            int delay = noise->delay_min_ms;
            if (noise->delay_max_ms > noise->delay_min_ms) {
                delay += rand() % (int)(noise->delay_max_ms - noise->delay_min_ms);
            }
            if (delay > 0) {
                struct timespec ts = {0, (long)delay * 1000000L};
                nanosleep(&ts, nullptr);
            }
        }
    }
}

// ---- Post-noise injection (through the tunnel after CONNECT succeeds) ----

static void inject_post_noise(usque_tunnel *t) {
    const usque_noise_config_t *noise = &t->cfg.outbound.noise;
    if (!noise->enabled || noise->count <= 0) return;

    for (int i = 0; i < noise->count; i++) {
        int payload_size = noise->min_size;
        if (noise->max_size > noise->min_size) {
            payload_size += rand() % (noise->max_size - noise->min_size);
        }

        uint8_t pkt[1500];
        size_t pkt_len = 0;
        int rc = cip_compose_noise_packet(pkt, sizeof(pkt), &pkt_len, (size_t)payload_size);
        if (rc != CIP_OK) continue;

        t->engine.send_packet(pkt, pkt_len);

        if (i < noise->count - 1) {
            int delay = noise->delay_min_ms;
            if (noise->delay_max_ms > noise->delay_min_ms) {
                delay += rand() % (int)(noise->delay_max_ms - noise->delay_min_ms);
            }
            if (delay > 0) {
                struct timespec ts = {0, (long)delay * 1000000L};
                nanosleep(&ts, nullptr);
            }
        }
    }
    t->engine.on_write();
    fprintf(stderr, "[tunnel] post-noise: sent %d packets\n", noise->count);
}

// ---- Supervisor: single connection attempt ----

static int run_connection(usque_tunnel *t) {
    // 1. Create TUN device
    char errbuf[256] = {};
    usque_tun_params_t tun_params = {
        t->cfg.tun.name,
        t->cfg.tun.mtu,
        t->cfg.account.ipv4,
        t->cfg.account.ipv6,
        t->cfg.tun.persist,
        nullptr  /* wintun_dll: not used on Linux */
    };
    t->tun = usque_tun_create(&tun_params, errbuf, sizeof(errbuf));
    if (!t->tun) {
        fprintf(stderr, "[tunnel] TUN create failed: %s\n", errbuf);
        return -1;
    }
    fprintf(stderr, "[tunnel] TUN device: %s\n", usque_tun_name(t->tun));

    // 2. Create DNS hijack context
    const char *hj_v4 = (t->cfg.tun.dns_count > 0) ? t->cfg.tun.dns[0] : "";
    const char *hj_v6 = (t->cfg.tun.dns_count > 1) ? t->cfg.tun.dns[1] : "";
    t->dns_hj = usque_dns_hijack_create(hj_v4, hj_v6);

    // 3. Create UDP socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        usque_tun_destroy(t->tun); t->tun = nullptr;
        return -1;
    }
    t->engine.fd = fd;

    // 4. Bind UDP socket to physical NIC (prevents routing loop)
#if defined(__linux__)
    if (t->cfg.tun.auto_route) {
        char phys_iface[64] = "";
        if (usque_route_detect_physical_iface(phys_iface, sizeof(phys_iface)) == 0) {
            usque_route_bind_to_device(fd, phys_iface, errbuf, sizeof(errbuf));
            fprintf(stderr, "[tunnel] UDP bound to %s\n", phys_iface);
        }
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    if (t->cfg.tun.auto_route) {
        char phys_iface[64] = "";
        if (usque_route_detect_physical_iface(phys_iface, sizeof(phys_iface)) == 0) {
            usque_route_bind_to_interface(fd, phys_iface, errbuf, sizeof(errbuf));
            fprintf(stderr, "[tunnel] UDP bound to %s\n", phys_iface);
        }
    }
#endif

    // 5. Connect to endpoint
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)t->cfg.outbound.port);
    inet_pton(AF_INET, t->cfg.account.endpoint_v4, &addr.sin_addr);

    // Pre-noise
    inject_pre_noise(fd, (struct sockaddr *)&addr, sizeof(addr),
                     &t->cfg.outbound.pre_noise);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd); t->engine.fd = -1;
        usque_tun_destroy(t->tun); t->tun = nullptr;
        return -1;
    }

    // 6. Setup routes (after connect, so endpoint bypass works)
#if defined(__linux__)
    if (t->cfg.tun.auto_route) {
        const char *dns_arr[USQUE_MAX_DNS_COUNT];
        for (int i = 0; i < t->cfg.tun.dns_count && i < USQUE_MAX_DNS_COUNT; i++) {
            dns_arr[i] = t->cfg.tun.dns[i];
        }
        if (usque_route_setup(usque_tun_name(t->tun),
                              t->cfg.account.endpoint_v4,
                              dns_arr, t->cfg.tun.dns_count,
                              errbuf, sizeof(errbuf)) < 0) {
            fprintf(stderr, "[tunnel] route setup: %s\n", errbuf);
        }
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    if (t->cfg.tun.auto_route) {
        const char *dns_arr[USQUE_MAX_DNS_COUNT];
        for (int i = 0; i < t->cfg.tun.dns_count && i < USQUE_MAX_DNS_COUNT; i++) {
            dns_arr[i] = t->cfg.tun.dns[i];
        }
        if (usque_route_setup_bsd(usque_tun_name(t->tun),
                                  t->cfg.account.endpoint_v4,
                                  dns_arr, t->cfg.tun.dns_count,
                                  errbuf, sizeof(errbuf)) < 0) {
            fprintf(stderr, "[tunnel] route setup: %s\n", errbuf);
        }
    }
#endif

    // 7. Setup QUIC engine with TUN write callback
    std::string err;
    auto recv_cb = [t](const uint8_t *pkt, size_t len) {
        uint8_t buf[65536];
        memcpy(buf, pkt, len);
        // DNS hijack: rewrite response
        if (t->dns_hj) {
            usque_dns_hijack_rewrite_response(t->dns_hj, buf, (int)len);
        }
        // Write to TUN
        if (t->tun) {
            usque_tun_write(t->tun, buf, (int)len);
        }
        // Also call user callback
        if (t->recv_cb) t->recv_cb(buf, len, t->recv_userdata);
    };

    if (t->engine.setup(&t->cfg, t->tls_ctx, fd, recv_cb, err) != 0) {
        fprintf(stderr, "[tunnel] engine setup failed: %s\n", err.c_str());
        close(fd); t->engine.fd = -1;
        usque_tun_destroy(t->tun); t->tun = nullptr;
        return -1;
    }

    // 8. Setup libev watchers
    ev_io_init(&t->udp_read, on_udp_read, fd, EV_READ);
    t->udp_read.data = t;
    ev_io_start(t->loop, &t->udp_read);

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    ev_io_init(&t->tun_read, on_tun_read, usque_tun_fd(t->tun), EV_READ);
    t->tun_read.data = t;
    ev_io_start(t->loop, &t->tun_read);
#endif

    ev_timer_init(&t->quic_timer, on_timer, 0.001, 0.0);
    t->quic_timer.data = t;
    ev_timer_again(t->loop, &t->quic_timer);

    // 9. Kick off handshake
    t->post_noise_sent = false;
    t->engine.on_write();

    // 10. Run event loop
    t->running = true;
    ev_run(t->loop, 0);

    // 11. Cleanup
    ev_io_stop(t->loop, &t->udp_read);
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    ev_io_stop(t->loop, &t->tun_read);
#endif
    ev_timer_stop(t->loop, &t->quic_timer);
    t->engine.cleanup();
    close(fd);
    t->engine.fd = -1;

#if defined(__linux__)
    if (t->cfg.tun.auto_route) {
        usque_route_cleanup(usque_tun_name(t->tun), errbuf, sizeof(errbuf));
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    if (t->cfg.tun.auto_route) {
        usque_route_cleanup_bsd(usque_tun_name(t->tun), errbuf, sizeof(errbuf));
    }
#endif

    usque_dns_hijack_destroy(t->dns_hj); t->dns_hj = nullptr;
    usque_tun_destroy(t->tun); t->tun = nullptr;

    return t->running ? 0 : -1;  // 0 = stop requested, -1 = error
}

// ---- Public C API ----

extern "C" usque_error_t usque_tunnel_new(const usque_tunnel_config_t *cfg,
                                           usque_recv_packet_cb cb,
                                           void *userdata,
                                           usque_tunnel_t **out,
                                           char *errbuf, size_t errbuf_len) {
    if (!cfg || !out) {
        if (errbuf && errbuf_len) snprintf(errbuf, errbuf_len, "null argument");
        return USQUE_ERR_INVALID_ARG;
    }

    auto *t = new usque_tunnel();
    t->cfg = *cfg;
    t->recv_cb = cb;
    t->recv_userdata = userdata;
    t->running = false;
    t->send_pending = false;
    t->send_len = 0;
    t->tun = nullptr;
    t->dns_hj = nullptr;
    t->post_noise_sent = false;

    // Create event loop
    t->loop = ev_loop_new(EVFLAG_AUTO);
    if (!t->loop) {
        delete t;
        if (errbuf && errbuf_len) snprintf(errbuf, errbuf_len, "ev_loop_new failed");
        return USQUE_ERR_INTERNAL;
    }

    // Setup async watchers
    ev_async_init(&t->stop_async, on_stop);
    t->stop_async.data = t;
    ev_async_start(t->loop, &t->stop_async);

    ev_async_init(&t->send_async, on_send);
    t->send_async.data = t;
    ev_async_start(t->loop, &t->send_async);

    // Create TLS context
    std::string err;
    t->tls_ctx = usque::tls_context_create(
        cfg->account.private_key,
        cfg->account.endpoint_pub_key,
        cfg->outbound.sni_address,
        cfg->outbound.insecure,
        err);

    if (!t->tls_ctx) {
        ev_async_stop(t->loop, &t->stop_async);
        ev_async_stop(t->loop, &t->send_async);
        ev_loop_destroy(t->loop);
        delete t;
        if (errbuf && errbuf_len) snprintf(errbuf, errbuf_len, "TLS: %s", err.c_str());
        return USQUE_ERR_INTERNAL;
    }

    *out = t;
    return USQUE_OK;
}

extern "C" usque_error_t usque_tunnel_run(usque_tunnel_t *t) {
    if (!t) return USQUE_ERR_INVALID_ARG;

    while (t->running || !t->recv_cb) {
        fprintf(stderr, "[tunnel] connecting to %s:%d...\n",
                t->cfg.account.endpoint_v4, t->cfg.outbound.port);

        int rv = run_connection(t);
        if (rv == 0) break;  // stop requested

        fprintf(stderr, "[tunnel] disconnected, reconnecting in %lldms...\n",
                (long long)t->cfg.outbound.reconnect_delay_ms);

        struct timespec ts;
        ts.tv_sec = t->cfg.outbound.reconnect_delay_ms / 1000;
        ts.tv_nsec = (t->cfg.outbound.reconnect_delay_ms % 1000) * 1000000L;
        nanosleep(&ts, nullptr);

        // Re-enable async watchers after ev_run returned
        if (!ev_is_active(&t->stop_async)) {
            ev_async_start(t->loop, &t->stop_async);
        }
        if (!ev_is_active(&t->send_async)) {
            ev_async_start(t->loop, &t->send_async);
        }
    }
    return USQUE_OK;
}

extern "C" void usque_tunnel_stop(usque_tunnel_t *t) {
    if (!t) return;
    t->running = false;
    ev_async_send(t->loop, &t->stop_async);
}

extern "C" usque_error_t usque_tunnel_send_packet(usque_tunnel_t *t,
                                                   const uint8_t *pkt, size_t len) {
    if (!t || !pkt) return USQUE_ERR_INVALID_ARG;
    if (len > sizeof(t->send_buf)) return USQUE_ERR_INVALID_ARG;

    memcpy(t->send_buf, pkt, len);
    t->send_len = len;
    t->send_pending = true;
    ev_async_send(t->loop, &t->send_async);
    return USQUE_OK;
}

extern "C" void usque_tunnel_destroy(usque_tunnel_t *t) {
    if (!t) return;
    if (t->loop) {
        ev_async_stop(t->loop, &t->stop_async);
        ev_async_stop(t->loop, &t->send_async);
        ev_loop_destroy(t->loop);
    }
    delete t->tls_ctx;
    delete t;
}
