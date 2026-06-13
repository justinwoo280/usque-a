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

#include <uv.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

// ---- Platform socket type ----
#ifdef _WIN32
typedef SOCKET socket_t;
#define INVALID_SOCK INVALID_SOCKET
#define close_socket closesocket
#else
typedef int socket_t;
#define INVALID_SOCK (-1)
#define close_socket close
#endif

struct usque_tunnel {
    usque_tunnel_config_t  cfg;
    usque_recv_packet_cb   recv_cb;
    void                  *recv_userdata;
    uv_loop_t             *loop;
    usque::TlsContext     *tls_ctx;
    usque::QuicEngine      engine;

    // TUN device
    usque_tun_t           *tun;
    usque_dns_hijack_t    *dns_hj;

    // libuv handles
    uv_poll_t              udp_poll;
    uv_poll_t              tun_poll;       // Unix only
    uv_timer_t             quic_timer;
    uv_async_t             stop_async;
    uv_async_t             send_async;
    uv_async_t             tun_async;      // Windows only (TUN read thread signal)

    // Windows TUN read thread
#ifdef _WIN32
    uv_thread_t            tun_thread;
    bool                   tun_thread_running;
#endif

    // Send buffer (for thread-safe send_packet)
    uint8_t                send_buf[65536];
    size_t                 send_len;
    bool                   send_pending;

    bool                   running;
    bool                   post_noise_sent;

    // Track active handles for cleanup
    bool                   udp_poll_active;
    bool                   tun_poll_active;
    bool                   timer_active;
};

// ---- Forward declarations ----
static void inject_post_noise(usque_tunnel *t);
static void update_timer(usque_tunnel *t);

// ---- Helper: update QUIC timer ----

static void update_timer(usque_tunnel *t) {
    uint64_t expiry = t->engine.get_expiry();
    uint64_t now = usque_timestamp();
    uint64_t timeout_ms;
    if (expiry <= now) {
        timeout_ms = 1;
    } else {
        timeout_ms = (expiry - now) / 1000000;  // ns → ms
        if (timeout_ms == 0) timeout_ms = 1;
    }
    uv_timer_start(&t->quic_timer, [](uv_timer_t *handle) {
        auto *tun = (usque_tunnel *)handle->data;

        // Inject post-noise once when tunnel becomes ready
        if (tun->engine.tunnel_ready && !tun->post_noise_sent) {
            tun->post_noise_sent = true;
            fprintf(stderr, "[tunnel] connected!\n");
            inject_post_noise(tun);
        }

        tun->engine.on_expiry();
        update_timer(tun);
    }, timeout_ms, 0);
}

// ---- libuv callbacks ----

static void on_udp_read(uv_poll_t *handle, int status, int events) {
    (void)status; (void)events;
    auto *t = (usque_tunnel *)handle->data;

    uint8_t buf[65536];
    ssize_t nread = recv((socket_t)t->engine.fd, (char *)buf, sizeof(buf), 0);
    if (nread <= 0) return;

    t->engine.on_read(buf, (size_t)nread);
    t->engine.on_write();
    update_timer(t);
}

static void on_stop(uv_async_t *handle) {
    auto *t = (usque_tunnel *)handle->data;
    t->running = false;
    uv_stop(t->loop);
}

static void on_send(uv_async_t *handle) {
    auto *t = (usque_tunnel *)handle->data;
    if (t->send_pending && t->send_len > 0) {
        t->engine.send_packet(t->send_buf, t->send_len);
        t->send_pending = false;
        t->engine.on_write();
    }
}

// ---- TUN read (Unix: poll on fd, Windows: thread + async) ----

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
static void on_tun_read(uv_poll_t *handle, int status, int events) {
    (void)status; (void)events;
    auto *t = (usque_tunnel *)handle->data;

    uint8_t buf[65536];
    int nread = usque_tun_read(t->tun, buf, sizeof(buf));
    if (nread <= 0) return;

    if (t->dns_hj) {
        usque_dns_hijack_rewrite_query(t->dns_hj, buf, nread);
    }

    t->engine.send_packet(buf, (size_t)nread);
    t->engine.on_write();
}
#endif

#ifdef _WIN32
static void on_tun_async(uv_async_t *handle) {
    auto *t = (usque_tunnel *)handle->data;

    // Drain all available packets from wintun
    uint8_t buf[65536];
    int nread;
    while ((nread = usque_tun_read(t->tun, buf, sizeof(buf))) > 0) {
        if (t->dns_hj) {
            usque_dns_hijack_rewrite_query(t->dns_hj, buf, nread);
        }
        t->engine.send_packet(buf, (size_t)nread);
    }
    t->engine.on_write();
}

static void tun_read_thread(void *arg) {
    auto *t = (usque_tunnel *)arg;
    void *event = usque_tun_read_event(t->tun);

    while (t->tun_thread_running) {
        DWORD result = WaitForSingleObject((HANDLE)event, 100);
        if (result == WAIT_OBJECT_0 && t->tun_thread_running) {
            uv_async_send(&t->tun_async);
        }
    }
}
#endif

// ---- Pre-noise injection ----

static void inject_pre_noise(socket_t fd, const struct sockaddr *addr, socklen_t addrlen,
                             const usque_noise_config_t *noise) {
    if (!noise->enabled || noise->count <= 0) return;

    for (int i = 0; i < noise->count; i++) {
        int size = noise->min_size;
        if (noise->max_size > noise->min_size) {
            size += rand() % (noise->max_size - noise->min_size);
        }
        std::vector<uint8_t> payload((size_t)size);
        for (int j = 0; j < size; j++) payload[j] = (uint8_t)(rand() & 0xff);
        sendto(fd, (const char *)payload.data(), (int)payload.size(), 0, addr, addrlen);

        if (i < noise->count - 1) {
            int delay = noise->delay_min_ms;
            if (noise->delay_max_ms > noise->delay_min_ms) {
                delay += rand() % (int)(noise->delay_max_ms - noise->delay_min_ms);
            }
            if (delay > 0) {
#ifdef _WIN32
                Sleep((DWORD)delay);
#else
                struct timespec ts = {0, (long)delay * 1000000L};
                nanosleep(&ts, nullptr);
#endif
            }
        }
    }
}

// ---- Post-noise injection ----

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
#ifdef _WIN32
                Sleep((DWORD)delay);
#else
                struct timespec ts = {0, (long)delay * 1000000L};
                nanosleep(&ts, nullptr);
#endif
            }
        }
    }
    t->engine.on_write();
    fprintf(stderr, "[tunnel] post-noise: sent %d packets\n", noise->count);
}

// ---- Supervisor: single connection attempt ----

static int run_connection(usque_tunnel *t) {
    char errbuf[256] = {};

    // 1. Create TUN device
    usque_tun_params_t tun_params = {
        t->cfg.tun.name,
        t->cfg.tun.mtu,
        t->cfg.account.ipv4,
        t->cfg.account.ipv6,
        t->cfg.tun.persist,
        nullptr
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
    socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == INVALID_SOCK) {
        perror("socket");
        usque_tun_destroy(t->tun); t->tun = nullptr;
        return -1;
    }
    t->engine.fd = (int)fd;

    // 4. Bind UDP socket to physical NIC
#if defined(__linux__)
    if (t->cfg.tun.auto_route) {
        char phys_iface[64] = "";
        if (usque_route_detect_physical_iface(phys_iface, sizeof(phys_iface)) == 0) {
            usque_route_bind_to_device((int)fd, phys_iface, errbuf, sizeof(errbuf));
            fprintf(stderr, "[tunnel] UDP bound to %s\n", phys_iface);
        }
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    if (t->cfg.tun.auto_route) {
        char phys_iface[64] = "";
        if (usque_route_detect_physical_iface(phys_iface, sizeof(phys_iface)) == 0) {
            usque_route_bind_to_interface((int)fd, phys_iface, errbuf, sizeof(errbuf));
            fprintf(stderr, "[tunnel] UDP bound to %s\n", phys_iface);
        }
    }
#endif

    // 5. Connect to endpoint
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)t->cfg.outbound.port);
    inet_pton(AF_INET, t->cfg.account.endpoint_v4, &addr.sin_addr);

    inject_pre_noise(fd, (struct sockaddr *)&addr, sizeof(addr),
                     &t->cfg.outbound.pre_noise);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close_socket(fd); t->engine.fd = -1;
        usque_tun_destroy(t->tun); t->tun = nullptr;
        return -1;
    }

    // 6. Setup routes
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

    // 7. Setup QUIC engine
    std::string err;
    auto recv_cb = [t](const uint8_t *pkt, size_t len) {
        uint8_t buf[65536];
        memcpy(buf, pkt, len);
        if (t->dns_hj) {
            usque_dns_hijack_rewrite_response(t->dns_hj, buf, (int)len);
        }
        if (t->tun) {
            usque_tun_write(t->tun, buf, (int)len);
        }
        if (t->recv_cb) t->recv_cb(buf, len, t->recv_userdata);
    };

    if (t->engine.setup(&t->cfg, t->tls_ctx, (int)fd, recv_cb, err) != 0) {
        fprintf(stderr, "[tunnel] engine setup failed: %s\n", err.c_str());
        close_socket(fd); t->engine.fd = -1;
        usque_tun_destroy(t->tun); t->tun = nullptr;
        return -1;
    }

    // 8. Setup libuv watchers
    uv_poll_init_socket(t->loop, &t->udp_poll, fd);
    t->udp_poll.data = t;
    uv_poll_start(&t->udp_poll, UV_READABLE, on_udp_read);
    t->udp_poll_active = true;

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    int tun_fd = usque_tun_fd(t->tun);
    if (tun_fd >= 0) {
        uv_poll_init(t->loop, &t->tun_poll, tun_fd);
        t->tun_poll.data = t;
        uv_poll_start(&t->tun_poll, UV_READABLE, on_tun_read);
        t->tun_poll_active = true;
    }
#endif

#ifdef _WIN32
    // Start TUN read thread
    t->tun_thread_running = true;
    uv_async_init(t->loop, &t->tun_async, on_tun_async);
    t->tun_async.data = t;
    uv_thread_create(&t->tun_thread, tun_read_thread, t);
#endif

    // Start QUIC timer
    t->quic_timer.data = t;
    uv_timer_init(t->loop, &t->quic_timer);
    t->timer_active = true;
    update_timer(t);

    // 9. Kick off handshake
    t->post_noise_sent = false;
    t->engine.on_write();

    // 10. Run event loop
    t->running = true;
    uv_run(t->loop, UV_RUN_DEFAULT);

    // 11. Cleanup watchers
    if (t->udp_poll_active) {
        uv_poll_stop(&t->udp_poll);
        t->udp_poll_active = false;
    }

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
    if (t->tun_poll_active) {
        uv_poll_stop(&t->tun_poll);
        t->tun_poll_active = false;
    }
#endif

#ifdef _WIN32
    t->tun_thread_running = false;
    uv_thread_join(&t->tun_thread);
    uv_close((uv_handle_t *)&t->tun_async, nullptr);
#endif

    if (t->timer_active) {
        uv_timer_stop(&t->quic_timer);
        uv_close((uv_handle_t *)&t->quic_timer, nullptr);
        t->timer_active = false;
    }

    t->engine.cleanup();
    close_socket(fd);
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

    return t->running ? 0 : -1;
}

// ---- Handle close callback for cleanup ----

static void close_cb(uv_handle_t *handle) {
    (void)handle;
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
    memset(t, 0, sizeof(usque_tunnel));
    t->cfg = *cfg;
    t->recv_cb = cb;
    t->recv_userdata = userdata;

    // Create event loop
    t->loop = (uv_loop_t *)malloc(sizeof(uv_loop_t));
    if (uv_loop_init(t->loop) != 0) {
        free(t->loop);
        delete t;
        if (errbuf && errbuf_len) snprintf(errbuf, errbuf_len, "uv_loop_init failed");
        return USQUE_ERR_INTERNAL;
    }

    // Setup async handles
    uv_async_init(t->loop, &t->stop_async, on_stop);
    t->stop_async.data = t;

    uv_async_init(t->loop, &t->send_async, on_send);
    t->send_async.data = t;

    // Create TLS context
    std::string err;
    t->tls_ctx = usque::tls_context_create(
        cfg->account.private_key,
        cfg->account.endpoint_pub_key,
        cfg->outbound.sni_address,
        cfg->outbound.insecure,
        err);

    if (!t->tls_ctx) {
        uv_loop_close(t->loop);
        free(t->loop);
        delete t;
        if (errbuf && errbuf_len) snprintf(errbuf, errbuf_len, "TLS: %s", err.c_str());
        return USQUE_ERR_INTERNAL;
    }

    *out = t;
    return USQUE_OK;
}

extern "C" usque_error_t usque_tunnel_run(usque_tunnel_t *t) {
    if (!t) return USQUE_ERR_INVALID_ARG;

    while (true) {
        fprintf(stderr, "[tunnel] connecting to %s:%d...\n",
                t->cfg.account.endpoint_v4, t->cfg.outbound.port);

        int rv = run_connection(t);
        if (rv == 0) break;

        fprintf(stderr, "[tunnel] disconnected, reconnecting in %lldms...\n",
                (long long)t->cfg.outbound.reconnect_delay_ms);

#ifdef _WIN32
        Sleep((DWORD)t->cfg.outbound.reconnect_delay_ms);
#else
        struct timespec ts;
        ts.tv_sec = t->cfg.outbound.reconnect_delay_ms / 1000;
        ts.tv_nsec = (t->cfg.outbound.reconnect_delay_ms % 1000) * 1000000L;
        nanosleep(&ts, nullptr);
#endif
    }
    return USQUE_OK;
}

extern "C" void usque_tunnel_stop(usque_tunnel_t *t) {
    if (!t) return;
    t->running = false;
    uv_async_send(&t->stop_async);
}

extern "C" usque_error_t usque_tunnel_send_packet(usque_tunnel_t *t,
                                                   const uint8_t *pkt, size_t len) {
    if (!t || !pkt) return USQUE_ERR_INVALID_ARG;
    if (len > sizeof(t->send_buf)) return USQUE_ERR_INVALID_ARG;

    memcpy(t->send_buf, pkt, len);
    t->send_len = len;
    t->send_pending = true;
    uv_async_send(&t->send_async);
    return USQUE_OK;
}

extern "C" void usque_tunnel_destroy(usque_tunnel_t *t) {
    if (!t) return;

    // Close async handles before closing loop
    if (uv_is_active((uv_handle_t *)&t->stop_async)) {
        uv_close((uv_handle_t *)&t->stop_async, close_cb);
    }
    if (uv_is_active((uv_handle_t *)&t->send_async)) {
        uv_close((uv_handle_t *)&t->send_async, close_cb);
    }

    // Run loop to process close callbacks
    uv_run(t->loop, UV_RUN_DEFAULT);
    uv_loop_close(t->loop);
    free(t->loop);

    delete t->tls_ctx;
    delete t;
}
