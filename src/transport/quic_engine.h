#pragma once

#include "tls_setup.h"
#include "http3_connect.h"
#include "timestamp.h"
#include "../connectip/connect_ip.h"
#include "../../include/usque/types.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <functional>
#include <string>

namespace usque {

// Callback invoked when an IP packet is received from the tunnel
using RecvPacketCb = std::function<void(const uint8_t *pkt, size_t len)>;

struct QuicEngine {
    // QUIC state
    ngtcp2_conn              *conn = nullptr;
    SSL                      *ssl  = nullptr;
    TlsContext               *tls_ctx = nullptr;
    ngtcp2_crypto_conn_ref    conn_ref{};

    // HTTP/3
    Http3Connect              h3{};

    // Network
    int                       fd = -1;
    ngtcp2_path               path{};
    ngtcp2_addr               local_addr{};
    ngtcp2_addr               remote_addr{};
    struct sockaddr_storage   local_sa{};
    struct sockaddr_storage   remote_sa{};

    // State
    bool                      handshake_done = false;
    bool                      tunnel_ready   = false;

    // Config (borrowed, not owned)
    const usque_tunnel_config_t *cfg = nullptr;

    // Callbacks
    RecvPacketCb              recv_packet_cb;

    // Datagram ID counter
    uint64_t                  dgram_id = 0;

    // Setup: create ngtcp2_conn + SSL, wire callbacks, start handshake
    int setup(const usque_tunnel_config_t *config,
              TlsContext *tls, int udp_fd,
              RecvPacketCb cb, std::string &err);

    // Process incoming UDP packet
    int on_read(const uint8_t *data, size_t datalen);

    // Write pending QUIC packets (handshake + stream + datagram)
    int on_write();

    // Handle timer expiry
    int on_expiry();

    // Send an IP packet through the tunnel (compose + DATAGRAM)
    int send_packet(const uint8_t *ip_pkt, size_t pkt_len);

    // Get next timer deadline (nanoseconds, absolute)
    uint64_t get_expiry();

    // Cleanup
    void cleanup();

    ~QuicEngine();
};

} // namespace usque
