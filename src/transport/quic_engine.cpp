#include "quic_engine.h"

#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/rand.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdio>

namespace usque {

// ---- ngtcp2 callback implementations ----

static void cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx) {
    (void)ctx;
    RAND_bytes(dest, destlen);
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
    (void)conn; (void)user_data;
    RAND_bytes(cid->data, cidlen);
    cid->datalen = cidlen;
    RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    auto *engine = (QuicEngine *)user_data;
    engine->handshake_done = true;
    fprintf(stderr, "[quic] handshake completed\n");
    return 0;
}

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data) {
    (void)conn; (void)flags; (void)offset; (void)stream_user_data;
    auto *engine = (QuicEngine *)user_data;
    uint64_t ts = usque_timestamp();

    int rv = http3_recv_stream_data(&engine->h3, stream_id, data, datalen, ts);
    if (rv != 0) return NGTCP2_ERR_CALLBACK_FAILURE;

    // Extend flow control
    ngtcp2_conn_extend_max_stream_offset(engine->conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(engine->conn, datalen);
    return 0;
}

static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                       uint64_t offset, uint64_t datalen,
                                       void *user_data, void *stream_user_data) {
    (void)conn; (void)offset; (void)stream_user_data;
    auto *engine = (QuicEngine *)user_data;
    return http3_acked_stream_data(&engine->h3, stream_id, datalen);
}

static int cb_stream_close(ngtcp2_conn *conn, uint32_t flags,
                           int64_t stream_id, uint64_t app_error_code,
                           void *user_data, void *stream_user_data) {
    (void)conn; (void)flags; (void)stream_user_data;
    auto *engine = (QuicEngine *)user_data;
    return http3_stream_close(&engine->h3, stream_id, app_error_code);
}

static int cb_recv_datagram(ngtcp2_conn *conn, uint32_t flags,
                            const uint8_t *data, size_t datalen,
                            void *user_data) {
    (void)conn; (void)flags;
    auto *engine = (QuicEngine *)user_data;

    const uint8_t *ip_pkt;
    size_t ip_len;
    int rc = cip_parse_datagram(data, datalen, &ip_pkt, &ip_len);
    if (rc == CIP_OK && engine->recv_packet_cb) {
        engine->recv_packet_cb(ip_pkt, ip_len);
    }
    return 0;
}

static int cb_extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                            uint64_t max_streams,
                                            void *user_data) {
    (void)max_streams;
    auto *engine = (QuicEngine *)user_data;

    // Setup HTTP/3 and submit CONNECT when bidi streams become available
    if (engine->h3.httpconn == nullptr) {
        std::string err;
        if (http3_setup(engine, &engine->h3, err) != 0) {
            fprintf(stderr, "[quic] http3 setup failed: %s\n", err.c_str());
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (http3_submit_connect(&engine->h3, engine->conn, err) != 0) {
            fprintf(stderr, "[quic] submit connect failed: %s\n", err.c_str());
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }
    return 0;
}

// ---- conn_ref bridge ----

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
    auto *engine = (QuicEngine *)ref->user_data;
    return engine->conn;
}

// ---- QuicEngine implementation ----

int QuicEngine::setup(const usque_tunnel_config_t *config,
                      TlsContext *tls, int udp_fd,
                      RecvPacketCb cb, std::string &err) {
    cfg = config;
    tls_ctx = tls;
    fd = udp_fd;
    recv_packet_cb = std::move(cb);

    // Setup callbacks
    ngtcp2_callbacks callbacks{};
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.rand = cb_rand;
    callbacks.get_new_connection_id = cb_get_new_connection_id;
    callbacks.handshake_completed = cb_handshake_completed;
    callbacks.recv_stream_data = cb_recv_stream_data;
    callbacks.acked_stream_data_offset = cb_acked_stream_data_offset;
    callbacks.stream_close = cb_stream_close;
    callbacks.recv_datagram = cb_recv_datagram;
    callbacks.extend_max_local_streams_bidi = cb_extend_max_local_streams_bidi;

    // Settings
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = usque_timestamp();
    if (config->outbound.initial_packet_size > 0) {
        settings.max_tx_udp_payload_size = config->outbound.initial_packet_size;
    }

    // Transport params
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 3;   // HTTP/3: control + qpack_enc + qpack_dec
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.max_datagram_frame_size = 65535;  // enable DATAGRAM

    // Generate random DCID and SCID
    ngtcp2_cid dcid, scid;
    uint8_t dcid_buf[16], scid_buf[16];
    RAND_bytes(dcid_buf, sizeof(dcid_buf));
    RAND_bytes(scid_buf, sizeof(scid_buf));
    ngtcp2_cid_init(&dcid, dcid_buf, sizeof(dcid_buf));
    ngtcp2_cid_init(&scid, scid_buf, sizeof(scid_buf));

    // Setup path
    memset(&local_sa, 0, sizeof(local_sa));
    memset(&remote_sa, 0, sizeof(remote_sa));

    struct sockaddr_in *r4 = (struct sockaddr_in *)&remote_sa;
    r4->sin_family = AF_INET;
    r4->sin_port = htons((uint16_t)config->outbound.port);
    inet_pton(AF_INET, config->account.endpoint_v4, &r4->sin_addr);

    ngtcp2_addr_init(&remote_addr, (struct sockaddr *)&remote_sa, sizeof(struct sockaddr_in));
    ngtcp2_addr_init(&local_addr, (struct sockaddr *)&local_sa, sizeof(struct sockaddr_in));
    path.local = local_addr;
    path.remote = remote_addr;
    path.user_data = nullptr;

    // Create connection
    int rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &path,
                                    NGTCP2_PROTO_VER_V1,
                                    &callbacks, &settings, &params,
                                    nullptr, this);
    if (rv != 0) {
        err = std::string("ngtcp2_conn_client_new: ") + ngtcp2_strerror(rv);
        return -1;
    }

    if (config->outbound.keepalive_period_ms > 0) {
        ngtcp2_conn_set_keep_alive_timeout(
            conn, (uint64_t)config->outbound.keepalive_period_ms * 1000000ULL);
    }

    // Create SSL and wire up
    ssl = tls_create_session(tls_ctx, config->outbound.sni_address);
    if (!ssl) {
        err = "tls_create_session failed";
        return -1;
    }

    // conn_ref bridge
    conn_ref.get_conn = get_conn;
    conn_ref.user_data = this;
    SSL_set_app_data(ssl, &conn_ref);

    // Give ngtcp2 the SSL handle
    ngtcp2_conn_set_tls_native_handle(conn, ssl);

    return 0;
}

int QuicEngine::on_read(const uint8_t *data, size_t datalen) {
    ngtcp2_path path_tmp;
    ngtcp2_pkt_info pi{};
    uint64_t ts = usque_timestamp();

    path_tmp.local = local_addr;
    path_tmp.remote = remote_addr;
    path_tmp.user_data = nullptr;

    int rv = ngtcp2_conn_read_pkt(conn, &path_tmp, &pi, data, datalen, ts);
    if (rv != 0) {
        fprintf(stderr, "[quic] read_pkt error: %s\n", ngtcp2_strerror(rv));
        return -1;
    }
    return 0;
}

int QuicEngine::on_write() {
    uint8_t buf[65536];
    ngtcp2_ssize nwrite;
    uint64_t ts = usque_timestamp();
    ngtcp2_path path_tmp;
    ngtcp2_pkt_info pi{};
    path_tmp.local = local_addr;
    path_tmp.remote = remote_addr;
    path_tmp.user_data = nullptr;

    // Write HTTP/3 stream data
    while (true) {
        int64_t stream_id = -1;
        int fin = 0;
        nghttp3_vec vec[16];

        nghttp3_ssize sveccnt = http3_writev(&h3, &stream_id, &fin, vec, 16);
        if (stream_id == -1) break;
        if (sveccnt < 0) {
            fprintf(stderr, "[quic] http3_writev error: %s\n", nghttp3_strerror((int)sveccnt));
            return -1;
        }

        size_t veccnt = (size_t)sveccnt;
        ngtcp2_ssize ndatalen;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

        nwrite = ngtcp2_conn_writev_stream(
            conn, &path_tmp, &pi, buf, sizeof(buf),
            &ndatalen, flags, stream_id,
            (ngtcp2_vec *)vec, veccnt, ts);

        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            nghttp3_conn_block_stream(h3.httpconn, stream_id);
            break;
        }
        if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
            ngtcp2_conn_shutdown_stream_write(conn, 0, stream_id, 0);
            break;
        }
        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
            http3_add_write_offset(&h3, stream_id, (size_t)ndatalen);
            continue;
        }
        if (nwrite < 0) {
            fprintf(stderr, "[quic] writev_stream error: %s\n", ngtcp2_strerror((int)nwrite));
            return -1;
        }

        if (ndatalen >= 0) {
            http3_add_write_offset(&h3, stream_id, (size_t)ndatalen);
        }

        if (nwrite > 0) {
            send(fd, buf, (size_t)nwrite, 0);
        }
    }

    // Write any remaining QUIC packets (handshake, ACKs, etc.)
    nwrite = ngtcp2_conn_write_pkt(conn, &path_tmp, &pi, buf, sizeof(buf), ts);
    if (nwrite < 0) {
        fprintf(stderr, "[quic] write_pkt error: %s\n", ngtcp2_strerror((int)nwrite));
        return -1;
    }
    if (nwrite > 0) {
        send(fd, buf, (size_t)nwrite, 0);
    }

    return 0;
}

int QuicEngine::on_expiry() {
    uint64_t ts = usque_timestamp();
    int rv = ngtcp2_conn_handle_expiry(conn, ts);
    if (rv != 0) {
        fprintf(stderr, "[quic] handle_expiry error: %s\n", ngtcp2_strerror(rv));
        return -1;
    }
    return on_write();
}

int QuicEngine::send_packet(const uint8_t *ip_pkt, size_t pkt_len) {
    if (!tunnel_ready || !conn) return -1;

    // Compose Connect-IP datagram
    uint8_t dg[1500];
    size_t dg_len = 0;
    // We need a mutable copy for compose_datagram (it modifies TTL in-place)
    uint8_t pkt_copy[1500];
    if (pkt_len > sizeof(pkt_copy)) return -1;
    memcpy(pkt_copy, ip_pkt, pkt_len);

    int rc = cip_compose_datagram(dg, sizeof(dg), &dg_len, pkt_copy, pkt_len);
    if (rc != CIP_OK) return rc;

    // Send as QUIC DATAGRAM
    uint8_t buf[65536];
    ngtcp2_path path_tmp;
    ngtcp2_pkt_info pi{};
    path_tmp.local = local_addr;
    path_tmp.remote = remote_addr;
    path_tmp.user_data = nullptr;
    uint64_t ts = usque_timestamp();

    int accepted = 0;
    ngtcp2_vec datav = {(uint8_t *)dg, dg_len};
    ngtcp2_ssize nwrite = ngtcp2_conn_writev_datagram(
        conn, &path_tmp, &pi, buf, sizeof(buf),
        &accepted, NGTCP2_WRITE_DATAGRAM_FLAG_NONE,
        dgram_id++, &datav, 1, ts);

    if (nwrite < 0) {
        if (nwrite == NGTCP2_ERR_INVALID_STATE) return 0;  // not ready yet
        return -1;
    }

    if (nwrite > 0) {
        send(fd, buf, (size_t)nwrite, 0);
    }
    return 0;
}

uint64_t QuicEngine::get_expiry() {
    if (!conn) return UINT64_MAX;
    return ngtcp2_conn_get_expiry(conn);
}

void QuicEngine::cleanup() {
    h3.~Http3Connect();
    new (&h3) Http3Connect();
    if (ssl) { SSL_free(ssl); ssl = nullptr; }
    if (conn) { ngtcp2_conn_del(conn); conn = nullptr; }
    handshake_done = false;
    tunnel_ready = false;
}

QuicEngine::~QuicEngine() {
    cleanup();
}

} // namespace usque
