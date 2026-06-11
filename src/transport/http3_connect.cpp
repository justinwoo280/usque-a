#include "http3_connect.h"
#include "quic_engine.h"

#include <cstring>

namespace usque {

// ---- nghttp3 callbacks ----

static int h3_acked_stream_data(nghttp3_conn *conn, int64_t stream_id,
                                uint64_t datalen, void *conn_user_data,
                                void *stream_user_data) {
    (void)conn; (void)stream_user_data;
    auto *engine = (QuicEngine *)conn_user_data;
    return http3_acked_stream_data(&engine->h3, stream_id, datalen);
}

static int h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                           uint64_t app_error_code, void *conn_user_data,
                           void *stream_user_data) {
    (void)conn; (void)stream_user_data;
    auto *engine = (QuicEngine *)conn_user_data;
    return http3_stream_close(&engine->h3, stream_id, app_error_code);
}

static int h3_recv_data(nghttp3_conn *conn, int64_t stream_id,
                        const uint8_t *data, size_t datalen,
                        void *conn_user_data, void *stream_user_data) {
    (void)conn; (void)stream_user_data; (void)data; (void)datalen;
    // We don't expect DATA frames in the CONNECT response
    (void)conn_user_data;
    return 0;
}

static int h3_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                               size_t nconsumed, void *conn_user_data,
                               void *stream_user_data) {
    (void)conn; (void)stream_user_data;
    auto *engine = (QuicEngine *)conn_user_data;
    ngtcp2_conn_extend_max_stream_offset(engine->conn, stream_id, nconsumed);
    ngtcp2_conn_extend_max_offset(engine->conn, nconsumed);
    return 0;
}

static int h3_recv_header(nghttp3_conn *conn, int64_t stream_id,
                          int32_t token, nghttp3_rcbuf *name,
                          nghttp3_rcbuf *value, uint8_t flags,
                          void *conn_user_data, void *stream_user_data) {
    (void)conn; (void)name; (void)value; (void)flags; (void)stream_user_data;
    auto *engine = (QuicEngine *)conn_user_data;

    if (token == NGHTTP3_QPACK_TOKEN__STATUS) {
        nghttp3_vec val = nghttp3_rcbuf_get_buf(value);
        if (val.len >= 3 && memcmp(val.base, "200", 3) == 0) {
            engine->h3.connected = true;
        }
    }
    return 0;
}

static int h3_end_headers(nghttp3_conn *conn, int64_t stream_id,
                          int fin, void *conn_user_data,
                          void *stream_user_data) {
    (void)conn; (void)stream_id; (void)fin; (void)stream_user_data;
    auto *engine = (QuicEngine *)conn_user_data;

    if (engine->h3.connected) {
        // Signal that the tunnel is ready for data
        engine->tunnel_ready = true;
    }
    return 0;
}

// ---- Implementation ----

Http3Connect::~Http3Connect() {
    nghttp3_conn_del(httpconn);
}

int http3_setup(QuicEngine *engine, Http3Connect *h3, std::string &err) {
    h3->engine = engine;

    nghttp3_callbacks callbacks{};
    callbacks.acked_stream_data = h3_acked_stream_data;
    callbacks.stream_close = h3_stream_close;
    callbacks.recv_data = h3_recv_data;
    callbacks.deferred_consume = h3_deferred_consume;
    callbacks.recv_header = h3_recv_header;
    callbacks.end_headers = h3_end_headers;

    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.h3_datagram = 1;

    // Custom SETTINGS: deprecated H3 DATAGRAM (0x276 = 1)
    nghttp3_settings_entry ext[] = {{0x276, 1}};
    settings.ext_settings = ext;
    settings.num_ext_settings = 1;

    int rv = nghttp3_conn_client_new(&h3->httpconn, &callbacks, &settings,
                                     nghttp3_mem_default(), engine);
    if (rv != 0) {
        err = std::string("nghttp3_conn_client_new: ") + nghttp3_strerror(rv);
        return -1;
    }

    // Open 3 unidirectional streams for HTTP/3 control + QPACK
    int64_t ctrl_id, qpack_enc_id, qpack_dec_id;

    rv = ngtcp2_conn_open_uni_stream(engine->conn, &ctrl_id, nullptr);
    if (rv != 0) { err = "open ctrl stream failed"; return -1; }

    rv = ngtcp2_conn_open_uni_stream(engine->conn, &qpack_enc_id, nullptr);
    if (rv != 0) { err = "open qpack_enc stream failed"; return -1; }

    rv = ngtcp2_conn_open_uni_stream(engine->conn, &qpack_dec_id, nullptr);
    if (rv != 0) { err = "open qpack_dec stream failed"; return -1; }

    nghttp3_conn_bind_control_stream(h3->httpconn, ctrl_id);
    nghttp3_conn_bind_qpack_streams(h3->httpconn, qpack_enc_id, qpack_dec_id);

    return 0;
}

int http3_submit_connect(Http3Connect *h3, ngtcp2_conn *conn, std::string &err) {
    int64_t stream_id;
    int rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, nullptr);
    if (rv != 0) {
        err = std::string("open bidi stream: ") + ngtcp2_strerror(rv);
        return -1;
    }

    // Build CONNECT-IP headers (Cloudflare-specific)
    nghttp3_nv nva[] = {
        {(uint8_t *)":method",    (uint8_t *)"CONNECT",           7, 22, NGHTTP3_NV_FLAG_NONE},
        {(uint8_t *)":protocol",  (uint8_t *)"cf-connect-ip",     9, 15, NGHTTP3_NV_FLAG_NONE},
        {(uint8_t *)":scheme",    (uint8_t *)"https",             7,  5, NGHTTP3_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"cloudflareaccess.com", 10, 22, NGHTTP3_NV_FLAG_NONE},
        {(uint8_t *)":path",      (uint8_t *)"/",                 5,  1, NGHTTP3_NV_FLAG_NONE},
        {(uint8_t *)"capsule-protocol", (uint8_t *)"?1",         16,  2, NGHTTP3_NV_FLAG_NONE},
        {(uint8_t *)"user-agent", (uint8_t *)"",                  10,  0, NGHTTP3_NV_FLAG_NONE},
    };

    rv = nghttp3_conn_submit_request(h3->httpconn, stream_id,
                                     nva, sizeof(nva) / sizeof(nva[0]),
                                     nullptr, nullptr);
    if (rv != 0) {
        err = std::string("submit_request: ") + nghttp3_strerror(rv);
        return -1;
    }

    h3->connect_stream_id = stream_id;
    return 0;
}

int http3_recv_stream_data(Http3Connect *h3, int64_t stream_id,
                           const uint8_t *data, size_t datalen,
                           uint64_t ts) {
    if (!h3->httpconn) return 0;
    (void)ts;

    nghttp3_ssize nconsumed = nghttp3_conn_read_stream(
        h3->httpconn, stream_id, data, datalen, 0);
    if (nconsumed < 0) return -1;
    return 0;
}

int http3_acked_stream_data(Http3Connect *h3, int64_t stream_id,
                            uint64_t datalen) {
    if (!h3->httpconn) return 0;
    return nghttp3_conn_add_ack_offset(h3->httpconn, stream_id, datalen);
}

int http3_stream_close(Http3Connect *h3, int64_t stream_id,
                       uint64_t app_error_code) {
    if (!h3->httpconn) return 0;
    return nghttp3_conn_close_stream(h3->httpconn, stream_id,
                                     (int64_t)app_error_code);
}

nghttp3_ssize http3_writev(Http3Connect *h3, int64_t *pstream_id, int *pfin,
                           nghttp3_vec *vec, size_t veccnt) {
    if (!h3->httpconn) {
        *pstream_id = -1;
        return 0;
    }
    return nghttp3_conn_writev_stream(h3->httpconn, pstream_id, pfin,
                                      vec, veccnt);
}

int http3_add_write_offset(Http3Connect *h3, int64_t stream_id, size_t nwrite) {
    if (!h3->httpconn) return 0;
    return nghttp3_conn_add_write_offset(h3->httpconn, stream_id, nwrite);
}

} // namespace usque
