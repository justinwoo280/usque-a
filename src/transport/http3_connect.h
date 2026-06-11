#pragma once

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>
#include <cstdint>
#include <string>

namespace usque {

// Forward declaration
struct QuicEngine;

struct Http3Connect {
    nghttp3_conn *httpconn = nullptr;
    int64_t       connect_stream_id = -1;
    bool          connected = false;   // true after 200 response

    // Bind this to a QuicEngine for callbacks
    QuicEngine   *engine = nullptr;

    ~Http3Connect();
};

// Initialize nghttp3 client connection.
// Opens 3 uni streams via ngtcp2 (control, qpack_enc, qpack_dec) and binds them.
// Returns 0 on success.
int http3_setup(QuicEngine *engine, Http3Connect *h3, std::string &err);

// Submit the CONNECT-IP request on a new bidi stream.
// Returns 0 on success.
int http3_submit_connect(Http3Connect *h3, ngtcp2_conn *conn, std::string &err);

// Bridge: called from ngtcp2 recv_stream_data callback
int http3_recv_stream_data(Http3Connect *h3, int64_t stream_id,
                           const uint8_t *data, size_t datalen,
                           uint64_t ts);

// Bridge: called from ngtcp2 acked_stream_data_offset callback
int http3_acked_stream_data(Http3Connect *h3, int64_t stream_id,
                            uint64_t datalen);

// Bridge: called from ngtcp2 stream_close callback
int http3_stream_close(Http3Connect *h3, int64_t stream_id,
                       uint64_t app_error_code);

// Get pending HTTP/3 data to write (called from write_pkt callback)
// veccnt is max capacity of vec array. Returns nghttp3_ssize (stream_id in *pstream_id).
nghttp3_ssize http3_writev(Http3Connect *h3, int64_t *pstream_id, int *pfin,
                           nghttp3_vec *vec, size_t veccnt);

// Notify nghttp3 that nwrite bytes were written for stream_id
int http3_add_write_offset(Http3Connect *h3, int64_t stream_id, size_t nwrite);

} // namespace usque
