#pragma once

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <string>
#include <cstdint>

namespace usque {

// Holds the pinned endpoint public key for verification
struct TlsContext {
    SSL_CTX     *ssl_ctx  = nullptr;
    EVP_PKEY    *pinned_key = nullptr;  // endpoint public key for pinning

    ~TlsContext();
};

// Create SSL_CTX configured for WARP MASQUE:
//   - TLS 1.3 via BoringSSL
//   - ngtcp2 SSL_QUIC_METHOD installed
//   - Public key pinning (endpoint_pub_key PEM)
//   - Client ECDSA P-256 private key (base64 DER) loaded
//   - Self-signed certificate generated
//
// Returns nullptr on error; error message in err.
TlsContext* tls_context_create(const char *private_key_b64,
                               const char *endpoint_pub_key_pem,
                               const char *sni,
                               bool insecure,
                               std::string &err);

// Create a per-connection SSL object from the context.
// Sets ALPN (h3), SNI, and prepares for ngtcp2 bridge.
// The caller must set SSL_set_app_data(ssl, &conn_ref) after this.
SSL* tls_create_session(TlsContext *ctx, const char *sni);

} // namespace usque
