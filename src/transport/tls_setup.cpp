#include "tls_setup.h"

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <cstring>
#include <ctime>

namespace usque {

static std::string ssl_error_string() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "unknown error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

// Decode base64 string to raw bytes
static std::string base64_decode(const char *b64) {
    size_t b64_len = strlen(b64);
    std::string result(b64_len, '\0');
    size_t out_len = 0;
    if (!EVP_DecodeBase64((uint8_t *)result.data(), &out_len, b64_len,
                          (const uint8_t *)b64, b64_len)) {
        return "";
    }
    result.resize(out_len);
    return result;
}

// Parse base64-encoded DER ECDSA private key (SEC1 format)
static EVP_PKEY* parse_private_key(const char *b64, std::string &err) {
    std::string der = base64_decode(b64);
    if (der.empty()) {
        err = "failed to base64-decode private key";
        return nullptr;
    }

    const unsigned char *p = (const unsigned char *)der.data();
    EC_KEY *ec_key = d2i_ECPrivateKey(nullptr, &p, (long)der.size());
    if (!ec_key) {
        err = "failed to parse EC private key: " + ssl_error_string();
        return nullptr;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        err = "failed to create EVP_PKEY: " + ssl_error_string();
        return nullptr;
    }
    return pkey;
}

// Parse PEM-encoded PKIX public key
static EVP_PKEY* parse_public_key_pem(const char *pem, std::string &err) {
    BIO *bio = BIO_new_mem_buf(pem, (int)strlen(pem));
    if (!bio) {
        err = "failed to create BIO for public key";
        return nullptr;
    }

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        err = "failed to parse public key PEM: " + ssl_error_string();
        return nullptr;
    }
    return pkey;
}

// Generate self-signed X.509 certificate (24h validity, empty Subject)
static X509* generate_self_signed_cert(EVP_PKEY *pkey, std::string &err) {
    X509 *cert = X509_new();
    if (!cert) {
        err = "X509_new failed";
        return nullptr;
    }

    X509_set_version(cert, 2);  // X.509 v3

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 0);

    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 24 * 3600);

    X509_set_pubkey(cert, pkey);

    // Empty subject and issuer (self-signed)
    X509_NAME *name = X509_get_subject_name(cert);
    X509_set_issuer_name(cert, name);

    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        X509_free(cert);
        err = "X509_sign failed: " + ssl_error_string();
        return nullptr;
    }

    return cert;
}

// Custom verify callback for public key pinning
static enum ssl_verify_result_t pinning_verify_cb(SSL *ssl, uint8_t *out_alert) {
    (void)out_alert;

    TlsContext *ctx = (TlsContext *)SSL_get_app_data(ssl);
    if (!ctx || !ctx->pinned_key) {
        return ssl_verify_ok;  // no pinning configured
    }

    // Get the peer's leaf certificate
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    if (!peer_cert) {
        return ssl_verify_invalid;
    }

    EVP_PKEY *peer_key = X509_get0_pubkey(peer_cert);
    if (!peer_key) {
        X509_free(peer_cert);
        return ssl_verify_invalid;
    }

    // Compare public keys
    enum ssl_verify_result_t result = ssl_verify_invalid;
    if (EVP_PKEY_eq(peer_key, ctx->pinned_key) == 1) {
        result = ssl_verify_ok;
    }

    X509_free(peer_cert);
    return result;
}

TlsContext::~TlsContext() {
    SSL_CTX_free(ssl_ctx);
    EVP_PKEY_free(pinned_key);
}

TlsContext* tls_context_create(const char *private_key_b64,
                               const char *endpoint_pub_key_pem,
                               const char *sni,
                               bool insecure,
                               std::string &err) {
    auto *ctx = new TlsContext();

    // Parse private key
    EVP_PKEY *client_key = parse_private_key(private_key_b64, err);
    if (!client_key) {
        delete ctx;
        return nullptr;
    }

    // Parse endpoint public key for pinning
    if (!insecure && endpoint_pub_key_pem && endpoint_pub_key_pem[0]) {
        ctx->pinned_key = parse_public_key_pem(endpoint_pub_key_pem, err);
        if (!ctx->pinned_key) {
            EVP_PKEY_free(client_key);
            delete ctx;
            return nullptr;
        }
    }

    // Generate self-signed certificate
    X509 *cert = generate_self_signed_cert(client_key, err);
    if (!cert) {
        EVP_PKEY_free(client_key);
        delete ctx;
        return nullptr;
    }

    // Create SSL_CTX
    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ssl_ctx) {
        err = "SSL_CTX_new failed: " + ssl_error_string();
        X509_free(cert);
        EVP_PKEY_free(client_key);
        delete ctx;
        return nullptr;
    }

    // Configure for QUIC (TLS 1.3 + SSL_QUIC_METHOD)
    if (ngtcp2_crypto_boringssl_configure_client_context(ctx->ssl_ctx) != 0) {
        err = "ngtcp2_crypto_boringssl_configure_client_context failed";
        X509_free(cert);
        EVP_PKEY_free(client_key);
        delete ctx;
        return nullptr;
    }

    // Set client certificate and private key
    if (SSL_CTX_use_PrivateKey(ctx->ssl_ctx, client_key) != 1) {
        err = "SSL_CTX_use_PrivateKey failed: " + ssl_error_string();
        X509_free(cert);
        EVP_PKEY_free(client_key);
        delete ctx;
        return nullptr;
    }

    if (SSL_CTX_add1_chain_cert(ctx->ssl_ctx, cert) != 1) {
        err = "SSL_CTX_add1_chain_cert failed: " + ssl_error_string();
        X509_free(cert);
        EVP_PKEY_free(client_key);
        delete ctx;
        return nullptr;
    }

    // Set up public key pinning
    if (!insecure && ctx->pinned_key) {
        SSL_CTX_set_custom_verify(ctx->ssl_ctx,
                                  SSL_VERIFY_PEER,
                                  pinning_verify_cb);
    }

    X509_free(cert);
    EVP_PKEY_free(client_key);
    return ctx;
}

SSL* tls_create_session(TlsContext *ctx, const char *sni) {
    SSL *ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) return nullptr;

    // ALPN: h3
    static const uint8_t alpn[] = {2, 'h', '3'};
    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));

    // SNI
    if (sni && sni[0]) {
        SSL_set_tlsext_host_name(ssl, sni);
    }

    // Store TlsContext for pinning callback
    // NOTE: The caller must overwrite app_data with conn_ref before starting handshake.
    // We temporarily store ctx here; quic_engine will replace it with conn_ref
    // and keep a pointer to ctx in its own struct.
    SSL_set_app_data(ssl, ctx);

    return ssl;
}

} // namespace usque
