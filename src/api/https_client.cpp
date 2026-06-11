#include "https_client.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>

namespace usque {

static int tcp_connect(const char *host, int port) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

HttpResponse https_request(const char *host, int port,
                           const char *method, const char *path,
                           const char *headers,
                           const char *body, size_t body_len) {
    HttpResponse resp;

    // TCP connect
    int fd = tcp_connect(host, port);
    if (fd < 0) {
        resp.error = "TCP connect failed";
        return resp;
    }

    // TLS
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); resp.error = "SSL_CTX_new failed"; return resp; }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); resp.error = "SSL_new failed"; return resp; }

    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) != 1) {
        resp.error = "TLS handshake failed";
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return resp;
    }

    // Build HTTP request
    std::string req;
    char content_len[64];
    snprintf(content_len, sizeof(content_len), "Content-Length: %zu\r\n", body_len);

    req = method;
    req += " ";
    req += path;
    req += " HTTP/1.1\r\nHost: ";
    req += host;
    req += "\r\n";
    req += content_len;
    if (headers) req += headers;
    req += "Connection: close\r\n\r\n";

    // Send
    if (SSL_write(ssl, req.data(), (int)req.size()) <= 0) {
        resp.error = "SSL_write header failed";
        goto done;
    }
    if (body_len > 0 && SSL_write(ssl, body, (int)body_len) <= 0) {
        resp.error = "SSL_write body failed";
        goto done;
    }

    // Read response
    {
        std::string raw;
        char buf[4096];
        int n;
        while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
            raw.append(buf, (size_t)n);
        }

        // Parse status line
        size_t sp1 = raw.find(' ');
        size_t sp2 = raw.find(' ', sp1 + 1);
        if (sp1 != std::string::npos && sp2 != std::string::npos) {
            resp.status_code = std::stoi(raw.substr(sp1 + 1, sp2 - sp1 - 1));
        }

        // Find body (after \r\n\r\n)
        size_t body_start = raw.find("\r\n\r\n");
        if (body_start != std::string::npos) {
            body_start += 4;

            // Check for chunked encoding
            if (raw.find("Transfer-Encoding: chunked") != std::string::npos ||
                raw.find("transfer-encoding: chunked") != std::string::npos) {
                // Parse chunked body
                size_t pos = body_start;
                while (pos < raw.size()) {
                    size_t line_end = raw.find("\r\n", pos);
                    if (line_end == std::string::npos) break;
                    std::string chunk_size_str = raw.substr(pos, line_end - pos);
                    unsigned long chunk_size = std::stoul(chunk_size_str, nullptr, 16);
                    if (chunk_size == 0) break;
                    pos = line_end + 2;
                    if (pos + chunk_size <= raw.size()) {
                        resp.body.append(raw.data() + pos, chunk_size);
                    }
                    pos += chunk_size + 2;  // skip \r\n after chunk data
                }
            } else {
                resp.body = raw.substr(body_start);
            }
        }
    }

done:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return resp;
}

} // namespace usque
