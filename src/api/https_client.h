#pragma once

#include <string>

namespace usque {

struct HttpResponse {
    int         status_code = 0;
    std::string body;
    std::string error;
};

// Minimal HTTPS client using BoringSSL.
// Sends an HTTP/1.1 request and returns the response.
// method: "POST" or "PATCH"
// headers: additional headers (each "Key: Value\n")
HttpResponse https_request(const char *host, int port,
                           const char *method, const char *path,
                           const char *headers,
                           const char *body, size_t body_len);

} // namespace usque
