#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;

static void check(const char *name, int cond) {
    if (!cond) { printf("FAIL: %s\n", name); failures++; }
    else       { printf("PASS: %s\n", name); }
}

/* ---- Mock JSON parsing tests ----
 * These test the JSON extraction logic used by register.cpp
 * without actually making HTTP requests. */

/* Minimal JSON string extractor (mirrors register.cpp logic) */
static const char* json_get_string(const char *json, const char *key,
                                   char *out, int out_len) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *pos = strstr(json, search);
    if (!pos) return NULL;
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return NULL;
    pos = strchr(pos + 1, '"');
    if (!pos) return NULL;
    pos++;

    const char *end = strchr(pos, '"');
    if (!end) return NULL;

    int len = (int)(end - pos);
    if (len >= out_len) len = out_len - 1;
    memcpy(out, pos, (size_t)len);
    out[len] = '\0';
    return out;
}

static void test_json_parse_account(void) {
    printf("\n--- Mock: JSON Account Parsing ---\n");

    const char *response =
        "{\"id\":\"abc-123-def\","
        "\"token\":\"bearer-xyz-789\","
        "\"account\":{\"license\":\"LICENSE-KEY-123\"},"
        "\"config\":{"
        "  \"peers\":[{\"public_key\":\"-----BEGIN PUBLIC KEY-----\\nMFkw...\\n-----END PUBLIC KEY-----\\n\","
        "              \"endpoint\":{\"v4\":\"162.159.198.1:0\",\"v6\":\"[2606:4700:103::]:0\"}}],"
        "  \"interface\":{\"addresses\":{\"v4\":\"100.96.0.3\",\"v6\":\"2606::1\"}}"
        "}}";

    char buf[512];

    check("parse id", json_get_string(response, "id", buf, sizeof(buf)) != NULL
          && strcmp(buf, "abc-123-def") == 0);
    check("parse token", json_get_string(response, "token", buf, sizeof(buf)) != NULL
          && strcmp(buf, "bearer-xyz-789") == 0);
    check("parse license", json_get_string(response, "license", buf, sizeof(buf)) != NULL
          && strcmp(buf, "LICENSE-KEY-123") == 0);
    check("parse v4", json_get_string(response, "v4", buf, sizeof(buf)) != NULL
          && strcmp(buf, "162.159.198.1:0") == 0);
    check("parse v6", json_get_string(response, "v6", buf, sizeof(buf)) != NULL
          && strstr(buf, "2606:4700:103::") != NULL);
    check("parse ipv4 addr", json_get_string(response, "v4", buf, sizeof(buf)) != NULL);
}

static void test_json_endpoint_strip(void) {
    printf("\n--- Mock: Endpoint Port Stripping ---\n");

    /* Simulate the Go-style endpoint stripping logic */
    const char *ep_v4 = "162.159.198.1:0";
    const char *ep_v6 = "[2606:4700:103::]:0";

    /* IPv4: strip from last ':' */
    char stripped_v4[128];
    strncpy(stripped_v4, ep_v4, sizeof(stripped_v4));
    char *colon = strrchr(stripped_v4, ':');
    if (colon) *colon = '\0';
    check("v4 strip port", strcmp(stripped_v4, "162.159.198.1") == 0);

    /* IPv6: strip '[' and ']:' */
    char stripped_v6[128];
    strncpy(stripped_v6, ep_v6, sizeof(stripped_v6));
    char *bracket = strchr(stripped_v6, ']');
    if (bracket) *bracket = '\0';
    char *result = stripped_v6[0] == '[' ? stripped_v6 + 1 : stripped_v6;
    check("v6 strip brackets+port", strcmp(result, "2606:4700:103::") == 0);
}

static void test_json_error_response(void) {
    printf("\n--- Mock: Error Response Handling ---\n");

    const char *error_resp = "{\"errors\":[{\"code\":1001,\"message\":\"Invalid public key\"}]}";
    char buf[256];

    check("error: has message field",
          json_get_string(error_resp, "message", buf, sizeof(buf)) != NULL
          && strstr(buf, "Invalid public key") != NULL);

    const char *empty_resp = "{}";
    check("error: missing id returns NULL",
          json_get_string(empty_resp, "id", buf, sizeof(buf)) == NULL);

    const char *malformed = "not json at all";
    check("error: malformed JSON returns NULL",
          json_get_string(malformed, "id", buf, sizeof(buf)) == NULL);
}

static void test_pem_normalization(void) {
    printf("\n--- Mock: PEM Newline Normalization ---\n");

    /* Simulate the PEM newline fix from register.cpp */
    const char *pem_with_escapes =
        "-----BEGIN PUBLIC KEY-----\\nMFkw\\n-----END PUBLIC KEY-----\\n";

    /* Normalize: replace \\n with real \n */
    char normalized[512];
    int j = 0;
    for (int i = 0; pem_with_escapes[i]; i++) {
        if (pem_with_escapes[i] == '\\' && pem_with_escapes[i + 1] == 'n') {
            normalized[j++] = '\n';
            i++;
        } else {
            normalized[j++] = pem_with_escapes[i];
        }
    }
    normalized[j] = '\0';

    check("pem has real newlines", strstr(normalized, "KEY-----\nMFkw\n") != NULL);
    check("pem starts correctly", strncmp(normalized, "-----BEGIN", 10) == 0);
    check("pem ends with newline", normalized[j - 1] == '\n');
}

static void test_registration_json_build(void) {
    printf("\n--- Mock: Registration JSON Build ---\n");

    /* Simulate building the registration request JSON */
    const char *fake_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const char *serial = "0123456789abcdef";
    const char *tos = "2024-01-01T00:00:00.000Z";

    char json[2048];
    int n = snprintf(json, sizeof(json),
        "{\"key\":\"%s\","
        "\"install_id\":\"\","
        "\"fcm_token\":\"\","
        "\"tos\":\"%s\","
        "\"model\":\"PC\","
        "\"serial_number\":\"%s\","
        "\"os_version\":\"\","
        "\"key_type\":\"curve25519\","
        "\"tunnel_type\":\"wireguard\","
        "\"locale\":\"en_US\"}",
        fake_key, tos, serial);

    check("json build: non-empty", n > 0);
    check("json build: has key", strstr(json, "\"key\":\"AAAA") != NULL);
    check("json build: has model", strstr(json, "\"model\":\"PC\"") != NULL);
    check("json build: has tunnel_type", strstr(json, "\"tunnel_type\":\"wireguard\"") != NULL);
    check("json build: has serial", strstr(json, serial) != NULL);
}

int main(void) {
    test_json_parse_account();
    test_json_endpoint_strip();
    test_json_error_response();
    test_pem_normalization();
    test_registration_json_build();

    if (failures > 0) {
        printf("\n%d mock tests FAILED\n", failures);
        return 1;
    }
    printf("\nAll mock tests passed\n");
    return 0;
}
