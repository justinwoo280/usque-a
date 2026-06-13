#include "../src/tun/dns_hijack.c"  /* include directly for internal access */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

static int failures = 0;

static void check(const char *name, int cond) {
    if (!cond) { printf("FAIL: %s\n", name); failures++; }
    else       { printf("PASS: %s\n", name); }
}

/* Build a minimal IPv4+UDP packet for testing.
 * src_ip, dst_ip in host order. src_port, dst_port in host order. */
static int build_udp4_packet(uint8_t *pkt, int buflen,
                             uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             const uint8_t *payload, int payload_len) {
    int total = 20 + 8 + payload_len;
    if (buflen < total) return -1;

    memset(pkt, 0, (size_t)total);
    pkt[0] = 0x45;  /* IPv4, IHL=5 */
    pkt[2] = (uint8_t)(total >> 8);
    pkt[3] = (uint8_t)(total & 0xff);
    pkt[8] = 64;     /* TTL */
    pkt[9] = 17;     /* UDP */
    pkt[12] = (uint8_t)(src_ip >> 24);
    pkt[13] = (uint8_t)(src_ip >> 16);
    pkt[14] = (uint8_t)(src_ip >> 8);
    pkt[15] = (uint8_t)(src_ip);
    pkt[16] = (uint8_t)(dst_ip >> 24);
    pkt[17] = (uint8_t)(dst_ip >> 16);
    pkt[18] = (uint8_t)(dst_ip >> 8);
    pkt[19] = (uint8_t)(dst_ip);

    uint8_t *udp = pkt + 20;
    udp[0] = (uint8_t)(src_port >> 8);
    udp[1] = (uint8_t)(src_port);
    udp[2] = (uint8_t)(dst_port >> 8);
    udp[3] = (uint8_t)(dst_port);
    int udp_len = 8 + payload_len;
    udp[4] = (uint8_t)(udp_len >> 8);
    udp[5] = (uint8_t)(udp_len);
    if (payload_len > 0) memcpy(udp + 8, payload, (size_t)payload_len);

    return total;
}

static void test_hijack_dns_query(void) {
    printf("\n--- DNS Hijack: Query Rewrite ---\n");

    usque_dns_hijack_t *hj = usque_dns_hijack_create("1.1.1.1", NULL);
    check("hijack create", hj != NULL);

    /* Build: 10.0.0.1:12345 → 8.8.8.8:53 */
    uint8_t pkt[256];
    uint8_t payload[] = {0xAB, 0xCD, 0x01, 0x00};  /* DNS query header */
    int len = build_udp4_packet(pkt, sizeof(pkt),
                                0x0A000001, 0x08080808,
                                12345, 53, payload, 4);

    /* Save original dst */
    uint8_t orig_dst[4];
    memcpy(orig_dst, pkt + 16, 4);

    int rewritten = usque_dns_hijack_rewrite_query(hj, pkt, len);
    check("dns query rewritten", rewritten == 1);

    /* Dst IP should now be 1.1.1.1 */
    uint32_t new_dst;
    memcpy(&new_dst, pkt + 16, 4);
    uint32_t expected;
    inet_pton(AF_INET, "1.1.1.1", &expected);
    check("dst changed to 1.1.1.1", new_dst == expected);

    /* Src IP unchanged */
    check("src unchanged", pkt[12] == 10 && pkt[13] == 0 && pkt[14] == 0 && pkt[15] == 1);

    /* Ports unchanged */
    check("src port unchanged", pkt[20] == (12345 >> 8) && pkt[21] == (12345 & 0xff));
    check("dst port unchanged", pkt[22] == 0 && pkt[23] == 53);

    usque_dns_hijack_destroy(hj);
}

static void test_hijack_non_dns(void) {
    printf("\n--- DNS Hijack: Non-DNS Passthrough ---\n");

    usque_dns_hijack_t *hj = usque_dns_hijack_create("1.1.1.1", NULL);

    /* Build: 10.0.0.1:12345 → 8.8.8.8:80 (HTTP, not DNS) */
    uint8_t pkt[256];
    int len = build_udp4_packet(pkt, sizeof(pkt),
                                0x0A000001, 0x08080808,
                                12345, 80, NULL, 0);

    uint8_t orig_dst[4];
    memcpy(orig_dst, pkt + 16, 4);

    int rewritten = usque_dns_hijack_rewrite_query(hj, pkt, len);
    check("non-dns not rewritten", rewritten == 0);
    check("dst unchanged", memcmp(pkt + 16, orig_dst, 4) == 0);

    usque_dns_hijack_destroy(hj);
}

static void test_hijack_response(void) {
    printf("\n--- DNS Hijack: Response Rewrite ---\n");

    usque_dns_hijack_t *hj = usque_dns_hijack_create("1.1.1.1", NULL);

    /* First: send a query to build the pending mapping */
    uint8_t query[256];
    int qlen = build_udp4_packet(query, sizeof(query),
                                 0x0A000001, 0x08080808,
                                 12345, 53, NULL, 0);
    usque_dns_hijack_rewrite_query(hj, query, qlen);

    /* Now: simulate response from 1.1.1.1:53 → 10.0.0.1:12345 */
    uint8_t resp[256];
    int rlen = build_udp4_packet(resp, sizeof(resp),
                                 0x01010101, 0x0A000001,
                                 53, 12345, NULL, 0);

    int rewritten = usque_dns_hijack_rewrite_response(hj, resp, rlen);
    check("response rewritten", rewritten == 1);

    /* Src IP should be restored to original dst (8.8.8.8) */
    check("src restored to 8.8.8.8",
          resp[12] == 8 && resp[13] == 8 && resp[14] == 8 && resp[15] == 8);

    usque_dns_hijack_destroy(hj);
}

static void test_hijack_disabled(void) {
    printf("\n--- DNS Hijack: Disabled ---\n");

    usque_dns_hijack_t *hj = usque_dns_hijack_create("", NULL);
    check("hijack with empty v4 creates ctx", hj != NULL);

    uint8_t pkt[256];
    int len = build_udp4_packet(pkt, sizeof(pkt),
                                0x0A000001, 0x08080808,
                                12345, 53, NULL, 0);

    int rewritten = usque_dns_hijack_rewrite_query(hj, pkt, len);
    check("disabled hijack does nothing", rewritten == 0);

    usque_dns_hijack_destroy(hj);
}

static void test_hijack_tcp_passthrough(void) {
    printf("\n--- DNS Hijack: TCP Passthrough ---\n");

    usque_dns_hijack_t *hj = usque_dns_hijack_create("1.1.1.1", NULL);

    /* Build a TCP packet (protocol 6, not UDP 17) */
    uint8_t pkt[256];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[8] = 64;
    pkt[9] = 6;  /* TCP */
    pkt[12] = 10; pkt[15] = 1;
    pkt[16] = 8; pkt[17] = 8; pkt[18] = 8; pkt[19] = 8;

    int rewritten = usque_dns_hijack_rewrite_query(hj, pkt, 40);
    check("TCP packet not rewritten", rewritten == 0);

    usque_dns_hijack_destroy(hj);
}

int main(void) {
    test_hijack_dns_query();
    test_hijack_non_dns();
    test_hijack_response();
    test_hijack_disabled();
    test_hijack_tcp_passthrough();

    if (failures > 0) {
        printf("\n%d tests FAILED\n", failures);
        return 1;
    }
    printf("\nAll DNS hijack tests passed\n");
    return 0;
}
