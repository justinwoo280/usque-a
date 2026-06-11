#include "../src/connectip/connect_ip.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

static int failures = 0;

static void check(const char *name, int cond) {
    if (!cond) { printf("FAIL: %s\n", name); failures++; }
    else       { printf("PASS: %s\n", name); }
}

/*
 * Regression tests for bugs found during development.
 * Each test documents the bug it prevents from recurring.
 */

/* ---- REG-001: Datagram parse byte offset bug ----
 * Bug: In test_connectip.c, parse tests used dg[3] = 40 thinking it was
 * Total Length low byte, but dg[3] is actually IP byte 2 (Total Length HIGH
 * byte). This caused Total Length = 40*256 = 10240 instead of 40.
 * Fix: Use correct offsets dg[3]=0 (high), dg[4]=40 (low).
 */
static void reg001_datagram_parse_offset(void) {
    printf("\n--- REG-001: Datagram Parse Byte Offset ---\n");

    /* Build a valid datagram: Context ID 0 + IPv4 packet */
    uint8_t dg[64];
    memset(dg, 0, sizeof(dg));
    dg[0] = 0x00;   /* Context ID = 0 */
    dg[1] = 0x45;   /* IPv4, IHL=5 */

    /* WRONG (old bug): dg[3] = 40 → Total Length = 40*256 = 10240 */
    dg[3] = 40;
    dg[4] = 0;
    dg[9] = 64;
    const uint8_t *ip_pkt;
    size_t ip_len;
    int rc = cip_parse_datagram(dg, 41, &ip_pkt, &ip_len);
    check("REG-001: wrong offset (dg[3]=40) should fail", rc != CIP_OK);

    /* CORRECT: dg[3] = 0 (high), dg[4] = 40 (low) → Total Length = 40 */
    dg[3] = 0;
    dg[4] = 40;
    rc = cip_parse_datagram(dg, 41, &ip_pkt, &ip_len);
    check("REG-001: correct offset (dg[3]=0,dg[4]=40) should pass", rc == CIP_OK);
}

/* ---- REG-002: IPv4 IHL validation ----
 * Bug: Original compose_datagram did not validate IHL field.
 * A packet with IHL=3 (12 bytes, less than minimum 20) would be accepted.
 * Fix: Added IHL < 20 check in compose_datagram.
 */
static void reg002_ihl_validation(void) {
    printf("\n--- REG-002: IPv4 IHL Validation ---\n");

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x43;  /* IHL=3 (12 bytes, invalid) */
    pkt[2] = 0; pkt[3] = 40;
    pkt[8] = 64;

    uint8_t out[128];
    size_t out_len;
    int rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 40);
    check("REG-002: IHL=3 rejected", rc == CIP_ERR_TOO_SHORT);

    pkt[0] = 0x45;  /* IHL=5 (20 bytes, valid) */
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 40);
    check("REG-002: IHL=5 accepted", rc == CIP_OK);

    /* IHL claims more than packet size */
    pkt[0] = 0x4A;  /* IHL=10 (40 bytes) */
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 20);
    check("REG-002: IHL=10 with 20-byte packet rejected", rc == CIP_ERR_TOO_SHORT);
}

/* ---- REG-003: Total Length overflow ----
 * Bug: compose_datagram did not check if IPv4 Total Length field exceeds
 * actual packet length. A forged packet could claim Total Length > actual.
 * Fix: Added total_len > pkt_len check.
 */
static void reg003_total_length_overflow(void) {
    printf("\n--- REG-003: Total Length Overflow ---\n");

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 60;  /* Total Length = 60, but packet is only 40 bytes */
    pkt[8] = 64;

    uint8_t out[128];
    size_t out_len;
    int rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 40);
    check("REG-003: TotalLen=60 > pkt_len=40 rejected", rc == CIP_ERR_TOO_SHORT);

    pkt[3] = 40;  /* Total Length = 40, matches packet */
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 40);
    check("REG-003: TotalLen=40 == pkt_len=40 accepted", rc == CIP_OK);
}

/* ---- REG-004: TTL boundary ----
 * Bug: TTL=0 and TTL=1 should both be rejected (packet would not survive
 * another hop). Original code checked TTL <= 1, which is correct.
 * This test ensures it stays correct.
 */
static void reg004_ttl_boundary(void) {
    printf("\n--- REG-004: TTL Boundary ---\n");

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[9] = 6;

    uint8_t out[128];
    size_t out_len;

    pkt[8] = 0;
    check("REG-004: TTL=0 rejected",
          cip_compose_datagram(out, sizeof(out), &out_len, pkt, 40) == CIP_ERR_TTL);

    pkt[8] = 1;
    check("REG-004: TTL=1 rejected",
          cip_compose_datagram(out, sizeof(out), &out_len, pkt, 40) == CIP_ERR_TTL);

    pkt[8] = 2;
    check("REG-004: TTL=2 accepted",
          cip_compose_datagram(out, sizeof(out), &out_len, pkt, 40) == CIP_OK);
    check("REG-004: TTL decremented to 1", pkt[8] == 1);
}

/* ---- REG-005: IPv6 Hop Limit boundary ----
 * Same as REG-004 but for IPv6.
 */
static void reg005_hop_limit_boundary(void) {
    printf("\n--- REG-005: IPv6 Hop Limit Boundary ---\n");

    uint8_t pkt[60];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;
    pkt[4] = 0; pkt[5] = 20;  /* Payload Length = 20 */

    uint8_t out[128];
    size_t out_len;

    pkt[7] = 0;
    check("REG-005: HopLimit=0 rejected",
          cip_compose_datagram(out, sizeof(out), &out_len, pkt, 60) == CIP_ERR_TTL);

    pkt[7] = 1;
    check("REG-005: HopLimit=1 rejected",
          cip_compose_datagram(out, sizeof(out), &out_len, pkt, 60) == CIP_ERR_TTL);

    pkt[7] = 2;
    check("REG-005: HopLimit=2 accepted",
          cip_compose_datagram(out, sizeof(out), &out_len, pkt, 60) == CIP_OK);
    check("REG-005: HopLimit decremented to 1", pkt[7] == 1);
}

/* ---- REG-006: Context ID non-zero rejection ----
 * Only Context ID 0 (IP proxying) should be accepted. Non-zero IDs are
 * for IP flow forwarding (unsupported) or noise datagrams.
 */
static void reg006_context_id_rejection(void) {
    printf("\n--- REG-006: Context ID Non-Zero Rejection ---\n");

    uint8_t dg[64];
    memset(dg, 0, sizeof(dg));

    /* Context ID = 1 (2-byte varint: 0x40, 0x01) */
    dg[0] = 0x40; dg[1] = 0x01;
    dg[2] = 0x45;  /* IPv4 */
    dg[4] = 40;

    const uint8_t *ip_pkt;
    size_t ip_len;
    int rc = cip_parse_datagram(dg, 42, &ip_pkt, &ip_len);
    check("REG-006: Context ID=1 rejected", rc == CIP_ERR_CTX_ID);

    /* Context ID = 63 (max 1-byte: 0x3F) */
    dg[0] = 0x3F;
    rc = cip_parse_datagram(dg, 41, &ip_pkt, &ip_len);
    check("REG-006: Context ID=63 rejected", rc == CIP_ERR_CTX_ID);
}

/* ---- REG-007: IPv6 Payload Length validation ----
 * Payload Length + 40 (fixed header) must not exceed actual packet length.
 */
static void reg007_ipv6_payload_length(void) {
    printf("\n--- REG-007: IPv6 Payload Length ---\n");

    uint8_t pkt[60];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;
    pkt[4] = 0; pkt[5] = 40;  /* Payload Length = 40, but payload area is only 20 */
    pkt[7] = 64;

    uint8_t out[128];
    size_t out_len;
    int rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 60);
    check("REG-007: PayloadLen=40 > actual=20 rejected", rc == CIP_ERR_TOO_SHORT);

    pkt[5] = 20;  /* Payload Length = 20, matches */
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 60);
    check("REG-007: PayloadLen=20 == actual=20 accepted", rc == CIP_OK);
}

/* ---- REG-008: Compose doesn't modify packet on error ----
 * When compose_datagram rejects a packet (e.g. TTL too low), the original
 * packet should NOT be modified.
 */
static void reg008_no_modify_on_error(void) {
    printf("\n--- REG-008: No Modify On Error ---\n");

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[8] = 1;  /* TTL=1, will be rejected */

    uint8_t saved[40];
    memcpy(saved, pkt, 40);

    uint8_t out[128];
    size_t out_len;
    int rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 40);
    check("REG-008: rejected", rc != CIP_OK);
    check("REG-008: packet unchanged after rejection", memcmp(pkt, saved, 40) == 0);
}

int main(void) {
    reg001_datagram_parse_offset();
    reg002_ihl_validation();
    reg003_total_length_overflow();
    reg004_ttl_boundary();
    reg005_hop_limit_boundary();
    reg006_context_id_rejection();
    reg007_ipv6_payload_length();
    reg008_no_modify_on_error();

    if (failures > 0) {
        printf("\n%d regression tests FAILED\n", failures);
        return 1;
    }
    printf("\nAll regression tests passed\n");
    return 0;
}
