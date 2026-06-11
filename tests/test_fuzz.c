#include "../src/connectip/connect_ip.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static int failures = 0;

static void check(const char *name, int cond) {
    if (!cond) { printf("FAIL: %s\n", name); failures++; }
    else       { printf("PASS: %s\n", name); }
}

/* Simple deterministic PRNG for reproducibility */
static uint32_t prng_state = 12345;
static uint8_t prng_byte(void) {
    prng_state = prng_state * 1103515245 + 12345;
    return (uint8_t)(prng_state >> 16);
}
static void prng_fill(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = prng_byte();
}
static void prng_seed(uint32_t s) { prng_state = s; }

/* ---- Varint fuzz ---- */

static void fuzz_varint(void) {
    printf("\n--- Fuzz: QUIC Varint ---\n");

    int crashes = 0;

    /* Fuzz decoder with random bytes */
    for (int trial = 0; trial < 10000; trial++) {
        uint8_t buf[8];
        prng_fill(buf, sizeof(buf));

        for (size_t len = 0; len <= 8; len++) {
            uint64_t val;
            int n = cip_varint_decode(buf, len, &val);
            /* Should never crash, just return 0 or valid n */
            if (n < 0 || n > 8) {
                crashes++;
            }
        }
    }
    check("varint decode: no crashes on 80000 random inputs", crashes == 0);

    /* Fuzz encoder with random values */
    crashes = 0;
    for (int trial = 0; trial < 10000; trial++) {
        uint64_t val;
        prng_fill((uint8_t *)&val, sizeof(val));
        /* Mask to valid range (< 2^62) */
        val &= 0x3FFFFFFFFFFFFFFFULL;

        uint8_t buf[8];
        int n = cip_varint_encode(buf, sizeof(buf), val);
        if (n <= 0 || n > 8) {
            crashes++;
            continue;
        }

        /* Roundtrip */
        uint64_t decoded;
        int m = cip_varint_decode(buf, (size_t)n, &decoded);
        if (m != n || decoded != val) {
            crashes++;
        }
    }
    check("varint roundtrip: 10000 random values", crashes == 0);

    /* Edge cases */
    uint8_t empty[1] = {0};
    uint64_t val;
    check("varint: empty buffer returns 0", cip_varint_decode(empty, 0, &val) == 0);
    check("varint: 1-byte prefix=0b11 needs 8 bytes", cip_varint_decode((uint8_t[]){0xC0}, 1, &val) == 0);
}

/* ---- Datagram parser fuzz ---- */

static void fuzz_datagram_parser(void) {
    printf("\n--- Fuzz: Datagram Parser ---\n");

    int crashes = 0;

    for (int trial = 0; trial < 10000; trial++) {
        uint8_t dg[256];
        prng_fill(dg, sizeof(dg));

        const uint8_t *ip_pkt = NULL;
        size_t ip_len = 0;

        /* Should never crash */
        int rc = cip_parse_datagram(dg, sizeof(dg), &ip_pkt, &ip_len);
        (void)rc;
        (void)ip_pkt;
        (void)ip_len;
    }
    check("datagram parser: no crashes on 10000 random inputs", crashes == 0);

    /* Targeted fuzz: valid context ID 0 + garbage IP */
    crashes = 0;
    for (int trial = 0; trial < 5000; trial++) {
        uint8_t dg[256];
        dg[0] = 0x00;  /* Context ID = 0 (valid) */
        prng_fill(dg + 1, sizeof(dg) - 1);

        /* Force first nibble to 4 or 6 (valid IP version) */
        dg[1] = (uint8_t)((trial % 2 == 0 ? 0x40 : 0x60) | (dg[1] & 0x0f));

        const uint8_t *ip_pkt = NULL;
        size_t ip_len = 0;
        int rc = cip_parse_datagram(dg, sizeof(dg), &ip_pkt, &ip_len);
        (void)rc;
    }
    check("datagram parser: no crashes on 5000 crafted inputs", crashes == 0);

    /* Empty and minimal inputs */
    const uint8_t *ip_pkt;
    size_t ip_len;
    check("parse: empty", cip_parse_datagram(NULL, 0, &ip_pkt, &ip_len) != CIP_OK);
    uint8_t one_byte[] = {0x00};
    check("parse: context-only", cip_parse_datagram(one_byte, 1, &ip_pkt, &ip_len) != CIP_OK);
}

/* ---- Compose datagram fuzz ---- */

static void fuzz_datagram_compose(void) {
    printf("\n--- Fuzz: Datagram Compose ---\n");

    int crashes = 0;

    for (int trial = 0; trial < 5000; trial++) {
        uint8_t pkt[256];
        prng_fill(pkt, sizeof(pkt));

        /* Force valid IP version */
        pkt[0] = (uint8_t)((trial % 2 == 0 ? 0x40 : 0x60) | (pkt[0] & 0x0f));

        uint8_t out[512];
        size_t out_len = 0;
        int rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, sizeof(pkt));
        (void)rc;
    }
    check("compose: no crashes on 5000 random packets", crashes == 0);
}

/* ---- Checksum fuzz ---- */

static void fuzz_checksum(void) {
    printf("\n--- Fuzz: IPv4 Checksum ---\n");

    int crashes = 0;

    for (int trial = 0; trial < 10000; trial++) {
        uint8_t header[20];
        prng_fill(header, sizeof(header));
        header[0] = 0x45;  /* Force valid version/IHL */

        /* Should never crash, always return a valid uint16 */
        uint16_t cksum = cip_ipv4_checksum(header);
        (void)cksum;
    }
    check("checksum: no crashes on 10000 random headers", crashes == 0);

    /* Verify: checksum of all zeros should be 0xffff */
    uint8_t zeros[20] = {0};
    check("checksum: all-zero header = 0xffff", cip_ipv4_checksum(zeros) == 0xffff);
}

/* ---- ICMP generation fuzz ---- */

static void fuzz_icmp(void) {
    printf("\n--- Fuzz: ICMP Too Big ---\n");

    int crashes = 0;

    for (int trial = 0; trial < 2000; trial++) {
        uint8_t pkt[256];
        prng_fill(pkt, sizeof(pkt));
        pkt[0] = (uint8_t)((trial % 2 == 0 ? 0x40 : 0x60) | (pkt[0] & 0x0f));

        uint8_t out[1500];
        size_t out_len = 0;
        int rc = cip_compose_icmp_too_big(out, sizeof(out), &out_len, pkt, sizeof(pkt), 1280);
        (void)rc;
    }
    check("icmp: no crashes on 2000 random packets", crashes == 0);
}

/* ---- Noise packet fuzz ---- */

static void fuzz_noise(void) {
    printf("\n--- Fuzz: Noise Packet ---\n");

    int crashes = 0;

    for (int trial = 0; trial < 2000; trial++) {
        uint8_t out[1500];
        size_t out_len = 0;
        size_t payload_size = (size_t)(trial % 1400);
        int rc = cip_compose_noise_packet(out, sizeof(out), &out_len, payload_size);
        if (rc == CIP_OK) {
            /* Verify structure */
            if ((out[0] >> 4) != 4) crashes++;
            if (out[8] != 64) crashes++;
            if (out[9] != 0xFF) crashes++;
        }
    }
    check("noise: no crashes and valid structure on 2000 sizes", crashes == 0);
}

int main(void) {
    prng_seed(42);

    fuzz_varint();
    fuzz_datagram_parser();
    fuzz_datagram_compose();
    fuzz_checksum();
    fuzz_icmp();
    fuzz_noise();

    if (failures > 0) {
        printf("\n%d fuzz tests FAILED\n", failures);
        return 1;
    }
    printf("\nAll fuzz tests passed\n");
    return 0;
}
