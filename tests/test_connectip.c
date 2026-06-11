#include "../src/connectip/connect_ip.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;

static void check(const char *name, int cond) {
    if (!cond) {
        printf("FAIL: %s\n", name);
        failures++;
    } else {
        printf("PASS: %s\n", name);
    }
}

static void test_varint(void) {
    printf("\n--- QUIC Varint ---\n");
    uint8_t buf[8];
    uint64_t val;
    int n;

    /* 1-byte: value 0 */
    n = cip_varint_encode(buf, sizeof(buf), 0);
    check("encode 0", n == 1 && buf[0] == 0x00);

    n = cip_varint_decode(buf, n, &val);
    check("decode 0", n == 1 && val == 0);

    /* 1-byte: value 37 */
    n = cip_varint_encode(buf, sizeof(buf), 37);
    check("encode 37", n == 1 && buf[0] == 37);
    n = cip_varint_decode(buf, n, &val);
    check("decode 37", n == 1 && val == 37);

    /* 1-byte: value 63 (max 1-byte) */
    n = cip_varint_encode(buf, sizeof(buf), 63);
    check("encode 63", n == 1 && (buf[0] & 0x3f) == 63);

    /* 2-byte: value 64 */
    n = cip_varint_encode(buf, sizeof(buf), 64);
    check("encode 64", n == 2);
    n = cip_varint_decode(buf, n, &val);
    check("decode 64", n == 2 && val == 64);

    /* 2-byte: value 16383 (max 2-byte) */
    n = cip_varint_encode(buf, sizeof(buf), 16383);
    check("encode 16383", n == 2);
    n = cip_varint_decode(buf, n, &val);
    check("decode 16383", n == 2 && val == 16383);

    /* 4-byte: value 1073741823 (max 4-byte) */
    n = cip_varint_encode(buf, sizeof(buf), 1073741823);
    check("encode 1073741823", n == 4);
    n = cip_varint_decode(buf, n, &val);
    check("decode 1073741823", n == 4 && val == 1073741823);

    /* Empty buffer */
    n = cip_varint_decode(buf, 0, &val);
    check("decode empty fails", n == 0);
}

static void test_ipv4_checksum(void) {
    printf("\n--- IPv4 Checksum ---\n");

    /* Standard IPv4 header: src=10.0.0.1, dst=10.0.0.2, TTL=64, proto=6 */
    uint8_t hdr[20] = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02
    };

    uint16_t cksum = cip_ipv4_checksum(hdr);
    check("checksum non-zero", cksum != 0);

    /* Set the checksum in the header */
    hdr[10] = (uint8_t)(cksum >> 8);
    hdr[11] = (uint8_t)(cksum & 0xff);

    /* Verify: sum all 16-bit words of the entire header.
       One's complement sum should equal 0xffff. */
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) {
        sum += ((uint16_t)hdr[i] << 8) | hdr[i + 1];
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    check("checksum verifies to 0xffff", (uint16_t)sum == 0xffff);
}

static void test_compose_datagram_ipv4(void) {
    printf("\n--- Compose Datagram (IPv4) ---\n");

    /* Fake IPv4 packet: src=10.0.0.1, dst=8.8.8.8, TTL=64, proto=6(TCP) */
    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;               /* Version=4, IHL=5 */
    pkt[2] = 0x00; pkt[3] = 40;  /* Total Length = 40 */
    pkt[8] = 64;                  /* TTL = 64 */
    pkt[9] = 6;                   /* Protocol = TCP */
    pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1;
    pkt[16] = 8;  pkt[17] = 8; pkt[18] = 8; pkt[19] = 8;

    uint8_t out[64];
    size_t out_len = 0;
    int rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 40);
    check("compose ipv4 ok", rc == CIP_OK);
    check("compose ipv4 length", out_len == 41);
    check("context id is 0x00", out[0] == 0x00);
    check("ttl decremented", pkt[8] == 63);
    check("ip data copied", memcmp(out + 1, pkt, 40) == 0);
}

static void test_compose_datagram_ipv6(void) {
    printf("\n--- Compose Datagram (IPv6) ---\n");

    uint8_t pkt[60];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;               /* Version=6 */
    pkt[7] = 128;                /* Hop Limit = 128 */

    uint8_t out[80];
    size_t out_len = 0;
    int rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 60);
    check("compose ipv6 ok", rc == CIP_OK);
    check("compose ipv6 length", out_len == 61);
    check("context id is 0x00", out[0] == 0x00);
    check("hop limit decremented", pkt[7] == 127);
}

static void test_compose_datagram_errors(void) {
    printf("\n--- Compose Datagram Errors ---\n");

    uint8_t out[64];
    size_t out_len = 0;

    /* Empty packet */
    int rc = cip_compose_datagram(out, sizeof(out), &out_len, NULL, 0);
    check("empty packet rejected", rc == CIP_ERR_EMPTY);

    /* TTL = 1 */
    uint8_t pkt[20] = {0};
    pkt[0] = 0x45;
    pkt[8] = 1;
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 20);
    check("ttl=1 rejected", rc == CIP_ERR_TTL);

    /* TTL = 0 */
    pkt[8] = 0;
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 20);
    check("ttl=0 rejected", rc == CIP_ERR_TTL);

    /* Too short */
    pkt[8] = 64;
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 10);
    check("too short rejected", rc == CIP_ERR_TOO_SHORT);

    /* Bad version */
    pkt[0] = 0x30;
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt, 20);
    check("bad version rejected", rc == CIP_ERR_BAD_VER);

    /* Buffer too small */
    pkt[0] = 0x45;
    rc = cip_compose_datagram(out, 5, &out_len, pkt, 20);
    check("buffer overflow rejected", rc == CIP_ERR_OVERFLOW);
}

static void test_parse_datagram(void) {
    printf("\n--- Parse Datagram ---\n");

    /* Build a valid datagram: Context ID 0 + IPv4 packet */
    uint8_t dg[41];
    dg[0] = 0x00;  /* Context ID 0 */
    memset(dg + 1, 0, 40);
    dg[1] = 0x45;  /* IPv4 */

    const uint8_t *ip_pkt = NULL;
    size_t ip_len = 0;
    int rc = cip_parse_datagram(dg, sizeof(dg), &ip_pkt, &ip_len);
    check("parse ipv4 ok", rc == CIP_OK);
    check("parse ipv4 ptr", ip_pkt == dg + 1);
    check("parse ipv4 len", ip_len == 40);

    /* Non-zero context ID should be rejected */
    dg[0] = 0x01;  /* Context ID 1 */
    rc = cip_parse_datagram(dg, sizeof(dg), &ip_pkt, &ip_len);
    check("non-zero ctx rejected", rc == CIP_ERR_CTX_ID);

    /* Empty datagram */
    rc = cip_parse_datagram(dg, 0, &ip_pkt, &ip_len);
    check("empty rejected", rc == CIP_ERR_EMPTY);
}

static void test_icmp_too_big_ipv4(void) {
    printf("\n--- ICMP Too Big (IPv4) ---\n");

    /* Fake IPv4 packet */
    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1;   /* src */
    pkt[16] = 8;  pkt[17] = 8; pkt[18] = 8; pkt[19] = 8;    /* dst */

    uint8_t out[128];
    size_t out_len = 0;
    int rc = cip_compose_icmp_too_big(out, sizeof(out), &out_len, pkt, 40, 1280);
    check("icmp v4 ok", rc == CIP_OK);
    check("icmp v4 total len", out_len == 20 + 8 + 28);  /* IP hdr + ICMP hdr + 28 bytes orig */
    check("icmp v4 type=3", out[20] == 3);
    check("icmp v4 code=4", out[21] == 4);
    /* Source/dest IPs swapped */
    check("icmp v4 src=orig dst", out[12] == 8 && out[13] == 8 && out[14] == 8 && out[15] == 8);
    check("icmp v4 dst=orig src", out[16] == 10 && out[17] == 0 && out[18] == 0 && out[19] == 1);
}

static void test_icmp_too_big_ipv6(void) {
    printf("\n--- ICMP Too Big (IPv6) ---\n");

    uint8_t pkt[60];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;               /* Version=6 */
    pkt[6] = 6;                  /* Next Header = TCP */
    pkt[7] = 64;                 /* Hop Limit */
    /* src = fd00::1 */
    pkt[8] = 0xfd; pkt[9] = 0;
    pkt[23] = 1;
    /* dst = 2001:db8::1 */
    pkt[24] = 0x20; pkt[25] = 0x01; pkt[26] = 0x0d; pkt[27] = 0xb8;
    pkt[39] = 1;

    uint8_t out[1400];
    size_t out_len = 0;
    int rc = cip_compose_icmp_too_big(out, sizeof(out), &out_len, pkt, 60, 1280);
    check("icmp v6 ok", rc == CIP_OK);
    check("icmp v6 type=2", out[40] == 2);
    check("icmp v6 code=0", out[41] == 0);
    /* Source/dest swapped */
    check("icmp v6 src starts with 2001", out[8] == 0x20 && out[9] == 0x01);
    check("icmp v6 dst starts with fd00", out[24] == 0xfd && out[25] == 0);
}

static void test_noise_packet(void) {
    printf("\n--- Noise Packet ---\n");

    uint8_t out[512];
    size_t out_len = 0;
    srand(42);
    int rc = cip_compose_noise_packet(out, sizeof(out), &out_len, 100);
    check("noise ok", rc == CIP_OK);
    check("noise length", out_len == 20 + 100);
    check("noise version=4", (out[0] >> 4) == 4);
    check("noise ttl=64", out[8] == 64);
    check("noise proto=0xff", out[9] == 0xFF);
    check("noise src=172.16.0.1", out[12] == 172 && out[13] == 16 && out[14] == 0 && out[15] == 1);
    check("noise dst=192.0.2.x", out[16] == 192 && out[17] == 0 && out[18] == 2);
}

static void test_structural_validation(void) {
    printf("\n--- Structural Validation ---\n");

    uint8_t out[128];
    size_t out_len = 0;
    int rc;

    /* --- Compose side --- */

    /* IPv4 IHL too small (IHL=3 means 12 bytes, less than 20) */
    uint8_t pkt4[40];
    memset(pkt4, 0, sizeof(pkt4));
    pkt4[0] = 0x43;  /* Version=4, IHL=3 */
    pkt4[2] = 0; pkt4[3] = 40;
    pkt4[8] = 64;
    pkt4[9] = 6;
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt4, 40);
    check("compose: IHL<5 rejected", rc == CIP_ERR_TOO_SHORT);

    /* IPv4 IHL claims 40 bytes but packet is only 20 */
    memset(pkt4, 0, sizeof(pkt4));
    pkt4[0] = 0x4a;  /* Version=4, IHL=10 (40 bytes) */
    pkt4[2] = 0; pkt4[3] = 20;
    pkt4[8] = 64;
    pkt4[9] = 6;
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt4, 20);
    check("compose: IHL>pkt_len rejected", rc == CIP_ERR_TOO_SHORT);

    /* IPv4 Total Length claims more than actual */
    memset(pkt4, 0, sizeof(pkt4));
    pkt4[0] = 0x45;  /* IHL=5 */
    pkt4[2] = 0; pkt4[3] = 60;  /* Total Length = 60 but pkt_len = 40 */
    pkt4[8] = 64;
    pkt4[9] = 6;
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt4, 40);
    check("compose: TotalLen>pkt_len rejected", rc == CIP_ERR_TOO_SHORT);

    /* IPv6 Payload Length claims more than actual */
    uint8_t pkt6[60];
    memset(pkt6, 0, sizeof(pkt6));
    pkt6[0] = 0x60;
    pkt6[4] = 0; pkt6[5] = 40;  /* Payload Length = 40 but payload area = 20 */
    pkt6[7] = 64;
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt6, 60);
    check("compose: v6 PayloadLen>actual rejected", rc == CIP_ERR_TOO_SHORT);

    /* Valid IPv4 with options (IHL=6, 24 bytes header, 40 total) */
    memset(pkt4, 0, sizeof(pkt4));
    pkt4[0] = 0x46;  /* Version=4, IHL=6 (24 bytes) */
    pkt4[2] = 0; pkt4[3] = 40;
    pkt4[8] = 64;
    pkt4[9] = 6;
    rc = cip_compose_datagram(out, sizeof(out), &out_len, pkt4, 40);
    check("compose: IHL=6 valid", rc == CIP_OK);

    /* --- Parse side --- */

    /* Parse: IPv4 IHL too small */
    uint8_t dg[64];
    dg[0] = 0x00;
    memset(dg + 1, 0, 40);
    dg[1] = 0x43;  /* IHL=3 */
    dg[3] = 0; dg[4] = 40;  /* Total Length = 40 */
    dg[9] = 64;
    const uint8_t *ip_pkt;
    size_t ip_len;
    rc = cip_parse_datagram(dg, 41, &ip_pkt, &ip_len);
    check("parse: IHL<5 rejected", rc == CIP_ERR_TOO_SHORT);

    /* Parse: IPv4 Total Length > remaining */
    dg[1] = 0x45;
    dg[3] = 0; dg[4] = 60;  /* Total Length = 60 but remaining = 40 */
    rc = cip_parse_datagram(dg, 41, &ip_pkt, &ip_len);
    check("parse: TotalLen>remaining rejected", rc == CIP_ERR_TOO_SHORT);

    /* Parse: IPv6 Payload Length > remaining */
    uint8_t dg6[61];
    dg6[0] = 0x00;
    memset(dg6 + 1, 0, 60);
    dg6[1] = 0x60;
    dg6[5] = 40;  /* Payload Length = 40 but payload = 20 */
    dg6[7] = 64;
    rc = cip_parse_datagram(dg6, 61, &ip_pkt, &ip_len);
    check("parse: v6 PayloadLen>remaining rejected", rc == CIP_ERR_TOO_SHORT);

    /* Parse: valid IPv4 */
    dg[1] = 0x45;
    dg[3] = 0; dg[4] = 40;  /* Total Length = 40 */
    dg[9] = 64;
    rc = cip_parse_datagram(dg, 41, &ip_pkt, &ip_len);
    check("parse: valid ipv4 ok", rc == CIP_OK);
}

static void test_roundtrip(void) {
    printf("\n--- Compose → Parse Roundtrip ---\n");

    /* IPv4 packet */
    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;  /* Total Length = 40 */
    pkt[8] = 64;
    pkt[9] = 17; /* UDP */
    pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1;
    pkt[16] = 1;  pkt[17] = 1; pkt[18] = 1; pkt[19] = 1;

    /* Save original for comparison (compose modifies TTL in-place) */
    uint8_t orig[40];
    memcpy(orig, pkt, 40);

    uint8_t dg[64];
    size_t dg_len = 0;
    int rc = cip_compose_datagram(dg, sizeof(dg), &dg_len, pkt, 40);
    check("roundtrip compose ok", rc == CIP_OK);

    const uint8_t *ip_pkt = NULL;
    size_t ip_len = 0;
    rc = cip_parse_datagram(dg, dg_len, &ip_pkt, &ip_len);
    check("roundtrip parse ok", rc == CIP_OK);
    check("roundtrip ip_len", ip_len == 40);
    /* TTL should have been decremented by compose */
    check("roundtrip ttl decremented", ip_pkt[8] == 63);
    /* Rest of the packet should be intact */
    check("roundtrip src preserved", ip_pkt[12] == 10 && ip_pkt[15] == 1);
    check("roundtrip dst preserved", ip_pkt[16] == 1 && ip_pkt[19] == 1);
}

int main(void) {
    test_varint();
    test_ipv4_checksum();
    test_compose_datagram_ipv4();
    test_compose_datagram_ipv6();
    test_compose_datagram_errors();
    test_parse_datagram();
    test_icmp_too_big_ipv4();
    test_icmp_too_big_ipv6();
    test_noise_packet();
    test_structural_validation();
    test_roundtrip();

    if (failures > 0) {
        printf("\n%d tests FAILED\n", failures);
        return 1;
    }
    printf("\nAll connect-ip tests passed\n");
    return 0;
}
