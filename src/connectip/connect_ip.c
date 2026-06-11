#include "connect_ip.h"

#include <string.h>
#include <stdlib.h>

/* ---- QUIC Variable-Length Integer (RFC 9000 §16) ---- */

int cip_varint_encode(uint8_t *buf, size_t buflen, uint64_t value) {
    if (value <= 63) {
        if (buflen < 1) return 0;
        buf[0] = (uint8_t)value;
        return 1;
    }
    if (value <= 16383) {
        if (buflen < 2) return 0;
        buf[0] = (uint8_t)(0x40 | (value >> 8));
        buf[1] = (uint8_t)(value & 0xff);
        return 2;
    }
    if (value <= 1073741823) {
        if (buflen < 4) return 0;
        buf[0] = (uint8_t)(0x80 | (value >> 24));
        buf[1] = (uint8_t)((value >> 16) & 0xff);
        buf[2] = (uint8_t)((value >> 8) & 0xff);
        buf[3] = (uint8_t)(value & 0xff);
        return 4;
    }
    if (value <= 4611686018427387903ULL) {
        if (buflen < 8) return 0;
        buf[0] = (uint8_t)(0xc0 | (value >> 56));
        buf[1] = (uint8_t)((value >> 48) & 0xff);
        buf[2] = (uint8_t)((value >> 40) & 0xff);
        buf[3] = (uint8_t)((value >> 32) & 0xff);
        buf[4] = (uint8_t)((value >> 24) & 0xff);
        buf[5] = (uint8_t)((value >> 16) & 0xff);
        buf[6] = (uint8_t)((value >> 8) & 0xff);
        buf[7] = (uint8_t)(value & 0xff);
        return 8;
    }
    return 0;
}

int cip_varint_decode(const uint8_t *buf, size_t buflen, uint64_t *value) {
    if (buflen == 0) return 0;
    int prefix = buf[0] >> 6;
    int n = 1 << prefix;
    if ((int)buflen < n) return 0;
    uint64_t v = buf[0] & 0x3f;
    for (int i = 1; i < n; i++) {
        v = (v << 8) | buf[i];
    }
    *value = v;
    return n;
}

/* ---- IPv4 Header Checksum (RFC 1071) ---- */

uint16_t cip_ipv4_checksum(const uint8_t *header) {
    uint32_t sum = 0;
    for (int i = 0; i < CIP_IPV4_HDR_LEN; i += 2) {
        if (i == 10) continue;
        sum += ((uint16_t)header[i] << 8) | header[i + 1];
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint8_t ip_version(const uint8_t *pkt) {
    return pkt[0] >> 4;
}

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void write_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

/* ---- Datagram Compose (TUN → QUIC) ---- */

int cip_compose_datagram(uint8_t *out, size_t out_buflen, size_t *out_len,
                         uint8_t *pkt, size_t pkt_len) {
    if (pkt_len == 0) return CIP_ERR_EMPTY;

    uint8_t ver = ip_version(pkt);

    switch (ver) {
    case 4:
        if (pkt_len < CIP_IPV4_HDR_LEN) return CIP_ERR_TOO_SHORT;
        {
            /* IHL is in 32-bit words; minimum valid IHL is 5 (= 20 bytes) */
            uint8_t ihl = pkt[0] & 0x0f;
            size_t hdr_len = (size_t)ihl * 4;
            if (hdr_len < CIP_IPV4_HDR_LEN || hdr_len > pkt_len)
                return CIP_ERR_TOO_SHORT;
            /* Total Length must not claim more than what we have */
            uint16_t total_len = read_be16(pkt + 2);
            if (total_len > pkt_len)
                return CIP_ERR_TOO_SHORT;
        }
        if (pkt[8] <= 1) return CIP_ERR_TTL;
        pkt[8]--;
        write_be16(pkt + 10, cip_ipv4_checksum(pkt));
        break;
    case 6:
        if (pkt_len < CIP_IPV6_HDR_LEN) return CIP_ERR_TOO_SHORT;
        {
            /* Payload Length + fixed 40-byte header must not exceed pkt_len */
            uint16_t payload_len = read_be16(pkt + 4);
            if ((size_t)payload_len + CIP_IPV6_HDR_LEN > pkt_len)
                return CIP_ERR_TOO_SHORT;
        }
        if (pkt[7] <= 1) return CIP_ERR_TTL;
        pkt[7]--;
        break;
    default:
        return CIP_ERR_BAD_VER;
    }

    /* Context ID 0 = single byte 0x00 (QUIC varint) */
    size_t needed = 1 + pkt_len;
    if (out_buflen < needed) return CIP_ERR_OVERFLOW;

    out[0] = 0x00;
    memcpy(out + 1, pkt, pkt_len);
    *out_len = needed;
    return CIP_OK;
}

/* ---- Datagram Parse (QUIC → TUN) ---- */

int cip_parse_datagram(const uint8_t *datagram, size_t datagram_len,
                       const uint8_t **ip_pkt, size_t *ip_len) {
    if (datagram_len == 0) return CIP_ERR_EMPTY;

    uint64_t ctx_id;
    int n = cip_varint_decode(datagram, datagram_len, &ctx_id);
    if (n == 0) return CIP_ERR_TOO_SHORT;
    if (ctx_id != 0) return CIP_ERR_CTX_ID;

    size_t remaining = datagram_len - (size_t)n;
    if (remaining == 0) return CIP_ERR_EMPTY;

    uint8_t ver = ip_version(datagram + n);
    if (ver != 4 && ver != 6) return CIP_ERR_BAD_VER;

    const uint8_t *ip = datagram + n;

    if (ver == 4) {
        if (remaining < CIP_IPV4_HDR_LEN) return CIP_ERR_TOO_SHORT;
        uint8_t ihl = ip[0] & 0x0f;
        size_t hdr_len = (size_t)ihl * 4;
        if (hdr_len < CIP_IPV4_HDR_LEN || hdr_len > remaining)
            return CIP_ERR_TOO_SHORT;
        uint16_t total_len = read_be16(ip + 2);
        if (total_len > remaining)
            return CIP_ERR_TOO_SHORT;
    } else {
        if (remaining < CIP_IPV6_HDR_LEN) return CIP_ERR_TOO_SHORT;
        uint16_t payload_len = read_be16(ip + 4);
        if ((size_t)payload_len + CIP_IPV6_HDR_LEN > remaining)
            return CIP_ERR_TOO_SHORT;
    }

    *ip_pkt = ip;
    *ip_len = remaining;
    return CIP_OK;
}

/* ---- ICMP Checksum (same algorithm as IPv4, over ICMP header+data) ---- */

static uint16_t icmp_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)data[i] << 8) | data[i + 1];
    }
    if (len & 1) {
        sum += (uint16_t)data[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* ICMPv6 pseudo-header checksum contribution */
static uint32_t ipv6_pseudo_header_sum(const uint8_t *src, const uint8_t *dst,
                                       uint16_t payload_len) {
    uint32_t sum = 0;
    for (int i = 0; i < 16; i += 2) {
        sum += ((uint16_t)src[i] << 8) | src[i + 1];
        sum += ((uint16_t)dst[i] << 8) | dst[i + 1];
    }
    sum += payload_len;       /* upper-layer packet length */
    sum += 58;                /* next header = ICMPv6 */
    return sum;
}

/* ---- ICMP Packet Too Big ---- */

int cip_compose_icmp_too_big(uint8_t *out, size_t out_buflen, size_t *out_len,
                             const uint8_t *pkt, size_t pkt_len, int mtu) {
    if (pkt_len == 0) return CIP_ERR_EMPTY;

    uint8_t ver = ip_version(pkt);

    if (ver == 4) {
        if (pkt_len < CIP_IPV4_HDR_LEN) return CIP_ERR_TOO_SHORT;

        size_t orig_copy = pkt_len < (size_t)(CIP_IPV4_HDR_LEN + 8) ?
                           pkt_len : (size_t)(CIP_IPV4_HDR_LEN + 8);
        /* ICMPv4: type(1) + code(1) + checksum(2) + unused(2) + mtu(2) + orig_data */
        size_t icmp_len = 8 + orig_copy;
        size_t total = CIP_IPV4_HDR_LEN + icmp_len;
        if (out_buflen < total) return CIP_ERR_OVERFLOW;

        /* Build ICMP body first (for checksum) */
        uint8_t icmp_body[8];
        icmp_body[0] = 3;    /* Type: Destination Unreachable */
        icmp_body[1] = 4;    /* Code: Fragmentation Needed */
        icmp_body[2] = 0;    /* Checksum placeholder */
        icmp_body[3] = 0;
        icmp_body[4] = 0;    /* Unused */
        icmp_body[5] = 0;
        write_be16(icmp_body + 6, (uint16_t)mtu);

        /* Compute ICMP checksum over header + original data */
        uint32_t sum = 0;
        for (size_t i = 0; i + 1 < 8; i += 2) {
            sum += ((uint16_t)icmp_body[i] << 8) | icmp_body[i + 1];
        }
        for (size_t i = 0; i + 1 < orig_copy; i += 2) {
            sum += ((uint16_t)pkt[i] << 8) | pkt[i + 1];
        }
        if (orig_copy & 1) {
            sum += (uint16_t)pkt[orig_copy - 1] << 8;
        }
        while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        uint16_t cksum = (uint16_t)(~sum);
        write_be16(icmp_body + 2, cksum);

        /* Write IP header */
        uint8_t *hdr = out;
        memset(hdr, 0, CIP_IPV4_HDR_LEN);
        hdr[0] = 0x45;                          /* Version=4, IHL=5 */
        write_be16(hdr + 2, (uint16_t)total);   /* Total Length */
        hdr[8] = 64;                            /* TTL */
        hdr[9] = 1;                             /* Protocol: ICMP */
        memcpy(hdr + 12, pkt + 16, 4);          /* Src = original dst */
        memcpy(hdr + 16, pkt + 12, 4);          /* Dst = original src */
        write_be16(hdr + 10, cip_ipv4_checksum(hdr));

        /* Write ICMP */
        memcpy(out + CIP_IPV4_HDR_LEN, icmp_body, 8);
        memcpy(out + CIP_IPV4_HDR_LEN + 8, pkt, orig_copy);

        *out_len = total;
        return CIP_OK;
    }

    if (ver == 6) {
        if (pkt_len < CIP_IPV6_HDR_LEN) return CIP_ERR_TOO_SHORT;

        size_t orig_copy = pkt_len < 1232 ? pkt_len : 1232;
        /* ICMPv6: type(1) + code(1) + checksum(2) + mtu(4) + orig_data */
        size_t icmp_len = 8 + orig_copy;
        size_t total = CIP_IPV6_HDR_LEN + icmp_len;
        if (out_buflen < total) return CIP_ERR_OVERFLOW;

        /* Build ICMPv6 body (checksum placeholder = 0) */
        uint8_t *icmp_start = out + CIP_IPV6_HDR_LEN;
        icmp_start[0] = 2;    /* Type: Packet Too Big */
        icmp_start[1] = 0;    /* Code */
        icmp_start[2] = 0;    /* Checksum placeholder */
        icmp_start[3] = 0;
        write_be32(icmp_start + 4, (uint32_t)mtu);
        memcpy(icmp_start + 8, pkt, orig_copy);

        /* Compute ICMPv6 checksum with pseudo-header */
        /* pseudo-header: src(16) + dst(16) + length(4) + next_header(4) */
        const uint8_t *orig_src = pkt + 8;   /* original src */
        const uint8_t *orig_dst = pkt + 24;  /* original dst */

        uint32_t sum = ipv6_pseudo_header_sum(orig_dst, orig_src, (uint16_t)icmp_len);
        for (size_t i = 0; i + 1 < icmp_len; i += 2) {
            sum += ((uint16_t)icmp_start[i] << 8) | icmp_start[i + 1];
        }
        if (icmp_len & 1) {
            sum += (uint16_t)icmp_start[icmp_len - 1] << 8;
        }
        while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        write_be16(icmp_start + 2, (uint16_t)(~sum));

        /* Write IPv6 header */
        uint8_t *hdr = out;
        memset(hdr, 0, CIP_IPV6_HDR_LEN);
        hdr[0] = 0x60;                          /* Version=6 */
        write_be16(hdr + 4, (uint16_t)icmp_len); /* Payload Length */
        hdr[6] = 58;                            /* Next Header: ICMPv6 */
        hdr[7] = 64;                            /* Hop Limit */
        memcpy(hdr + 8, orig_dst, 16);          /* Src = original dst */
        memcpy(hdr + 24, orig_src, 16);         /* Dst = original src */

        *out_len = total;
        return CIP_OK;
    }

    return CIP_ERR_BAD_VER;
}

/* ---- Noise Packet ---- */

int cip_compose_noise_packet(uint8_t *out, size_t out_buflen, size_t *out_len,
                             size_t payload_size) {
    size_t total = CIP_IPV4_HDR_LEN + payload_size;
    if (out_buflen < total) return CIP_ERR_OVERFLOW;

    uint8_t *hdr = out;
    memset(hdr, 0, CIP_IPV4_HDR_LEN);
    hdr[0] = 0x45;                           /* Version=4, IHL=5 */
    write_be16(hdr + 2, (uint16_t)total);    /* Total Length */
    /* ID + Flags+Fragment: fill with random 4 bytes */
    uint32_t rand_id = (uint32_t)rand();
    hdr[4] = (uint8_t)(rand_id >> 24);
    hdr[5] = (uint8_t)(rand_id >> 16);
    hdr[6] = (uint8_t)(rand_id >> 8);
    hdr[7] = (uint8_t)(rand_id);
    hdr[8] = 64;                             /* TTL */
    hdr[9] = 0xFF;                           /* Protocol: reserved/experimental */
    /* Source: 172.16.0.1 */
    hdr[12] = 172; hdr[13] = 16; hdr[14] = 0; hdr[15] = 1;
    /* Dest: 192.0.2.<random> (TEST-NET-1, RFC 5737) */
    hdr[16] = 192; hdr[17] = 0; hdr[18] = 2; hdr[19] = (uint8_t)(rand() & 0xff);
    write_be16(hdr + 10, cip_ipv4_checksum(hdr));

    /* Random payload */
    for (size_t i = 0; i < payload_size; i++) {
        out[CIP_IPV4_HDR_LEN + i] = (uint8_t)(rand() & 0xff);
    }

    *out_len = total;
    return CIP_OK;
}
