#include "usque/dns_hijack.h"
#include "../connectip/connect_ip.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define DNS_HIJACK_MAX_PENDING 256

typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t orig_dst;
} pending_v4_t;

struct usque_dns_hijack {
    uint32_t hijack_v4;     /* network byte order, 0 = disabled */
    uint8_t  hijack_v6[16]; /* 0 = disabled */
    int      has_v6;

    pending_v4_t pending[DNS_HIJACK_MAX_PENDING];
    int          pending_count;
};

static uint16_t udp_checksum(const uint8_t *ip_hdr, const uint8_t *udp_hdr, int udp_len) {
    uint32_t sum = 0;

    /* Pseudo-header (IPv4) */
    sum += ((uint16_t)ip_hdr[12] << 8) | ip_hdr[13];  /* src IP */
    sum += ((uint16_t)ip_hdr[14] << 8) | ip_hdr[15];
    sum += ((uint16_t)ip_hdr[16] << 8) | ip_hdr[17];  /* dst IP */
    sum += ((uint16_t)ip_hdr[18] << 8) | ip_hdr[19];
    sum += 17;           /* protocol = UDP */
    sum += udp_len;      /* UDP length */

    /* UDP header + data */
    for (int i = 0; i + 1 < udp_len; i += 2) {
        sum += ((uint16_t)udp_hdr[i] << 8) | udp_hdr[i + 1];
    }
    if (udp_len & 1) {
        sum += (uint16_t)udp_hdr[udp_len - 1] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    uint16_t cksum = (uint16_t)(~sum);
    return cksum == 0 ? 0xffff : cksum;
}

usque_dns_hijack_t* usque_dns_hijack_create(const char *hijack_v4, const char *hijack_v6) {
    usque_dns_hijack_t *ctx = (usque_dns_hijack_t *)calloc(1, sizeof(usque_dns_hijack_t));
    if (!ctx) return NULL;

    if (hijack_v4 && hijack_v4[0]) {
        inet_pton(AF_INET, hijack_v4, &ctx->hijack_v4);
    }
    if (hijack_v6 && hijack_v6[0]) {
        inet_pton(AF_INET6, hijack_v6, ctx->hijack_v6);
        ctx->has_v6 = 1;
    }
    return ctx;
}

void usque_dns_hijack_destroy(usque_dns_hijack_t *ctx) {
    free(ctx);
}

int usque_dns_hijack_rewrite_query(usque_dns_hijack_t *ctx, uint8_t *pkt, int pkt_len) {
    if (!ctx || ctx->hijack_v4 == 0) return 0;
    if (pkt_len < 20) return 0;

    /* Only IPv4 */
    if ((pkt[0] >> 4) != 4) return 0;

    int ihl = (pkt[0] & 0x0f) * 4;
    if (ihl < 20 || pkt_len < ihl) return 0;

    /* Only UDP (protocol 17) */
    if (pkt[9] != 17) return 0;

    int total_len = ((int)pkt[2] << 8) | pkt[3];
    if (total_len > pkt_len) return 0;

    int udp_len = total_len - ihl;
    if (udp_len < 8) return 0;

    uint8_t *udp = pkt + ihl;
    uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];

    /* Only port 53 */
    if (dst_port != 53) return 0;

    /* Save mapping */
    uint32_t src_ip = ((uint32_t)pkt[12] << 24) | ((uint32_t)pkt[13] << 16) |
                      ((uint32_t)pkt[14] << 8) | pkt[15];
    uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
    uint32_t orig_dst = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                        ((uint32_t)pkt[18] << 8) | pkt[19];

    if (ctx->pending_count < DNS_HIJACK_MAX_PENDING) {
        pending_v4_t *p = &ctx->pending[ctx->pending_count++];
        p->src_ip = src_ip;
        p->src_port = src_port;
        p->orig_dst = orig_dst;
    }

    /* Rewrite destination IP (network byte order already) */
    memcpy(pkt + 16, &ctx->hijack_v4, 4);

    /* Recalculate IP header checksum */
    uint16_t ip_cksum = cip_ipv4_checksum(pkt);
    pkt[10] = (uint8_t)(ip_cksum >> 8);
    pkt[11] = (uint8_t)(ip_cksum & 0xff);

    /* Recalculate UDP checksum */
    udp[6] = 0; udp[7] = 0;  /* zero checksum field */
    uint16_t udp_cksum = udp_checksum(pkt, udp, udp_len);
    udp[6] = (uint8_t)(udp_cksum >> 8);
    udp[7] = (uint8_t)(udp_cksum & 0xff);

    return 1;
}

int usque_dns_hijack_rewrite_response(usque_dns_hijack_t *ctx, uint8_t *pkt, int pkt_len) {
    if (!ctx || ctx->hijack_v4 == 0) return 0;
    if (pkt_len < 20) return 0;
    if ((pkt[0] >> 4) != 4) return 0;

    int ihl = (pkt[0] & 0x0f) * 4;
    if (ihl < 20 || pkt_len < ihl) return 0;
    if (pkt[9] != 17) return 0;

    int total_len = ((int)pkt[2] << 8) | pkt[3];
    if (total_len > pkt_len) return 0;

    int udp_len = total_len - ihl;
    if (udp_len < 8) return 0;

    uint8_t *udp = pkt + ihl;
    uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];

    /* Only responses from port 53 */
    if (src_port != 53) return 0;

    /* Check if source IP matches our hijack target */
    if (memcmp(pkt + 12, &ctx->hijack_v4, 4) != 0) return 0;

    /* Look up the pending mapping by destination IP + port */
    uint32_t dst_ip = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                      ((uint32_t)pkt[18] << 8) | pkt[19];
    uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];

    for (int i = ctx->pending_count - 1; i >= 0; i--) {
        pending_v4_t *p = &ctx->pending[i];
        if (p->src_ip == dst_ip && p->src_port == dst_port) {
            /* Restore original source IP (= the original destination of the query) */
            pkt[12] = (uint8_t)(p->orig_dst >> 24);
            pkt[13] = (uint8_t)(p->orig_dst >> 16);
            pkt[14] = (uint8_t)(p->orig_dst >> 8);
            pkt[15] = (uint8_t)(p->orig_dst);

            /* Remove from pending */
            ctx->pending[i] = ctx->pending[--ctx->pending_count];

            /* Recalculate checksums */
            uint16_t ip_cksum = cip_ipv4_checksum(pkt);
            pkt[10] = (uint8_t)(ip_cksum >> 8);
            pkt[11] = (uint8_t)(ip_cksum & 0xff);

            udp[6] = 0; udp[7] = 0;
            uint16_t udp_cksum = udp_checksum(pkt, udp, udp_len);
            udp[6] = (uint8_t)(udp_cksum >> 8);
            udp[7] = (uint8_t)(udp_cksum & 0xff);

            return 1;
        }
    }
    return 0;
}
