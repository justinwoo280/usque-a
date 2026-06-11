#ifndef USQUE_DNS_HIJACK_H
#define USQUE_DNS_HIJACK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DNS hijack context.
 * hijack_v4: IPv4 DNS server to redirect queries to (e.g. "1.1.1.1"), empty to disable
 * hijack_v6: IPv6 DNS server to redirect queries to, empty to disable */
typedef struct usque_dns_hijack usque_dns_hijack_t;

usque_dns_hijack_t* usque_dns_hijack_create(const char *hijack_v4, const char *hijack_v6);
void usque_dns_hijack_destroy(usque_dns_hijack_t *ctx);

/* Rewrite outgoing DNS query: if packet is UDP dst port 53, replace dst IP
 * with the hijack target. Recalculates IP and UDP checksums.
 * Returns 1 if rewritten, 0 if not a DNS packet. Packet is modified in-place. */
int usque_dns_hijack_rewrite_query(usque_dns_hijack_t *ctx, uint8_t *pkt, int pkt_len);

/* Rewrite incoming DNS response: if packet is UDP src port 53 from the hijack
 * target, restore the original destination IP. Recalculates checksums.
 * Returns 1 if rewritten, 0 if not a DNS response. Packet is modified in-place. */
int usque_dns_hijack_rewrite_response(usque_dns_hijack_t *ctx, uint8_t *pkt, int pkt_len);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_DNS_HIJACK_H */
