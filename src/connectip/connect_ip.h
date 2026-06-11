#ifndef CONNECT_IP_H
#define CONNECT_IP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CIP_IPV4_HDR_LEN 20
#define CIP_IPV6_HDR_LEN 40
#define CIP_MIN_MTU      1280

/* Return codes */
#define CIP_OK              0
#define CIP_ERR_EMPTY      -1
#define CIP_ERR_TOO_SHORT  -2
#define CIP_ERR_BAD_VER    -3
#define CIP_ERR_TTL        -4
#define CIP_ERR_CTX_ID     -5
#define CIP_ERR_OVERFLOW   -6

/* ---- QUIC Variable-Length Integer (RFC 9000 §16) ---- */

/* Encode value as QUIC varint into buf. Returns bytes written (1,2,4,8) or 0 on overflow. */
int cip_varint_encode(uint8_t *buf, size_t buflen, uint64_t value);

/* Decode QUIC varint from buf. Returns bytes consumed, or 0 on error.
   Sets *value to the decoded integer. */
int cip_varint_decode(const uint8_t *buf, size_t buflen, uint64_t *value);

/* ---- IPv4 Header Checksum (RFC 1071) ---- */

/* Calculate IPv4 header checksum over a 20-byte header, skipping bytes [10:12]. */
uint16_t cip_ipv4_checksum(const uint8_t *header);

/* ---- Datagram Compose (TUN → QUIC) ----
 *
 * Takes a raw IP packet, decrements TTL/Hop Limit, recalculates IPv4
 * checksum if needed, and prepends Context ID 0 (QUIC varint).
 *
 * The IP packet in pkt[] is modified in-place (TTL--, checksum).
 * The output datagram is written to out[].
 *
 * Returns CIP_OK on success, writing *out_len bytes to out[].
 * Returns negative error code on failure (pkt is NOT modified on error).
 */
int cip_compose_datagram(uint8_t *out, size_t out_buflen, size_t *out_len,
                         uint8_t *pkt, size_t pkt_len);

/* ---- Datagram Parse (QUIC → TUN) ----
 *
 * Strips the Context ID varint prefix from a received QUIC DATAGRAM.
 * Only Context ID 0 is accepted (IP proxying). Non-zero IDs return CIP_ERR_CTX_ID.
 *
 * The IP packet starts at datagram[cip_varint_len..]. This function does NOT
 * copy the packet — it returns a pointer into the input buffer.
 *
 * Sets *ip_pkt to point at the IP packet within datagram[].
 * Sets *ip_len to the IP packet length.
 *
 * Returns CIP_OK on success, negative error code on failure.
 */
int cip_parse_datagram(const uint8_t *datagram, size_t datagram_len,
                       const uint8_t **ip_pkt, size_t *ip_len);

/* ---- ICMP Packet Too Big Generation ----
 *
 * Generates an ICMP "Packet Too Big" / "Fragmentation Needed" response
 * for the given IP packet. Source/dest IPs are swapped.
 *
 * For IPv4: Type 3, Code 4, includes first min(pkt_len, 28) bytes of original.
 * For IPv6: Type 2, Code 0, includes first min(pkt_len, 1232) bytes of original.
 *
 * Output is written to out[]. *out_len is set to the ICMP packet length.
 * Returns CIP_OK on success, negative error code on failure.
 */
int cip_compose_icmp_too_big(uint8_t *out, size_t out_buflen, size_t *out_len,
                             const uint8_t *pkt, size_t pkt_len, int mtu);

/* ---- Noise Packet Composition ----
 *
 * Builds a fake IPv4 packet for noise injection (traffic obfuscation).
 * src = 172.16.0.1, dst = 192.0.2.<random>, protocol = 0xFF, TTL = 64.
 * Payload is random bytes.
 *
 * Output is written to out[]. *out_len is set to the packet length.
 * Returns CIP_OK on success.
 */
int cip_compose_noise_packet(uint8_t *out, size_t out_buflen, size_t *out_len,
                             size_t payload_size);

#ifdef __cplusplus
}
#endif

#endif /* CONNECT_IP_H */
