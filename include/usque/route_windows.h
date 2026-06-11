#ifndef USQUE_ROUTE_WINDOWS_H
#define USQUE_ROUTE_WINDOWS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Setup routes on Windows: default route via TUN + endpoint bypass.
 * luid: TUN adapter LUID (from usque_tun_luid)
 * endpoint_v4: WARP server IP
 * dns_servers: DNS server IPs
 * dns_count: number of DNS servers
 * Returns 0 on success. */
int usque_route_setup_windows(uint64_t luid,
                              const char *endpoint_v4,
                              const char *const *dns_servers,
                              int dns_count,
                              char *errbuf, int errbuf_len);

/* Cleanup routes. */
int usque_route_cleanup_windows(uint64_t luid,
                                char *errbuf, int errbuf_len);

/* Bind a UDP socket to a specific interface by LUID index.
 * Uses IP_UNICAST_IF / IPV6_UNICAST_IF. */
int usque_route_bind_to_device_windows(int fd, uint64_t luid,
                                       char *errbuf, int errbuf_len);

/* Detect the best physical interface LUID.
 * Returns the LUID as uint64, or 0 on failure. */
uint64_t usque_route_detect_physical_luid(void);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_ROUTE_WINDOWS_H */
