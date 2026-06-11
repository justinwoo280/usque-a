#ifndef USQUE_ROUTE_LINUX_H
#define USQUE_ROUTE_LINUX_H

#ifdef __cplusplus
extern "C" {
#endif

#define USQUE_ROUTE_TABLE_TUNNEL 2022
#define USQUE_ROUTE_RULE_PRIORITY 9000

/* Setup policy routing: tunnel table + ip rule + endpoint bypass.
 * tun_name: TUN device name
 * endpoint_v4: WARP endpoint IPv4 (for bypass route)
 * dns_servers: array of DNS server IPs (NULL-terminated)
 * dns_count: number of DNS servers
 * Returns 0 on success, -1 on error. */
int usque_route_setup(const char *tun_name,
                      const char *endpoint_v4,
                      const char *const *dns_servers,
                      int dns_count,
                      char *errbuf, int errbuf_len);

/* Cleanup all routes, rules, and DNS configuration. */
int usque_route_cleanup(const char *tun_name,
                        char *errbuf, int errbuf_len);

/* Bind a UDP socket fd to a specific network interface by name.
 * Uses SO_BINDTODEVICE. Returns 0 on success. */
int usque_route_bind_to_device(int fd, const char *ifname,
                               char *errbuf, int errbuf_len);

/* Detect the best physical network interface name.
 * Writes the name into buf (max buflen chars).
 * Returns 0 on success, -1 if no suitable interface found. */
int usque_route_detect_physical_iface(char *buf, int buflen);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_ROUTE_LINUX_H */
