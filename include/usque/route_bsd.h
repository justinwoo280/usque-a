#ifndef USQUE_ROUTE_DARWIN_H
#define USQUE_ROUTE_DARWIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Setup routes on macOS: two /1 halves + endpoint bypass.
 * Uses 'route' command and 'networksetup' for DNS.
 * tun_name: TUN device name
 * endpoint_v4: WARP server IP
 * Returns 0 on success. */
int usque_route_setup_bsd(const char *tun_name,
                          const char *endpoint_v4,
                          const char *const *dns_servers,
                          int dns_count,
                          char *errbuf, int errbuf_len);

int usque_route_cleanup_bsd(const char *tun_name,
                            char *errbuf, int errbuf_len);

/* Bind UDP socket to interface by index (IP_BOUND_IF on macOS). */
int usque_route_bind_to_interface(int fd, const char *ifname,
                                  char *errbuf, int errbuf_len);

/* Detect best physical interface name. */
int usque_route_detect_physical_iface(char *buf, int buflen);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_ROUTE_DARWIN_H */
