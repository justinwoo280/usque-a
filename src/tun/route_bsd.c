#include "usque/route_bsd.h"

#if defined(__APPLE__) || defined(__FreeBSD__)

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>

#ifdef __APPLE__
#include <netinet/in.h>
/* IP_BOUND_IF for macOS */
#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif
#ifndef IPV6_BOUND_IF
#define IPV6_BOUND_IF 125
#endif
#endif

/* Discover default gateway IP and interface */
static int get_default_gateway(char *gw_ip, int gw_len, char *gw_iface, int iface_len) {
    FILE *fp = popen("route -n get default 2>/dev/null", "r");
    if (!fp) return -1;

    char line[256];
    int found_gw = 0, found_if = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p;
        if ((p = strstr(line, "gateway:")) != NULL) {
            p += 8;
            while (*p == ' ') p++;
            char *end = p;
            while (*end && *end != '\n' && *end != ' ') end++;
            int len = (int)(end - p);
            if (len >= gw_len) len = gw_len - 1;
            memcpy(gw_ip, p, (size_t)len);
            gw_ip[len] = '\0';
            found_gw = 1;
        }
        if ((p = strstr(line, "interface:")) != NULL) {
            p += 10;
            while (*p == ' ') p++;
            char *end = p;
            while (*end && *end != '\n' && *end != ' ') end++;
            int len = (int)(end - p);
            if (len >= iface_len) len = iface_len - 1;
            memcpy(gw_iface, p, (size_t)len);
            gw_iface[len] = '\0';
            found_if = 1;
        }
    }
    pclose(fp);
    return (found_gw && found_if) ? 0 : -1;
}

int usque_route_setup_bsd(const char *tun_name,
                          const char *endpoint_v4,
                          const char *const *dns_servers,
                          int dns_count,
                          char *errbuf, int errbuf_len) {
    char cmd[512];
    char gw_ip[64] = "", gw_iface[64] = "";

    /* Discover default gateway */
    if (get_default_gateway(gw_ip, sizeof(gw_ip), gw_iface, sizeof(gw_iface)) != 0) {
        snprintf(errbuf, errbuf_len, "cannot discover default gateway");
        return -1;
    }

    /* Endpoint bypass: route WARP server via physical gateway */
    if (endpoint_v4 && endpoint_v4[0]) {
        snprintf(cmd, sizeof(cmd),
                 "route add %s/32 %s", endpoint_v4, gw_ip);
        system(cmd);
    }

    /* Two /1 halves: override default route without deleting it */
    snprintf(cmd, sizeof(cmd), "route add 0.0.0.0/1 -interface %s", tun_name);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "route add 128.0.0.0/1 -interface %s", tun_name);
    system(cmd);

    /* IPv6: same approach */
    snprintf(cmd, sizeof(cmd), "route add -inet6 ::/1 -interface %s", tun_name);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "route add -inet6 8000::/1 -interface %s", tun_name);
    system(cmd);

    /* DNS configuration */
    if (dns_count > 0 && dns_servers) {
#ifdef __APPLE__
        /* Try networksetup first */
        char svc[128] = "";
        FILE *fp = popen("networksetup -listallnetworkservices 2>/dev/null", "r");
        if (fp) {
            char line[256];
            /* Skip header line */
            if (fgets(line, sizeof(line), fp)) {
                while (fgets(line, sizeof(line), fp)) {
                    if (line[0] == '*') continue;  /* disabled service */
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = '\0';

                    /* Check if this service has DNS configured */
                    char check[256];
                    snprintf(check, sizeof(check),
                             "networksetup -getdnsservers '%s' 2>/dev/null | grep -q .", line);
                    if (system(check) == 0) {
                        strncpy(svc, line, sizeof(svc) - 1);
                        break;
                    }
                }
            }
            pclose(fp);
        }

        if (svc[0]) {
            snprintf(cmd, sizeof(cmd), "networksetup -setdnsservers '%s'", svc);
            for (int i = 0; i < dns_count; i++) {
                char tmp[256];
                snprintf(tmp, sizeof(tmp), " %s", dns_servers[i]);
                strcat(cmd, tmp);
            }
            system(cmd);
            /* Flush DNS cache */
            system("dscacheutil -flushcache 2>/dev/null");
            system("killall -HUP mDNSResponder 2>/dev/null");
        } else
#endif
        {
            /* Fallback: resolv.conf */
            rename("/etc/resolv.conf", "/etc/resolv.conf.usque.bak");
            FILE *fp = fopen("/etc/resolv.conf", "w");
            if (fp) {
                for (int i = 0; i < dns_count; i++) {
                    fprintf(fp, "nameserver %s\n", dns_servers[i]);
                }
                fclose(fp);
            }
        }
    }

    return 0;
}

int usque_route_cleanup_bsd(const char *tun_name,
                            char *errbuf, int errbuf_len) {
    (void)errbuf; (void)errbuf_len;
    char cmd[256];

    /* Delete /1 routes */
    snprintf(cmd, sizeof(cmd), "route delete 0.0.0.0/1 -interface %s 2>/dev/null", tun_name);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "route delete 128.0.0.0/1 -interface %s 2>/dev/null", tun_name);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "route delete -inet6 ::/1 -interface %s 2>/dev/null", tun_name);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "route delete -inet6 8000::/1 -interface %s 2>/dev/null", tun_name);
    system(cmd);

#ifdef __APPLE__
    /* Reset DNS */
    system("dscacheutil -flushcache 2>/dev/null");
    system("killall -HUP mDNSResponder 2>/dev/null");
#endif

    /* Restore resolv.conf if backed up */
    rename("/etc/resolv.conf.usque.bak", "/etc/resolv.conf");

    return 0;
}

int usque_route_bind_to_interface(int fd, const char *ifname,
                                  char *errbuf, int errbuf_len) {
    unsigned int idx = if_nametoindex(ifname);
    if (idx == 0) {
        snprintf(errbuf, errbuf_len, "if_nametoindex(%s) failed", ifname);
        return -1;
    }

#ifdef __APPLE__
    /* macOS: IP_BOUND_IF / IPV6_BOUND_IF */
    if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx)) < 0) {
        snprintf(errbuf, errbuf_len, "IP_BOUND_IF: %s", strerror(errno));
        return -1;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx)) < 0) {
        /* Non-fatal */
    }
#elif defined(__FreeBSD__)
    /* FreeBSD: no IP_BOUND_IF, rely on endpoint bypass route only */
    (void)fd; (void)idx;
#endif

    return 0;
}

int usque_route_detect_physical_iface(char *buf, int buflen) {
    /* Use the default gateway's interface */
    char gw_ip[64], gw_iface[64];
    if (get_default_gateway(gw_ip, sizeof(gw_ip), gw_iface, sizeof(gw_iface)) == 0) {
        strncpy(buf, gw_iface, (size_t)(buflen - 1));
        buf[buflen - 1] = '\0';
        return 0;
    }

    /* Fallback: scan for common names */
    const char *candidates[] = {"en0", "en1", "em0", "igb0", "wlan0", NULL};
    for (int i = 0; candidates[i]; i++) {
        if (if_nametoindex(candidates[i]) > 0) {
            strncpy(buf, candidates[i], (size_t)(buflen - 1));
            buf[buflen - 1] = '\0';
            return 0;
        }
    }

    return -1;
}

#else /* !__APPLE__ && !__FreeBSD__ */

#include <stdio.h>
#include <string.h>

int usque_route_setup_bsd(const char *tun_name, const char *endpoint_v4,
                          const char *const *dns_servers, int dns_count,
                          char *errbuf, int errbuf_len) {
    (void)tun_name; (void)endpoint_v4; (void)dns_servers; (void)dns_count;
    snprintf(errbuf, errbuf_len, "BSD routes not available on this platform");
    return -1;
}

int usque_route_cleanup_bsd(const char *tun_name, char *errbuf, int errbuf_len) {
    (void)tun_name; (void)errbuf; (void)errbuf_len;
    return -1;
}

int usque_route_bind_to_interface(int fd, const char *ifname,
                                  char *errbuf, int errbuf_len) {
    (void)fd; (void)ifname;
    snprintf(errbuf, errbuf_len, "BSD socket binding not available");
    return -1;
}

int usque_route_detect_physical_iface(char *buf, int buflen) {
    (void)buf; (void)buflen;
    return -1;
}

#endif /* __APPLE__ || __FreeBSD__ */
