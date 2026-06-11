#include "usque/tun.h"

#ifdef __APPLE__

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

struct usque_tun {
    int  fd;
    char name[USQUE_TUN_MAX_NAME];
};

/* Connect to kernel control socket for utun */
static int utun_connect(int unit, char *ifname, int ifname_len) {
    struct sockaddr_ctl sc;
    struct ctl_info ki;
    int fd;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return -1;

    memset(&ki, 0, sizeof(ki));
    strncpy(ki.ctl_name, "com.apple.net.utun_control", sizeof(ki.ctl_name));

    if (ioctl(fd, CTLIOCGINFO, &ki) < 0) {
        close(fd);
        return -1;
    }

    memset(&sc, 0, sizeof(sc));
    sc.sc_id = ki.ctl_id;
    sc.sc_unit = (uint32_t)(unit + 1);  /* utun0 = sc_unit 1 */

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        close(fd);
        return -1;
    }

    /* Get the interface name */
    socklen_t len = (socklen_t)ifname_len;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &len) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* Configure IP and bring up via ifconfig */
static int configure_darwin(const char *name, int mtu,
                            const char *ipv4, const char *ipv6,
                            char *errbuf, int errbuf_len) {
    char cmd[512];

    /* MTU */
    if (mtu > 0) {
        snprintf(cmd, sizeof(cmd), "ifconfig %s mtu %d", name, mtu);
        if (system(cmd) != 0) {
            snprintf(errbuf, errbuf_len, "ifconfig mtu failed");
            return -1;
        }
    }

    /* IPv4: point-to-point with derived peer */
    if (ipv4 && ipv4[0]) {
        /* Derive peer IP: increment last octet */
        struct in_addr addr;
        inet_pton(AF_INET, ipv4, &addr);
        uint8_t *octets = (uint8_t *)&addr.s_addr;
        uint8_t peer_last = (uint8_t)(octets[0] + 1);
        if (peer_last == 0) peer_last = 1;

        char peer[INET_ADDRSTRLEN];
        snprintf(peer, sizeof(peer), "%d.%d.%d.%d",
                 octets[1], octets[2], octets[3], peer_last);

        snprintf(cmd, sizeof(cmd), "ifconfig %s inet %s %s", name, ipv4, peer);
        if (system(cmd) != 0) {
            snprintf(errbuf, errbuf_len, "ifconfig inet failed");
            return -1;
        }
    }

    /* IPv6 */
    if (ipv6 && ipv6[0]) {
        snprintf(cmd, sizeof(cmd),
                 "ifconfig %s inet6 %s fe80::1 prefixlen 128", name, ipv6);
        if (system(cmd) != 0) {
            snprintf(errbuf, errbuf_len, "ifconfig inet6 failed");
            return -1;
        }
    }

    /* Bring up */
    snprintf(cmd, sizeof(cmd), "ifconfig %s up", name);
    system(cmd);

    return 0;
}

usque_tun_t* usque_tun_create(const usque_tun_params_t *p,
                              char *errbuf, int errbuf_len) {
    (void)p->wintun_dll;  /* Not used on macOS */

    /* Try to find a free utun unit */
    int fd = -1;
    char ifname[USQUE_TUN_MAX_NAME] = "";

    for (int unit = 0; unit < 32; unit++) {
        fd = utun_connect(unit, ifname, sizeof(ifname));
        if (fd >= 0) break;
    }

    if (fd < 0) {
        snprintf(errbuf, errbuf_len, "no free utun device available");
        return NULL;
    }

    /* Configure IP and MTU */
    if (configure_darwin(ifname, p->mtu, p->ipv4, p->ipv6, errbuf, errbuf_len) != 0) {
        close(fd);
        return NULL;
    }

    usque_tun_t *tun = (usque_tun_t *)calloc(1, sizeof(usque_tun_t));
    if (!tun) { close(fd); return NULL; }
    tun->fd = fd;
    strncpy(tun->name, ifname, USQUE_TUN_MAX_NAME - 1);

    return tun;
}

const char* usque_tun_name(const usque_tun_t *tun) {
    return tun ? tun->name : "";
}

int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen) {
    if (!tun) return -1;
    /* utun on macOS uses AF_INET/AF_INET6 family header (4 bytes) */
    uint8_t tmp[4 + 65536];
    ssize_t n = read(tun->fd, tmp, sizeof(tmp));
    if (n <= 4) return -1;
    int pkt_len = (int)(n - 4);
    if (pkt_len > buflen) pkt_len = buflen;
    memcpy(buf, tmp + 4, (size_t)pkt_len);
    return pkt_len;
}

int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len) {
    if (!tun || len <= 0) return -1;
    /* Prepend AF family header */
    uint8_t family;
    if ((buf[0] >> 4) == 4) family = AF_INET;
    else if ((buf[0] >> 4) == 6) family = AF_INET6;
    else return -1;

    /* utun expects 4-byte family header (network byte order) */
    uint8_t tmp[4 + 65536];
    memset(tmp, 0, 4);
    tmp[3] = family;
    memcpy(tmp + 4, buf, (size_t)len);
    ssize_t n = write(tun->fd, tmp, 4 + (size_t)len);
    return (n > 4) ? (int)(n - 4) : -1;
}

void usque_tun_destroy(usque_tun_t *tun) {
    if (!tun) return;
    if (tun->fd >= 0) close(tun->fd);
    free(tun);
}

int usque_tun_fd(const usque_tun_t *tun) {
    return tun ? tun->fd : -1;
}

#else /* !__APPLE__ */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct usque_tun { char name[USQUE_TUN_MAX_NAME]; };

usque_tun_t* usque_tun_create(const usque_tun_params_t *p,
                              char *errbuf, int errbuf_len) {
    (void)p;
    snprintf(errbuf, errbuf_len, "macOS TUN not available on this platform");
    return NULL;
}
const char* usque_tun_name(const usque_tun_t *tun) { return tun ? tun->name : ""; }
int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen) { (void)tun; (void)buf; (void)buflen; return -1; }
int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len) { (void)tun; (void)buf; (void)len; return -1; }
void usque_tun_destroy(usque_tun_t *tun) { free(tun); }

#endif /* __APPLE__ */
