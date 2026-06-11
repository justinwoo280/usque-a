#include "usque/tun.h"

#ifdef __FreeBSD__

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
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

/* Configure IP via ifconfig (same approach as macOS) */
static int configure_freebsd(const char *name, int mtu,
                             const char *ipv4, const char *ipv6,
                             char *errbuf, int errbuf_len) {
    char cmd[512];

    if (mtu > 0) {
        snprintf(cmd, sizeof(cmd), "ifconfig %s mtu %d", name, mtu);
        if (system(cmd) != 0) {
            snprintf(errbuf, errbuf_len, "ifconfig mtu failed");
            return -1;
        }
    }

    if (ipv4 && ipv4[0]) {
        /* Point-to-point: derive peer */
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
    (void)p->wintun_dll;  /* Not used on FreeBSD */
    (void)p->persist;

    /* Try /dev/tun0, tun1, ... tun7 */
    int fd = -1;
    char devpath[64];
    char ifname[USQUE_TUN_MAX_NAME];

    for (int i = 0; i < 8; i++) {
        snprintf(devpath, sizeof(devpath), "/dev/tun%d", i);
        fd = open(devpath, O_RDWR);
        if (fd >= 0) {
            snprintf(ifname, sizeof(ifname), "tun%d", i);
            break;
        }
    }

    if (fd < 0) {
        snprintf(errbuf, errbuf_len, "no free /dev/tun device: %s", strerror(errno));
        return NULL;
    }

    /* Configure IP and MTU */
    if (configure_freebsd(ifname, p->mtu, p->ipv4, p->ipv6, errbuf, errbuf_len) != 0) {
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
    /* FreeBSD /dev/tun: reads raw IP packets (no family header) */
    return (int)read(tun->fd, buf, (size_t)buflen);
}

int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len) {
    if (!tun) return -1;
    return (int)write(tun->fd, buf, (size_t)len);
}

void usque_tun_destroy(usque_tun_t *tun) {
    if (!tun) return;
    if (tun->fd >= 0) close(tun->fd);
    free(tun);
}

int usque_tun_fd(const usque_tun_t *tun) {
    return tun ? tun->fd : -1;
}

#else /* !__FreeBSD__ */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct usque_tun { char name[USQUE_TUN_MAX_NAME]; };

usque_tun_t* usque_tun_create(const usque_tun_params_t *p,
                              char *errbuf, int errbuf_len) {
    (void)p;
    snprintf(errbuf, errbuf_len, "FreeBSD TUN not available on this platform");
    return NULL;
}
const char* usque_tun_name(const usque_tun_t *tun) { return tun ? tun->name : ""; }
int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen) { (void)tun; (void)buf; (void)buflen; return -1; }
int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len) { (void)tun; (void)buf; (void)len; return -1; }
void usque_tun_destroy(usque_tun_t *tun) { free(tun); }

#endif /* __FreeBSD__ */
