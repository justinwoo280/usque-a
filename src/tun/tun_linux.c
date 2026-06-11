#include "usque/tun.h"

#ifdef __linux__

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
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

/* ---- Netlink helpers ---- */

struct nl_req {
    struct nlmsghdr  nlh;
    char             buf[512];
};

static int nl_open(char *errbuf, int errbuf_len) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        snprintf(errbuf, errbuf_len, "netlink socket: %s", strerror(errno));
    }
    return fd;
}

static int nl_send_recv(int nlfd, struct nl_req *req, char *errbuf, int errbuf_len) {
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};

    struct iovec iov = {.iov_base = req, .iov_len = req->nlh.nlmsg_len};
    struct msghdr msg = {
        .msg_name = &sa, .msg_namelen = sizeof(sa),
        .msg_iov = &iov, .msg_iovlen = 1,
    };

    if (sendmsg(nlfd, &msg, 0) < 0) {
        snprintf(errbuf, errbuf_len, "netlink sendmsg: %s", strerror(errno));
        return -1;
    }

    char rbuf[4096];
    iov.iov_base = rbuf;
    iov.iov_len = sizeof(rbuf);

    ssize_t len = recvmsg(nlfd, &msg, 0);
    if (len < 0) {
        snprintf(errbuf, errbuf_len, "netlink recvmsg: %s", strerror(errno));
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)rbuf;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error != 0) {
            snprintf(errbuf, errbuf_len, "netlink error: %s", strerror(-err->error));
            return -1;
        }
    }
    return 0;
}

static int if_nametoindex_safe(const char *name) {
    unsigned int idx = if_nametoindex(name);
    return (int)idx;
}

/* ---- Add IP address via netlink ---- */

static int nl_add_addr(int nlfd, int ifindex, int family,
                       const void *addr, int prefixlen,
                       char *errbuf, int errbuf_len) {
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
        char attrs[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_type = RTM_NEWADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

    req.ifa.ifa_family = (unsigned char)family;
    req.ifa.ifa_prefixlen = (unsigned char)prefixlen;
    req.ifa.ifa_index = (unsigned int)ifindex;
    req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;

    int addrlen = (family == AF_INET) ? 4 : 16;
    struct rtattr *rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = (unsigned short)(RTA_LENGTH(addrlen));
    memcpy(RTA_DATA(rta), addr, (size_t)addrlen);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + (unsigned int)RTA_LENGTH(addrlen);

    return nl_send_recv(nlfd, (struct nl_req *)&req, errbuf, errbuf_len);
}

/* ---- Set link up and MTU via netlink ---- */

static int nl_set_link(int nlfd, int ifindex, int mtu,
                       char *errbuf, int errbuf_len) {
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
        char attrs[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_type = RTM_NEWLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = ifindex;
    req.ifi.ifi_change = IFF_UP;
    req.ifi.ifi_flags = IFF_UP;

    if (mtu > 0) {
        struct rtattr *rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
        rta->rta_type = IFLA_MTU;
        rta->rta_len = (unsigned short)RTA_LENGTH(4);
        *(uint32_t *)RTA_DATA(rta) = (uint32_t)mtu;
        req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + (unsigned int)RTA_LENGTH(4);
    }

    return nl_send_recv(nlfd, (struct nl_req *)&req, errbuf, errbuf_len);
}

/* ---- Public API ---- */

usque_tun_t* usque_tun_create(const usque_tun_params_t *p,
                              char *errbuf, int errbuf_len) {
    const char *name = p->name;
    int mtu = p->mtu;
    const char *ipv4 = p->ipv4;
    const char *ipv6 = p->ipv6;
    bool persist = p->persist;

    int tunfd = open("/dev/net/tun", O_RDWR);
    if (tunfd < 0) {
        snprintf(errbuf, errbuf_len, "open /dev/net/tun: %s", strerror(errno));
        return NULL;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = (short)(IFF_TUN | IFF_NO_PI);
    if (name && name[0]) {
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    }

    if (ioctl(tunfd, TUNSETIFF, &ifr) < 0) {
        snprintf(errbuf, errbuf_len, "ioctl TUNSETIFF: %s", strerror(errno));
        close(tunfd);
        return NULL;
    }

    if (!persist) {
        ioctl(tunfd, TUNSETPERSIST, 0);
    }

    usque_tun_t *tun = (usque_tun_t *)calloc(1, sizeof(usque_tun_t));
    if (!tun) {
        close(tunfd);
        return NULL;
    }
    tun->fd = tunfd;
    strncpy(tun->name, ifr.ifr_name, USQUE_TUN_MAX_NAME - 1);

    /* Configure via netlink */
    char nlerr[256];
    int nlfd = nl_open(nlerr, sizeof(nlerr));
    if (nlfd < 0) {
        snprintf(errbuf, errbuf_len, "%s", nlerr);
        close(tunfd);
        free(tun);
        return NULL;
    }

    int ifindex = if_nametoindex_safe(tun->name);
    if (ifindex <= 0) {
        snprintf(errbuf, errbuf_len, "if_nametoindex(%s) failed", tun->name);
        close(nlfd);
        close(tunfd);
        free(tun);
        return NULL;
    }

    /* Set MTU and bring link up */
    if (nl_set_link(nlfd, ifindex, mtu, nlerr, sizeof(nlerr)) < 0) {
        snprintf(errbuf, errbuf_len, "set link: %s", nlerr);
        close(nlfd);
        close(tunfd);
        free(tun);
        return NULL;
    }

    /* Add IPv4 address */
    if (ipv4 && ipv4[0]) {
        struct in_addr addr4;
        if (inet_pton(AF_INET, ipv4, &addr4) != 1) {
            snprintf(errbuf, errbuf_len, "invalid IPv4: %s", ipv4);
            close(nlfd);
            close(tunfd);
            free(tun);
            return NULL;
        }
        if (nl_add_addr(nlfd, ifindex, AF_INET, &addr4, 32, nlerr, sizeof(nlerr)) < 0) {
            snprintf(errbuf, errbuf_len, "add IPv4: %s", nlerr);
            close(nlfd);
            close(tunfd);
            free(tun);
            return NULL;
        }
    }

    /* Add IPv6 address */
    if (ipv6 && ipv6[0]) {
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, ipv6, &addr6) != 1) {
            snprintf(errbuf, errbuf_len, "invalid IPv6: %s", ipv6);
            close(nlfd);
            close(tunfd);
            free(tun);
            return NULL;
        }
        if (nl_add_addr(nlfd, ifindex, AF_INET6, &addr6, 128, nlerr, sizeof(nlerr)) < 0) {
            snprintf(errbuf, errbuf_len, "add IPv6: %s", nlerr);
            close(nlfd);
            close(tunfd);
            free(tun);
            return NULL;
        }
    }

    close(nlfd);
    return tun;
}

const char* usque_tun_name(const usque_tun_t *tun) {
    return tun ? tun->name : "";
}

int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen) {
    return (int)read(tun->fd, buf, (size_t)buflen);
}

int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len) {
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

#else /* !__linux__ */

struct usque_tun { char name[USQUE_TUN_MAX_NAME]; };

usque_tun_t* usque_tun_create(const usque_tun_params_t *p,
                              char *errbuf, int errbuf_len) {
    (void)p;
    snprintf(errbuf, errbuf_len, "Linux TUN not available on this platform");
    return NULL;
}
const char* usque_tun_name(const usque_tun_t *tun) { return tun ? tun->name : ""; }
int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen) { (void)tun; (void)buf; (void)buflen; return -1; }
int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len) { (void)tun; (void)buf; (void)len; return -1; }
void usque_tun_destroy(usque_tun_t *tun) { free(tun); }
int usque_tun_fd(const usque_tun_t *tun) { (void)tun; return -1; }

#endif /* __linux__ */
