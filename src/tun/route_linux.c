#include "usque/route_linux.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>

/* ---- Netlink route/rule helpers ---- */

static int nl_open_route(void) {
    return socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
}

struct nlmsg_buf {
    struct nlmsghdr nlh;
    char            data[512];
};

static int nl_route_request(int nlfd, struct nlmsghdr *nlh,
                            char *errbuf, int errbuf_len) {
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    struct iovec iov = {.iov_base = nlh, .iov_len = nlh->nlmsg_len};
    struct msghdr msg = {
        .msg_name = &sa, .msg_namelen = sizeof(sa),
        .msg_iov = &iov, .msg_iovlen = 1,
    };

    if (sendmsg(nlfd, &msg, 0) < 0) {
        snprintf(errbuf, errbuf_len, "sendmsg: %s", strerror(errno));
        return -1;
    }

    char rbuf[4096];
    iov.iov_base = rbuf;
    iov.iov_len = sizeof(rbuf);
    ssize_t len = recvmsg(nlfd, &msg, 0);
    if (len < 0) {
        snprintf(errbuf, errbuf_len, "recvmsg: %s", strerror(errno));
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)rbuf;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (e->error != 0) {
            snprintf(errbuf, errbuf_len, "netlink: %s", strerror(-e->error));
            return -1;
        }
    }
    return 0;
}

/* Add a default route to the tunnel routing table */
static int add_tunnel_route(int nlfd, int ifindex,
                            char *errbuf, int errbuf_len) {
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char            attrs[128];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_type = RTM_NEWROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_table = RT_TABLE_UNSPEC;
    req.rtm.rtm_protocol = RTPROT_STATIC;
    req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
    req.rtm.rtm_type = RTN_UNICAST;
    req.rtm.rtm_dst_len = 0;  /* default route */

    /* RTA_TABLE for table ID > 255 */
    struct rtattr *rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_TABLE;
    rta->rta_len = (unsigned short)RTA_LENGTH(4);
    *(uint32_t *)RTA_DATA(rta) = USQUE_ROUTE_TABLE_TUNNEL;
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + (unsigned int)RTA_LENGTH(4);

    /* Output interface */
    rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_OIF;
    rta->rta_len = (unsigned short)RTA_LENGTH(4);
    *(uint32_t *)RTA_DATA(rta) = (uint32_t)ifindex;
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + (unsigned int)RTA_LENGTH(4);

    return nl_route_request(nlfd, &req.nlh, errbuf, errbuf_len);
}

/* Add ip rule: traffic goes to tunnel table */
static int add_tunnel_rule(int nlfd, int ifindex,
                           char *errbuf, int errbuf_len) {
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char            attrs[128];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_type = RTM_NEWRULE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_table = RT_TABLE_UNSPEC;
    req.rtm.rtm_protocol = RTPROT_STATIC;
    req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
    req.rtm.rtm_type = RTN_UNICAST;

    /* RTA_TABLE for table ID > 255 */
    struct rtattr *rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_TABLE;
    rta->rta_len = (unsigned short)RTA_LENGTH(4);
    *(uint32_t *)RTA_DATA(rta) = USQUE_ROUTE_TABLE_TUNNEL;
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + (unsigned int)RTA_LENGTH(4);

    /* Priority */
    rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_PRIORITY;
    rta->rta_len = (unsigned short)RTA_LENGTH(4);
    *(uint32_t *)RTA_DATA(rta) = USQUE_ROUTE_RULE_PRIORITY;
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + (unsigned int)RTA_LENGTH(4);

    (void)ifindex;  /* rule applies to all interfaces */
    return nl_route_request(nlfd, &req.nlh, errbuf, errbuf_len);
}

/* Add endpoint bypass route in the main table */
static int add_endpoint_bypass(int nlfd, const char *endpoint_v4,
                               int gw_ifindex,
                               char *errbuf, int errbuf_len) {
    struct in_addr dst;
    if (inet_pton(AF_INET, endpoint_v4, &dst) != 1) {
        snprintf(errbuf, errbuf_len, "invalid endpoint IP: %s", endpoint_v4);
        return -1;
    }

    /* Get the current default gateway */
    /* For simplicity, we add a /32 host route via the default gateway's interface.
     * A more robust approach would query the default gateway IP via netlink. */
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char            attrs[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_type = RTM_NEWROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_table = RT_TABLE_MAIN;
    req.rtm.rtm_protocol = RTPROT_STATIC;
    req.rtm.rtm_scope = RT_SCOPE_LINK;
    req.rtm.rtm_type = RTN_UNICAST;
    req.rtm.rtm_dst_len = 32;  /* /32 host route */

    /* Destination */
    struct rtattr *rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len = (unsigned short)RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &dst, 4);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + (unsigned int)RTA_LENGTH(4);

    /* Output interface */
    rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_OIF;
    rta->rta_len = (unsigned short)RTA_LENGTH(4);
    *(uint32_t *)RTA_DATA(rta) = (uint32_t)gw_ifindex;
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + (unsigned int)RTA_LENGTH(4);

    return nl_route_request(nlfd, &req.nlh, errbuf, errbuf_len);
}

/* ---- DNS configuration ---- */

static int dns_has_resolvectl(void) {
    return system("command -v resolvectl >/dev/null 2>&1") == 0;
}

static int dns_setup_resolvectl(const char *ifname,
                                const char *const *servers, int count,
                                char *errbuf, int errbuf_len) {
    char cmd[2048];
    int off = snprintf(cmd, sizeof(cmd), "resolvectl dns %s", ifname);
    for (int i = 0; i < count && off < (int)sizeof(cmd) - 64; i++) {
        off += snprintf(cmd + off, sizeof(cmd) - (size_t)off, " %s", servers[i]);
    }
    if (system(cmd) != 0) {
        snprintf(errbuf, errbuf_len, "resolvectl dns failed");
        return -1;
    }
    /* Set catch-all domain routing */
    snprintf(cmd, sizeof(cmd), "resolvectl domain %s ~.", ifname);
    system(cmd);
    /* Enable default-route */
    snprintf(cmd, sizeof(cmd), "resolvectl default-route %s true", ifname);
    system(cmd);
    return 0;
}

static int dns_cleanup_resolvectl(const char *ifname) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "resolvectl revert %s", ifname);
    return system(cmd);
}

static int dns_setup_resolv_conf(const char *const *servers, int count,
                                 char *errbuf, int errbuf_len) {
    /* Backup */
    if (rename("/etc/resolv.conf", "/etc/resolv.conf.usque.bak") != 0 && errno != ENOENT) {
        snprintf(errbuf, errbuf_len, "backup resolv.conf: %s", strerror(errno));
        return -1;
    }
    FILE *fp = fopen("/etc/resolv.conf", "w");
    if (!fp) {
        snprintf(errbuf, errbuf_len, "write resolv.conf: %s", strerror(errno));
        return -1;
    }
    for (int i = 0; i < count; i++) {
        fprintf(fp, "nameserver %s\n", servers[i]);
    }
    fclose(fp);
    return 0;
}

static int dns_cleanup_resolv_conf(void) {
    return rename("/etc/resolv.conf.usque.bak", "/etc/resolv.conf");
}

/* ---- Physical interface detection ---- */

int usque_route_detect_physical_iface(char *buf, int buflen) {
    DIR *dir = opendir("/sys/class/net");
    if (!dir) return -1;

    struct dirent *ent;
    int best_score = -1;
    char best_name[IFNAMSIZ] = "";

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strcmp(ent->d_name, "lo") == 0) continue;
        if (strncmp(ent->d_name, "tun", 3) == 0) continue;
        if (strncmp(ent->d_name, "veth", 4) == 0) continue;
        if (strncmp(ent->d_name, "docker", 6) == 0) continue;
        if (strncmp(ent->d_name, "br-", 3) == 0) continue;

        /* Check if interface is up */
        char path[256];
        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", ent->d_name);
        FILE *fp = fopen(path, "r");
        if (!fp) continue;
        char state[32];
        if (!fgets(state, sizeof(state), fp)) { fclose(fp); continue; }
        fclose(fp);
        if (strstr(state, "up") == NULL && strstr(state, "unknown") == NULL) continue;

        /* Score: prefer eth/en/wlan */
        int score = 1;
        if (strncmp(ent->d_name, "eth", 3) == 0) score = 10;
        else if (strncmp(ent->d_name, "en", 2) == 0) score = 10;
        else if (strncmp(ent->d_name, "wlan", 4) == 0) score = 9;
        else if (strncmp(ent->d_name, "wl", 2) == 0) score = 8;

        if (score > best_score) {
            best_score = score;
            strncpy(best_name, ent->d_name, IFNAMSIZ - 1);
        }
    }
    closedir(dir);

    if (best_name[0] == '\0') return -1;
    strncpy(buf, best_name, (size_t)(buflen - 1));
    buf[buflen - 1] = '\0';
    return 0;
}

/* ---- SO_BINDTODEVICE ---- */

int usque_route_bind_to_device(int fd, const char *ifname,
                               char *errbuf, int errbuf_len) {
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0) {
        snprintf(errbuf, errbuf_len, "SO_BINDTODEVICE(%s): %s", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

/* ---- Public API ---- */

int usque_route_setup(const char *tun_name,
                      const char *endpoint_v4,
                      const char *const *dns_servers,
                      int dns_count,
                      char *errbuf, int errbuf_len) {
    int nlfd = nl_open_route();
    if (nlfd < 0) {
        snprintf(errbuf, errbuf_len, "netlink socket: %s", strerror(errno));
        return -1;
    }

    int tun_ifindex = (int)if_nametoindex(tun_name);
    if (tun_ifindex <= 0) {
        snprintf(errbuf, errbuf_len, "if_nametoindex(%s) failed", tun_name);
        close(nlfd);
        return -1;
    }

    /* Detect physical interface for bypass route */
    char phys_iface[IFNAMSIZ] = "";
    int phys_ifindex = 0;
    if (usque_route_detect_physical_iface(phys_iface, sizeof(phys_iface)) == 0) {
        phys_ifindex = (int)if_nametoindex(phys_iface);
    }

    /* Add endpoint bypass route (via physical interface) */
    if (endpoint_v4 && endpoint_v4[0] && phys_ifindex > 0) {
        if (add_endpoint_bypass(nlfd, endpoint_v4, phys_ifindex, errbuf, errbuf_len) < 0) {
            close(nlfd);
            return -1;
        }
    }

    /* Add default route in tunnel table */
    if (add_tunnel_route(nlfd, tun_ifindex, errbuf, errbuf_len) < 0) {
        close(nlfd);
        return -1;
    }

    /* Add ip rule pointing to tunnel table */
    if (add_tunnel_rule(nlfd, tun_ifindex, errbuf, errbuf_len) < 0) {
        close(nlfd);
        return -1;
    }

    close(nlfd);

    /* Configure DNS */
    if (dns_count > 0 && dns_servers) {
        if (dns_has_resolvectl()) {
            dns_setup_resolvectl(tun_name, dns_servers, dns_count, errbuf, errbuf_len);
        } else {
            dns_setup_resolv_conf(dns_servers, dns_count, errbuf, errbuf_len);
        }
    }

    return 0;
}

int usque_route_cleanup(const char *tun_name,
                        char *errbuf, int errbuf_len) {
    (void)errbuf; (void)errbuf_len;

    /* Clean up DNS */
    if (dns_has_resolvectl()) {
        dns_cleanup_resolvectl(tun_name);
    } else {
        dns_cleanup_resolv_conf();
    }

    /* Note: routes and rules are cleaned up automatically when the TUN
     * interface is destroyed (kernel removes them). For explicit cleanup,
     * we would need to send RTM_DELROUTE and RTM_DELRULE messages. */
    return 0;
}
