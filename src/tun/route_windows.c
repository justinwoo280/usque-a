#include "usque/route_windows.h"

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static NET_LUID luid_from_u64(uint64_t v) {
    NET_LUID luid;
    memcpy(&luid, &v, sizeof(luid));
    return luid;
}

static int get_default_gateway(struct in_addr *gw, NET_IFINDEX *ifindex) {
    PMIB_IPFORWARDTABLE table = NULL;
    DWORD size = 0;

    GetIpForwardTable(NULL, &size, FALSE);
    table = (PMIB_IPFORWARD_TABLE)malloc(size);
    if (!table) return -1;

    if (GetIpForwardTable(table, &size, FALSE) != NO_ERROR) {
        free(table);
        return -1;
    }

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        if (table->table[i].dwForwardDest == 0 &&
            table->table[i].dwForwardMask == 0) {
            gw->s_addr = table->table[i].dwForwardNextHop;
            *ifindex = table->table[i].dwForwardIfIndex;
            free(table);
            return 0;
        }
    }

    free(table);
    return -1;
}

/* Add endpoint bypass route: endpoint/32 via default gateway on physical NIC */
static int add_endpoint_bypass(const char *endpoint_v4,
                               char *errbuf, int errbuf_len) {
    struct in_addr gw;
    NET_IFINDEX phys_ifindex;
    if (get_default_gateway(&gw, &phys_ifindex) != 0) {
        snprintf(errbuf, errbuf_len, "cannot find default gateway");
        return -1;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "route add %s mask 255.255.255.255 %s metric 1 if %lu",
             endpoint_v4, inet_ntoa(gw), (unsigned long)phys_ifindex);
    if (system(cmd)) { /* best-effort */ }
    return 0;
}

int usque_route_setup_windows(uint64_t luid_val,
                              const char *endpoint_v4,
                              const char *const *dns_servers,
                              int dns_count,
                              char *errbuf, int errbuf_len) {
    NET_LUID luid = luid_from_u64(luid_val);
    NET_IFINDEX ifindex;
    ConvertInterfaceLuidToIndex(&luid, &ifindex);

    /* Endpoint bypass */
    if (endpoint_v4 && endpoint_v4[0]) {
        add_endpoint_bypass(endpoint_v4, errbuf, errbuf_len);
    }

    /* Default route via TUN (metric 0) */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "route add 0.0.0.0 mask 0.0.0.0 0.0.0.0 metric 0 if %lu",
             (unsigned long)ifindex);
    if (system(cmd)) { /* best-effort */ }

    /* DNS configuration via SetInterfaceDnsSettings (Windows 10+) or netsh fallback */
    if (dns_count > 0 && dns_servers) {
        wchar_t wguid[64];
        NET_LUID luid2 = luid;
        GUID guid;
        ConvertInterfaceLuidToGuid(&luid2, &guid);
        swprintf(wguid, 64,
                 L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                 guid.Data1, guid.Data2, guid.Data3,
                 guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                 guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

        /* Build DNS server list */
        char dns_list[1024] = "";
        for (int i = 0; i < dns_count; i++) {
            if (i > 0) strcat(dns_list, ",");
            strcat(dns_list, dns_servers[i]);
        }

        /* Use netsh as fallback (works on all Windows versions) */
        snprintf(cmd, sizeof(cmd),
                 "netsh interface ip set dns name=\"%lu\" static %s",
                 (unsigned long)ifindex, dns_servers[0]);
        if (system(cmd)) { /* best-effort */ }

        for (int i = 1; i < dns_count; i++) {
            snprintf(cmd, sizeof(cmd),
                     "netsh interface ip add dns name=\"%lu\" %s index=%d",
                     (unsigned long)ifindex, dns_servers[i], i + 1);
            if (system(cmd)) { /* best-effort */ }
        }

        /* Flush DNS cache */
        if (system("ipconfig /flushdns >nul 2>&1")) { /* best-effort */ }
    }

    return 0;
}

int usque_route_cleanup_windows(uint64_t luid_val,
                                char *errbuf, int errbuf_len) {
    (void)errbuf; (void)errbuf_len;
    NET_LUID luid = luid_from_u64(luid_val);
    NET_IFINDEX ifindex;
    ConvertInterfaceLuidToIndex(&luid, &ifindex);

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "route delete 0.0.0.0 mask 0.0.0.0 if %lu >nul 2>&1",
             (unsigned long)ifindex);
    if (system(cmd)) { /* best-effort */ }

    if (system("ipconfig /flushdns >nul 2>&1")) { /* best-effort */ }
    return 0;
}

int usque_route_bind_to_device_windows(int fd, uint64_t luid_val,
                                       char *errbuf, int errbuf_len) {
    NET_LUID luid = luid_from_u64(luid_val);
    NET_IFINDEX ifindex;
    ConvertInterfaceLuidToIndex(&luid, &ifindex);

    /* IP_UNICAST_IF: the interface index in network byte order (for IPv4) */
    DWORD idx = htonl(ifindex);
    if (setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (char *)&idx, sizeof(idx)) != 0) {
        snprintf(errbuf, errbuf_len, "IP_UNICAST_IF: %d", WSAGetLastError());
        return -1;
    }

    /* IPV6_UNICAST_IF: the interface index in host byte order (for IPv6) */
    DWORD idx6 = ifindex;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (char *)&idx6, sizeof(idx6)) != 0) {
        /* Non-fatal: IPv6 might not be available */
    }

    return 0;
}

uint64_t usque_route_detect_physical_luid(void) {
    PMIB_IF_TABLE2 table = NULL;
    if (GetIfTable2(&table) != NO_ERROR) return 0;

    /* Virtual adapter name patterns to exclude (case-insensitive substring match) */
    static const char *virtual_patterns[] = {
        "vEthernet",       /* Hyper-V */
        "VMware",          /* VMware */
        "VirtualBox",      /* VirtualBox */
        "vmnet",           /* VMware vmnet */
        "vbox",            /* VirtualBox */
        "Wintun",          /* Wintun (our own TUN) */
        "ZeroTier",        /* ZeroTier */
        "Hamachi",         /* LogMeIn Hamachi */
        "TAP-Windows",     /* OpenVPN TAP */
        "TAP-",            /* Various TAP adapters */
        "Docker",          /* Docker Desktop */
        "vnic",            /* Various virtual NICs */
        "tun",             /* TUN devices */
        "utun",            /* TUN via some tools */
        "ProtonVPN",       /* ProtonVPN */
        "Mullvad",         /* Mullvad VPN */
        "NordVPN",         /* NordVPN */
        "WireGuard",       /* WireGuard */
        "ExpressVPN",      /* ExpressVPN */
        "Surfshark",       /* Surfshark */
        "PANGP",           /* Palo Alto GlobalProtect */
        "Cisco",           /* Cisco AnyConnect */
        "Sangfor",         /* Sangfor SSL VPN */
        "SoftEther",       /* SoftEther VPN */
        NULL
    };

    NET_LUID best = {0};
    int best_score = -1;

    for (ULONG i = 0; i < table->NumEntries; i++) {
        MIB_IF_ROW2 *row = &table->Table[i];

        /* Skip non-up interfaces */
        if (row->OperStatus != IfOperStatusUp) continue;
        if (row->Loopback) continue;

        /* Skip non-physical types: must have a physical connector */
        if (!row->ConnectorPresent) continue;
        if (row->Type != IF_TYPE_ETHERNET_CSMACD &&
            row->Type != IF_TYPE_IEEE80211) continue;

        /* Convert description and alias to UTF-8 for matching */
        char desc[256] = "", alias[256] = "";
        WideCharToMultiByte(CP_UTF8, 0, row->Description, -1,
                            desc, sizeof(desc), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, row->Alias, -1,
                            alias, sizeof(alias), NULL, NULL);

        /* Check against virtual adapter blacklist (case-insensitive) */
        int is_virtual = 0;
        for (int p = 0; virtual_patterns[p] != NULL; p++) {
            const char *pat = virtual_patterns[p];
            /* Case-insensitive substring search */
            char d_lower[256], a_lower[256], p_lower[128];
            size_t dl = strlen(desc), al = strlen(alias), pl = strlen(pat);
            for (size_t j = 0; j <= dl; j++) d_lower[j] = (char)tolower((unsigned char)desc[j]);
            for (size_t j = 0; j <= al; j++) a_lower[j] = (char)tolower((unsigned char)alias[j]);
            for (size_t j = 0; j <= pl; j++) p_lower[j] = (char)tolower((unsigned char)pat[j]);
            if (strstr(d_lower, p_lower) || strstr(a_lower, p_lower)) {
                is_virtual = 1;
                break;
            }
        }
        if (is_virtual) continue;

        /* Scoring */
        int score = 1;
        if (row->Type == IF_TYPE_ETHERNET_CSMACD)
            score = 10;  /* Wired Ethernet */
        else if (row->Type == IF_TYPE_IEEE80211)
            score = 8;   /* WiFi */

        /* Bonus for adapters with IPv4 (actually connected to network) */
        if (row->Ipv4Indicator) score += 2;

        if (score > best_score) {
            best_score = score;
            best = row->InterfaceLuid;
        }
    }

    FreeMibTable(table);
    uint64_t result;
    memcpy(&result, &best, sizeof(result));
    return result;
}

#else /* !_WIN32 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

int usque_route_setup_windows(uint64_t luid, const char *endpoint_v4,
                              const char *const *dns_servers, int dns_count,
                              char *errbuf, int errbuf_len) {
    (void)luid; (void)endpoint_v4; (void)dns_servers; (void)dns_count;
    snprintf(errbuf, errbuf_len, "Windows routes not available on this platform");
    return -1;
}

int usque_route_cleanup_windows(uint64_t luid, char *errbuf, int errbuf_len) {
    (void)luid; (void)errbuf; (void)errbuf_len;
    return -1;
}

int usque_route_bind_to_device_windows(int fd, uint64_t luid,
                                       char *errbuf, int errbuf_len) {
    (void)fd; (void)luid;
    snprintf(errbuf, errbuf_len, "Windows socket binding not available");
    return -1;
}

uint64_t usque_route_detect_physical_luid(void) { return 0; }

#endif /* _WIN32 */
