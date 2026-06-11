#include "usque/tun.h"

#ifdef _WIN32

#include <windows.h>
#include <iphlpapi.h>
#include <ws2ipdef.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* ---- wintun.dll function types ---- */

typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;

typedef enum {
    WINTUN_MIN_RING_CAPACITY = 0x20000,
    WINTUN_MAX_RING_CAPACITY = 0x4000000,
    WINTUN_DEFAULT_RING_CAPACITY = 0x400000
} WINTUN_RING_CAPACITY;

typedef WINTUN_ADAPTER_HANDLE (*WintunCreateAdapterFunc)(
    const wchar_t *Name, const wchar_t *TunnelType, const GUID *RequestedGUID);
typedef void (*WintunCloseAdapterFunc)(WINTUN_ADAPTER_HANDLE Adapter);
typedef WINTUN_SESSION_HANDLE (*WintunStartSessionFunc)(
    WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
typedef void (*WintunEndSessionFunc)(WINTUN_SESSION_HANDLE Session);
typedef HANDLE (*WintunGetReadWaitEventFunc)(WINTUN_SESSION_HANDLE Session);
typedef BYTE* (*WintunReceivePacketFunc)(
    WINTUN_SESSION_HANDLE Session, DWORD *PacketSize);
typedef void (*WintunReleaseReceivePacketFunc)(
    WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
typedef BYTE* (*WintunAllocateSendPacketFunc)(
    WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
typedef void (*WintunSendPacketFunc)(
    WINTUN_SESSION_HANDLE Session, BYTE *Packet);
typedef DWORD (*WintunGetAdapterLUIDFunc)(
    WINTUN_ADAPTER_HANDLE Adapter, NET_LUID *Luid);

struct wintun_funcs {
    WintunCreateAdapterFunc       CreateAdapter;
    WintunCloseAdapterFunc        CloseAdapter;
    WintunStartSessionFunc        StartSession;
    WintunEndSessionFunc          EndSession;
    WintunGetReadWaitEventFunc    GetReadWaitEvent;
    WintunReceivePacketFunc       ReceivePacket;
    WintunReleaseReceivePacketFunc ReleaseReceivePacket;
    WintunAllocateSendPacketFunc  AllocateSendPacket;
    WintunSendPacketFunc          SendPacket;
    WintunGetAdapterLUIDFunc      GetAdapterLUID;
};

struct usque_tun {
    HMODULE                dll;
    struct wintun_funcs    w;
    WINTUN_ADAPTER_HANDLE  adapter;
    WINTUN_SESSION_HANDLE  session;
    HANDLE                 read_event;
    NET_LUID               luid;
    char                   name[USQUE_TUN_MAX_NAME];
};

/* ---- wintun DLL loading ---- */

static HMODULE load_wintun_dll(const char *path, char *errbuf, int errbuf_len) {
    HMODULE dll = NULL;
    if (path && path[0]) {
        dll = LoadLibraryA(path);
    }
    if (!dll) {
        dll = LoadLibraryA("wintun.dll");
    }
    if (!dll) {
        snprintf(errbuf, errbuf_len,
                 "Cannot load wintun.dll. Download from https://www.wintun.net/ "
                 "and place wintun.dll next to the executable or in PATH.");
    }
    return dll;
}

static int load_wintun_funcs(HMODULE dll, struct wintun_funcs *w,
                             char *errbuf, int errbuf_len) {
#define LOAD(name) \
    w->name = (Wintun##name##Func)GetProcAddress(dll, "Wintun" #name); \
    if (!w->name) { \
        snprintf(errbuf, errbuf_len, "Wintun" #name " not found in DLL"); \
        return -1; \
    }

    LOAD(CreateAdapter)
    LOAD(CloseAdapter)
    LOAD(StartSession)
    LOAD(EndSession)
    LOAD(GetReadWaitEvent)
    LOAD(ReceivePacket)
    LOAD(ReleaseReceivePacket)
    LOAD(AllocateSendPacket)
    LOAD(SendPacket)
    LOAD(GetAdapterLUID)
#undef LOAD
    return 0;
}

/* ---- GUID generation (deterministic from adapter name) ---- */

static void name_to_guid(const char *name, GUID *guid) {
    /* Simple hash-based deterministic GUID */
    uint32_t hash[4] = {0x57617270, 0x54554E, 0, 0};  /* "WarpTUN\0" */
    for (const char *p = name; *p; p++) {
        hash[0] = hash[0] * 31 + (uint8_t)*p;
        hash[1] = hash[1] * 37 + (uint8_t)*p;
        hash[2] = hash[2] * 41 + (uint8_t)*p;
        hash[3] = hash[3] * 43 + (uint8_t)*p;
    }
    guid->Data1 = hash[0];
    guid->Data2 = (uint16_t)(hash[1] & 0xFFFF);
    guid->Data3 = (uint16_t)((hash[1] >> 16) & 0xFFFF);
    uint8_t *b = (uint8_t *)&hash[2];
    for (int i = 0; i < 8; i++) guid->Data4[i] = b[i];
}

/* ---- UTF-8 to UTF-16 conversion ---- */

static int utf8_to_wchar(const char *src, wchar_t *dst, int dst_len) {
    return MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dst_len);
}

/* ---- IP configuration via IP Helper API ---- */

static int configure_ip(NET_LUID luid, const char *ipv4, const char *ipv6,
                        int mtu, char *errbuf, int errbuf_len) {
    MIB_IF_ROW2 if_row;
    InitializeIpInterfaceEntry(&if_row);

    /* IPv4 */
    if (ipv4 && ipv4[0]) {
        MIB_IPINTERFACE_ROW ip_row;
        InitializeIpInterfaceEntry(&ip_row);
        ip_row.InterfaceLuid = luid;
        ip_row.Family = AF_INET;
        ip_row.NlMtu = (ULONG)mtu;
        ip_row.UseAutomaticMetric = FALSE;
        ip_row.Metric = 0;
        DWORD err = SetIpInterfaceEntry(&ip_row);
        if (err != NO_ERROR && err != ERROR_NOT_FOUND) {
            snprintf(errbuf, errbuf_len, "SetIpInterfaceEntry(v4): %lu", err);
            return -1;
        }

        /* Add /32 address */
        MIB_UNICASTIPADDRESS_ROW addr_row;
        InitializeUnicastIpAddressEntry(&addr_row);
        addr_row.InterfaceLuid = luid;
        addr_row.Address.Ipv4.sin_family = AF_INET;
        addr_row.Address.Ipv4.sin_addr.s_addr = inet_addr(ipv4);
        addr_row.OnLinkPrefixLength = 32;
        err = CreateUnicastIpAddressEntry(&addr_row);
        if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
            snprintf(errbuf, errbuf_len, "CreateUnicastIpAddress(v4): %lu", err);
            return -1;
        }
    }

    /* IPv6 */
    if (ipv6 && ipv6[0]) {
        MIB_IPINTERFACE_ROW ip_row;
        InitializeIpInterfaceEntry(&ip_row);
        ip_row.InterfaceLuid = luid;
        ip_row.Family = AF_INET6;
        ip_row.NlMtu = (ULONG)mtu;
        ip_row.UseAutomaticMetric = FALSE;
        ip_row.Metric = 0;
        SetIpInterfaceEntry(&ip_row);

        MIB_UNICASTIPADDRESS_ROW addr_row;
        InitializeUnicastIpAddressEntry(&addr_row);
        addr_row.InterfaceLuid = luid;
        addr_row.Address.Ipv6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, ipv6, &addr_row.Address.Ipv6.sin6_addr);
        addr_row.OnLinkPrefixLength = 128;
        DWORD err = CreateUnicastIpAddressEntry(&addr_row);
        if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
            snprintf(errbuf, errbuf_len, "CreateUnicastIpAddress(v6): %lu", err);
            return -1;
        }
    }

    return 0;
}

/* ---- Public API ---- */

usque_tun_t* usque_tun_create(const usque_tun_params_t *p,
                              char *errbuf, int errbuf_len) {
    const char *name = p->name;
    int mtu = p->mtu;
    const char *ipv4 = p->ipv4;
    const char *ipv6 = p->ipv6;
    const char *wintun_dll_path = p->wintun_dll;

    usque_tun_t *tun = (usque_tun_t *)calloc(1, sizeof(usque_tun_t));
    if (!tun) return NULL;

    /* Load wintun.dll */
    tun->dll = load_wintun_dll(wintun_dll_path, errbuf, errbuf_len);
    if (!tun->dll) { free(tun); return NULL; }

    if (load_wintun_funcs(tun->dll, &tun->w, errbuf, errbuf_len) != 0) {
        FreeLibrary(tun->dll);
        free(tun);
        return NULL;
    }

    /* Create adapter */
    wchar_t wname[256];
    utf8_to_wchar(name, wname, 256);

    GUID guid;
    name_to_guid(name, &guid);

    tun->adapter = tun->w.CreateAdapter(wname, L"WARP", &guid);
    if (!tun->adapter) {
        snprintf(errbuf, errbuf_len, "WintunCreateAdapter failed: %lu", GetLastError());
        FreeLibrary(tun->dll);
        free(tun);
        return NULL;
    }

    /* Start session with 8 MiB ring buffer */
    tun->session = tun->w.StartSession(tun->adapter, 0x800000);
    if (!tun->session) {
        snprintf(errbuf, errbuf_len, "WintunStartSession failed: %lu", GetLastError());
        tun->w.CloseAdapter(tun->adapter);
        FreeLibrary(tun->dll);
        free(tun);
        return NULL;
    }

    tun->read_event = tun->w.GetReadWaitEvent(tun->session);

    /* Get LUID */
    if (tun->w.GetAdapterLUID(tun->adapter, &tun->luid) != ERROR_SUCCESS) {
        snprintf(errbuf, errbuf_len, "WintunGetAdapterLUID failed");
        tun->w.EndSession(tun->session);
        tun->w.CloseAdapter(tun->adapter);
        FreeLibrary(tun->dll);
        free(tun);
        return NULL;
    }

    strncpy(tun->name, name, USQUE_TUN_MAX_NAME - 1);

    /* Configure IP addresses and MTU */
    if (configure_ip(tun->luid, ipv4, ipv6, mtu, errbuf, errbuf_len) != 0) {
        tun->w.EndSession(tun->session);
        tun->w.CloseAdapter(tun->adapter);
        FreeLibrary(tun->dll);
        free(tun);
        return NULL;
    }

    return tun;
}

void* usque_tun_read_event(const usque_tun_t *tun) {
    return tun ? (void *)tun->read_event : NULL;
}

const char* usque_tun_name(const usque_tun_t *tun) {
    return tun ? tun->name : "";
}

uint64_t usque_tun_luid(const usque_tun_t *tun) {
    if (!tun) return 0;
    return *(uint64_t *)&tun->luid;
}

int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen) {
    if (!tun || !tun->session) return -1;

    DWORD pkt_size = 0;
    const BYTE *pkt = tun->w.ReceivePacket(tun->session, &pkt_size);
    if (!pkt) {
        /* No packet available or error */
        return (GetLastError() == ERROR_NO_MORE_ITEMS) ? 0 : -1;
    }

    int copy_len = ((int)pkt_size < buflen) ? (int)pkt_size : buflen;
    memcpy(buf, pkt, (size_t)copy_len);
    tun->w.ReleaseReceivePacket(tun->session, pkt);
    return copy_len;
}

int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len) {
    if (!tun || !tun->session || len <= 0) return -1;

    BYTE *pkt = tun->w.AllocateSendPacket(tun->session, (DWORD)len);
    if (!pkt) return -1;

    memcpy(pkt, buf, (size_t)len);
    tun->w.SendPacket(tun->session, pkt);
    return len;
}

void usque_tun_destroy(usque_tun_t *tun) {
    if (!tun) return;
    if (tun->session) tun->w.EndSession(tun->session);
    if (tun->adapter) tun->w.CloseAdapter(tun->adapter);
    if (tun->dll) FreeLibrary(tun->dll);
    free(tun);
}

#else /* !_WIN32 */

/* Stub for non-Windows platforms */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct usque_tun {
    char name[USQUE_TUN_MAX_NAME];
};

usque_tun_t* usque_tun_create(const usque_tun_params_t *p,
                              char *errbuf, int errbuf_len) {
    (void)p;
    snprintf(errbuf, errbuf_len, "Windows TUN not available on this platform");
    return NULL;
}

void* usque_tun_read_event(const usque_tun_t *tun) { (void)tun; return NULL; }
const char* usque_tun_name(const usque_tun_t *tun) { return tun ? tun->name : ""; }
uint64_t usque_tun_luid(const usque_tun_t *tun) { (void)tun; return 0; }
int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen) {
    (void)tun; (void)buf; (void)buflen; return -1;
}
int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len) {
    (void)tun; (void)buf; (void)len; return -1;
}
void usque_tun_destroy(usque_tun_t *tun) { free(tun); }

#endif /* _WIN32 */
