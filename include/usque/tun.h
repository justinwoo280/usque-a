#ifndef USQUE_TUN_H
#define USQUE_TUN_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define USQUE_TUN_MAX_NAME 64

typedef struct usque_tun usque_tun_t;

/* Cross-platform TUN creation parameters. */
typedef struct usque_tun_params {
    const char *name;           /* device name (empty = kernel-assigned) */
    int         mtu;            /* MTU */
    const char *ipv4;           /* tunnel IPv4 address */
    const char *ipv6;           /* tunnel IPv6 address */
    bool        persist;        /* Linux only: persist device after close */
    const char *wintun_dll;     /* Windows only: path to wintun.dll (NULL = search PATH) */
} usque_tun_params_t;

/* Create a TUN device. Platform-specific implementation selected at compile time. */
usque_tun_t* usque_tun_create(const usque_tun_params_t *params,
                              char *errbuf, int errbuf_len);

/* Get the actual device name. */
const char* usque_tun_name(const usque_tun_t *tun);

/* Read a packet. Returns bytes read, 0 if none available, -1 on error. */
int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen);

/* Write a packet. Returns bytes written, -1 on error. */
int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len);

/* Close and destroy. */
void usque_tun_destroy(usque_tun_t *tun);

/* ---- Platform-specific accessors ---- */

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
/* Unix: get fd for select/poll/kqueue. */
int usque_tun_fd(const usque_tun_t *tun);
#endif

#ifdef _WIN32
/* Windows: get read event HANDLE for WaitForMultipleObjects. */
void* usque_tun_read_event(const usque_tun_t *tun);
/* Windows: get adapter LUID for route/DNS config. */
uint64_t usque_tun_luid(const usque_tun_t *tun);
#endif

#ifdef __cplusplus
}
#endif

#endif /* USQUE_TUN_H */
