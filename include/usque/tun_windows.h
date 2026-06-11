#ifndef USQUE_TUN_WINDOWS_H
#define USQUE_TUN_WINDOWS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define USQUE_TUN_MAX_NAME 64

typedef struct usque_tun usque_tun_t;

/* Create a TUN device using wintun.dll.
 * name: adapter name (e.g. "usque")
 * mtu: MTU size
 * ipv4/ipv6: tunnel IP addresses
 * wintun_dll_path: path to wintun.dll (NULL = search PATH)
 * Returns handle or NULL on error. */
usque_tun_t* usque_tun_create(const char *name, int mtu,
                              const char *ipv4, const char *ipv6,
                              const char *wintun_dll_path,
                              char *errbuf, int errbuf_len);

/* Get the TUN read event handle (for WaitForMultipleObjects). */
void* usque_tun_read_event(const usque_tun_t *tun);

/* Get the adapter name. */
const char* usque_tun_name(const usque_tun_t *tun);

/* Get the adapter LUID (for route/DNS configuration). */
uint64_t usque_tun_luid(const usque_tun_t *tun);

/* Read a packet from the ring buffer. Non-blocking.
 * Returns bytes read, 0 if no packet available, -1 on error. */
int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen);

/* Write a packet to the ring buffer.
 * Returns bytes written, or -1 on error. */
int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len);

/* Close adapter and free resources. */
void usque_tun_destroy(usque_tun_t *tun);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_TUN_WINDOWS_H */
