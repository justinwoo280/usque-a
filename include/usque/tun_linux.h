#ifndef USQUE_TUN_LINUX_H
#define USQUE_TUN_LINUX_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define USQUE_TUN_MAX_NAME 64

typedef struct usque_tun usque_tun_t;

/* Create a TUN device with the given name, MTU, and IP addresses.
 * If name is empty, the kernel assigns one (e.g. "tun0").
 * Returns the fd on success, or -1 on error with message in errbuf. */
usque_tun_t* usque_tun_create(const char *name, int mtu,
                              const char *ipv4, const char *ipv6,
                              bool persist,
                              char *errbuf, int errbuf_len);

/* Get the TUN file descriptor for reading/writing packets. */
int usque_tun_fd(const usque_tun_t *tun);

/* Get the actual device name (may differ if kernel assigned it). */
const char* usque_tun_name(const usque_tun_t *tun);

/* Read a packet from the TUN device. Returns bytes read, or -1 on error. */
int usque_tun_read(usque_tun_t *tun, uint8_t *buf, int buflen);

/* Write a packet to the TUN device. Returns bytes written, or -1 on error. */
int usque_tun_write(usque_tun_t *tun, const uint8_t *buf, int len);

/* Close and destroy the TUN device. */
void usque_tun_destroy(usque_tun_t *tun);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_TUN_LINUX_H */
