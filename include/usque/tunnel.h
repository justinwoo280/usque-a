#ifndef USQUE_TUNNEL_H
#define USQUE_TUNNEL_H

#include <stdint.h>
#include <stddef.h>
#include "usque/error.h"
#include "usque/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct usque_tunnel usque_tunnel_t;

/* Callback invoked when an IP packet is received from the WARP tunnel.
 * The buffer is only valid for the duration of the callback. */
typedef void (*usque_recv_packet_cb)(const uint8_t *pkt, size_t len, void *userdata);

/* Create a tunnel instance. Does not connect immediately.
 * Call usque_tunnel_run() to start the event loop. */
usque_error_t usque_tunnel_new(const usque_tunnel_config_t *cfg,
                               usque_recv_packet_cb cb,
                               void *userdata,
                               usque_tunnel_t **out,
                               char *errbuf, size_t errbuf_len);

/* Run the tunnel event loop. Blocks until usque_tunnel_stop() is called
 * or a fatal error occurs. Automatically reconnects on connection loss. */
usque_error_t usque_tunnel_run(usque_tunnel_t *t);

/* Signal the tunnel to stop. Thread-safe; can be called from a signal handler. */
void usque_tunnel_stop(usque_tunnel_t *t);

/* Send an IP packet into the WARP tunnel. Thread-safe. */
usque_error_t usque_tunnel_send_packet(usque_tunnel_t *t,
                                       const uint8_t *pkt, size_t len);

/* Destroy the tunnel and free all resources. */
void usque_tunnel_destroy(usque_tunnel_t *t);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_TUNNEL_H */
