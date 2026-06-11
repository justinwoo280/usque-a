#ifndef USQUE_CONFIG_H
#define USQUE_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "error.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct usque_config usque_config_t;

/* ---- Lifecycle ---- */

usque_error_t usque_config_load_file(const char *path,
                                     usque_config_t **out,
                                     char *errbuf, size_t errbuf_len);

usque_error_t usque_config_load_string(const char *json, size_t json_len,
                                       usque_config_t **out,
                                       char *errbuf, size_t errbuf_len);

usque_error_t usque_config_save_file(const usque_config_t *cfg,
                                     const char *path,
                                     char *errbuf, size_t errbuf_len);

void usque_config_destroy(usque_config_t *cfg);

/* ---- Account accessors ---- */

const char* usque_config_account_private_key(const usque_config_t *cfg);
const char* usque_config_account_endpoint_v4(const usque_config_t *cfg);
const char* usque_config_account_endpoint_v6(const usque_config_t *cfg);
const char* usque_config_account_endpoint_h2_v4(const usque_config_t *cfg);
const char* usque_config_account_endpoint_h2_v6(const usque_config_t *cfg);
const char* usque_config_account_endpoint_pub_key(const usque_config_t *cfg);
const char* usque_config_account_license(const usque_config_t *cfg);
const char* usque_config_account_id(const usque_config_t *cfg);
const char* usque_config_account_access_token(const usque_config_t *cfg);
const char* usque_config_account_ipv4(const usque_config_t *cfg);
const char* usque_config_account_ipv6(const usque_config_t *cfg);

/* ---- TUN Inbound accessors ---- */

const char* usque_config_tun_name(const usque_config_t *cfg);
int         usque_config_tun_mtu(const usque_config_t *cfg);
bool        usque_config_tun_ipv4(const usque_config_t *cfg);
bool        usque_config_tun_ipv6(const usque_config_t *cfg);
bool        usque_config_tun_persist(const usque_config_t *cfg);
int         usque_config_tun_fd(const usque_config_t *cfg);
bool        usque_config_tun_auto_route(const usque_config_t *cfg);
int         usque_config_tun_dns_count(const usque_config_t *cfg);
const char* usque_config_tun_dns_at(const usque_config_t *cfg, int index);

/* ---- Outbound accessors ---- */

const char* usque_config_outbound_tag(const usque_config_t *cfg);
int         usque_config_outbound_port(const usque_config_t *cfg);
bool        usque_config_outbound_use_ipv6(const usque_config_t *cfg);
bool        usque_config_outbound_use_http2(const usque_config_t *cfg);
const char* usque_config_outbound_sni_address(const usque_config_t *cfg);
int64_t     usque_config_outbound_keepalive_period_ms(const usque_config_t *cfg);
uint16_t    usque_config_outbound_initial_packet_size(const usque_config_t *cfg);
int64_t     usque_config_outbound_reconnect_delay_ms(const usque_config_t *cfg);
bool        usque_config_outbound_always_reconnect(const usque_config_t *cfg);
bool        usque_config_outbound_insecure(const usque_config_t *cfg);
const char* usque_config_outbound_on_connect(const usque_config_t *cfg);
const char* usque_config_outbound_on_disconnect(const usque_config_t *cfg);

/* ---- Congestion accessors ---- */

usque_congestion_type_t usque_config_congestion_type(const usque_config_t *cfg);
uint64_t                usque_config_congestion_brutal_bps(const usque_config_t *cfg);
usque_bbr_profile_t     usque_config_congestion_bbr_profile(const usque_config_t *cfg);

/* ---- Noise accessors ---- */

bool    usque_config_noise_enabled(const usque_config_t *cfg);
int     usque_config_noise_count(const usque_config_t *cfg);
int     usque_config_noise_min_size(const usque_config_t *cfg);
int     usque_config_noise_max_size(const usque_config_t *cfg);
int64_t usque_config_noise_delay_min_ms(const usque_config_t *cfg);
int64_t usque_config_noise_delay_max_ms(const usque_config_t *cfg);

bool    usque_config_pre_noise_enabled(const usque_config_t *cfg);
int     usque_config_pre_noise_count(const usque_config_t *cfg);
int     usque_config_pre_noise_min_size(const usque_config_t *cfg);
int     usque_config_pre_noise_max_size(const usque_config_t *cfg);
int64_t usque_config_pre_noise_delay_min_ms(const usque_config_t *cfg);
int64_t usque_config_pre_noise_delay_max_ms(const usque_config_t *cfg);

/* ---- Build resolved tunnel config ---- */

usque_error_t usque_config_build_tunnel_config(const usque_config_t *cfg,
                                               usque_tunnel_config_t *out,
                                               char *errbuf, size_t errbuf_len);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_CONFIG_H */
