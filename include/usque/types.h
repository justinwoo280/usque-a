#ifndef USQUE_TYPES_H
#define USQUE_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define USQUE_MAX_KEY_LEN   4096
#define USQUE_MAX_IP_LEN    64
#define USQUE_MAX_SNI_LEN   256
#define USQUE_MAX_PATH_LEN  1024
#define USQUE_MAX_TAG_LEN   64
#define USQUE_MAX_IFACE_LEN 64
#define USQUE_MAX_DNS_COUNT 16
#define USQUE_MAX_UUID_LEN  64

typedef enum usque_congestion_type {
    USQUE_CONGESTION_RENO   = 0,
    USQUE_CONGESTION_BBR    = 1,
    USQUE_CONGESTION_BRUTAL = 2
} usque_congestion_type_t;

typedef enum usque_bbr_profile {
    USQUE_BBR_CONSERVATIVE = 0,
    USQUE_BBR_STANDARD     = 1,
    USQUE_BBR_AGGRESSIVE   = 2
} usque_bbr_profile_t;

typedef struct usque_congestion_config {
    usque_congestion_type_t type;
    uint64_t                brutal_bps;
    usque_bbr_profile_t     bbr_profile;
} usque_congestion_config_t;

typedef struct usque_noise_config {
    bool    enabled;
    int     count;
    int     min_size;
    int     max_size;
    int64_t delay_min_ms;
    int64_t delay_max_ms;
} usque_noise_config_t;

typedef struct usque_account_info {
    char private_key[USQUE_MAX_KEY_LEN];
    char endpoint_v4[USQUE_MAX_IP_LEN];
    char endpoint_v6[USQUE_MAX_IP_LEN];
    char endpoint_h2_v4[USQUE_MAX_IP_LEN];
    char endpoint_h2_v6[USQUE_MAX_IP_LEN];
    char endpoint_pub_key[USQUE_MAX_KEY_LEN];
    char license[USQUE_MAX_KEY_LEN];
    char id[USQUE_MAX_UUID_LEN];
    char access_token[USQUE_MAX_KEY_LEN];
    char ipv4[USQUE_MAX_IP_LEN];
    char ipv6[USQUE_MAX_IP_LEN];
} usque_account_info_t;

typedef struct usque_tun_config {
    char name[USQUE_MAX_IFACE_LEN];
    int  mtu;
    bool ipv4;
    bool ipv6;
    bool persist;
    int  tun_fd;
    bool auto_route;
    char dns[USQUE_MAX_DNS_COUNT][USQUE_MAX_IP_LEN];
    int  dns_count;
} usque_tun_config_t;

typedef struct usque_outbound_config {
    char                    tag[USQUE_MAX_TAG_LEN];
    int                     port;
    bool                    use_ipv6;
    bool                    use_http2;
    char                    sni_address[USQUE_MAX_SNI_LEN];
    int64_t                 keepalive_period_ms;
    uint16_t                initial_packet_size;
    int64_t                 reconnect_delay_ms;
    bool                    always_reconnect;
    bool                    insecure;
    char                    on_connect[USQUE_MAX_PATH_LEN];
    char                    on_disconnect[USQUE_MAX_PATH_LEN];
    usque_congestion_config_t congestion;
    usque_noise_config_t    noise;
    usque_noise_config_t    pre_noise;
} usque_outbound_config_t;

typedef struct usque_tunnel_config {
    usque_account_info_t    account;
    usque_tun_config_t      tun;
    usque_outbound_config_t outbound;
} usque_tunnel_config_t;

#ifdef __cplusplus
}
#endif

#endif /* USQUE_TYPES_H */
