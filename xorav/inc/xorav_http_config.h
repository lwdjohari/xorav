#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xorav_http_config_s {
  uint32_t total_timeout_ms;       /* default 15000 */
  int      allow_private_ip;       /* default 0 (SSRF guard on) */
  uint16_t tls_min_version;        /* default TLS 1.2 (0x0303) */
  int      enable_gzip;            /* default 1 */
  int      enable_deflate;         /* default 1 */
  int      enable_brotli;          /* default 1 */
  uint64_t max_body_bytes;         /* default 16 MiB (cap raw body if needed) */
  uint64_t max_decompressed_bytes; /* default 64 MiB (bomb guard) */
  float    max_decompress_ratio;   /* default 30.0f */
  int      max_keepalive_per_host; /* default 2 */
  uint32_t keepalive_idle_ms;      /* default 15000 */
} xorav_http_config_t;

/* Initialize opinionated, secure runtime defaults. */
void xorav_http_config_secure_defaults(xorav_http_config_t *cfg);

#ifdef __cplusplus
}
#endif
