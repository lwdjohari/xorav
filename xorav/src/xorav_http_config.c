#include "xorav_http_config.h"
#include <string.h>

void xorav_http_config_secure_defaults(xorav_http_config_t *c) {
  if (!c) return;
  memset(c, 0, sizeof(*c));
  c->total_timeout_ms       = 15000;
  c->allow_private_ip       = 0;
  c->tls_min_version        = 0x0303; /* TLS 1.2 */
  c->enable_gzip            = 1;
  c->enable_deflate         = 1;
  c->enable_brotli          = 1;
  c->max_body_bytes         = 16ull << 20;
  c->max_decompressed_bytes = 64ull << 20;
  c->max_decompress_ratio   = 30.0f;
  c->max_keepalive_per_host = 2;
  c->keepalive_idle_ms      = 15000;
}
