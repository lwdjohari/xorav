#pragma once
#include <stdint.h>
#include <stddef.h>
#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward decls */
typedef struct xorav_http_client_s xorav_http_client_t;
typedef struct xorav_dns_ares_s    xorav_dns_ares_t;
typedef struct xorav_headers_s     xorav_headers_t;

/* ---- TLS version convenience (OpenSSL wire values) ---- */
#ifndef XORAV_TLS1_0
#  define XORAV_TLS1_0 0x0301
#endif
#ifndef XORAV_TLS1_1
#  define XORAV_TLS1_1 0x0302
#endif
#ifndef XORAV_TLS1_2
#  define XORAV_TLS1_2 0x0303
#endif
#ifndef XORAV_TLS1_3
#  define XORAV_TLS1_3 0x0304
#endif

/* ---- Methods ---- */
typedef enum {
  XORAV_HTTP_GET    = 0,
  XORAV_HTTP_HEAD   = 1,
  XORAV_HTTP_POST   = 2,
  XORAV_HTTP_PUT    = 3,
  XORAV_HTTP_DELETE = 4,
  XORAV_HTTP_PATCH  = 5
} xorav_http_method_e;

/* ---- Flags ---- */
enum {
  /* Don’t advertise Accept-Encoding (don’t negotiate compression) */
  XORAV_HTTP_F_NO_COMPRESS = (1u << 0),
  /* Don’t auto-decompress response even if Content-Encoding present */
  XORAV_HTTP_F_NO_DECOMPRESS = (1u << 1),
  /* Disable TLS verification (lab only; insecure) */
  XORAV_HTTP_F_INSECURE_TLS = (1u << 2),
  /* Force Transfer-Encoding: chunked for uploads even if content_length > 0 */
  XORAV_HTTP_F_FORCE_CHUNKED = (1u << 3),
};

/* ---- Callback types ---- */
typedef int (*xorav_http_on_data_cb)(const uint8_t *buf, size_t n, void *user);

typedef void (*xorav_http_on_headers_cb)(int         status_code,
                                         const char *raw_headers,
                                         size_t raw_len, void *user);

typedef void (*xorav_http_on_complete_cb)(int         status_or_neg_errno,
                                          const char *err, void *user);

/* Read streaming body for uploads.
 * Return SIZE_MAX on error; set *eof=1 when end-of-stream reached.
 */
typedef size_t (*xorav_http_on_body_read_cb)(uint8_t *dst, size_t max, int *eof,
                                             void *user);

/* ---- Public request ---- */
typedef struct xorav_http_req_s {
  xorav_http_method_e        method;
  const char                *url;         /* http:// or https:// */
  const xorav_headers_t     *headers_map; /* http headers map*/
  const void                *body;        /* optional fixed buffer */
  size_t                     body_len;

  /* Streaming upload (optional) */
  xorav_http_on_body_read_cb on_body_read;   /* if set, streaming */
  size_t                     content_length; /* 0 -> unknown -> chunked */

  /* Content-Type (optional) */
  const char                *content_type;

  /* Per-request flags */
  uint32_t                   flags;

  /* Callbacks */
  xorav_http_on_headers_cb   on_headers;  /* optional */
  xorav_http_on_data_cb      on_data;     /* optional */
  xorav_http_on_complete_cb  on_complete; /* required for status notification */

  /* Opaque user data */
  void                      *user;
} xorav_http_req_t;

/* ---- Init config (easy-options) ---- */
typedef struct xorav_http_client_config_s {
  /* scheduler / queue */
  int      max_inflight; /* default 32 */
  int      max_queued;   /* 0 => unbounded */

  /* timeouts / security */
  uint32_t total_timeout_ms; /* default 15000 ms */
  int      allow_private_ip; /* default 0 (SSRF guard on) */
  uint16_t tls_min_version;  /* default TLS 1.2 (0x0303) */

  /* compression negotiation defaults */
  int      enable_gzip;    /* default 1 */
  int      enable_deflate; /* default 1 */
  int      enable_brotli;  /* default 1 */

  /* keep-alive pool */
  int      max_keepalive_per_host; /* default 2 */
  uint32_t keepalive_idle_ms;      /* default 15000 */

  /* (optional) response limits/guards could be added here later */
} xorav_http_client_config_t;

/* ---- Public API ---- */

/* Create a long-running client bound to a libuv loop.
 * If resolver==NULL, one is created and owned by the client.
 * easy may be NULL for all defaults.
 */
int xorav_http_client_init(uv_loop_t *loop, xorav_dns_ares_t *resolver,
                           xorav_http_client_t             **out,
                           const xorav_http_client_config_t *easy);

/* Thread-safe submit. Returns 0 on success; negative on failure.
 * -EAGAIN is returned as -11 when bounded queue is full.
 */
int xorav_http_client_submit(xorav_http_client_t    *hc,
                             const xorav_http_req_t *req);

/* Graceful shutdown:
 *   - stops accepting
 *   - drains pending queue
 *   - closes pooled connections
 *   - destroys owned resolver
 * Caller should keep the loop alive until shutdown is complete.
 */
int xorav_http_client_shutdown(xorav_http_client_t *hc,
                               uint32_t             graceful_timeout_ms);

#ifdef __cplusplus
}
#endif
