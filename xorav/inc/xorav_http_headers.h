#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xorav_hdr_kv_s {
  char *name;
  char *value;
} xorav_hdr_kv_t;

typedef struct xorav_headers_s {
  xorav_hdr_kv_t *list;  /* stb_ds dynarray */
} xorav_headers_t;

void   xorav_headers_init (xorav_headers_t *h);
void   xorav_headers_free (xorav_headers_t *h);
int    xorav_headers_set  (xorav_headers_t *h, const char *name, const char *value);
int    xorav_headers_add  (xorav_headers_t *h, const char *name, const char *value);
int    xorav_headers_remove(xorav_headers_t *h, const char *name);
int    xorav_headers_has  (const xorav_headers_t *h, const char *name);
size_t xorav_headers_count(const xorav_headers_t *h);
const xorav_hdr_kv_t* xorav_headers_at(const xorav_headers_t *h, size_t i);

/* Build HTTP/1.1 request line + headers; mallocs out_buf. */
typedef struct xorav_http_config_s xorav_http_config_t; /* fwd */

int xorav_http_build_request_headers(const char *method,
                                     const char *path,
                                     const char *host,
                                     int keep_alive,
                                     const xorav_http_config_t *cfg,
                                     int disable_accept_encoding,
                                     const xorav_headers_t *user_headers,
                                     int has_body,
                                     size_t content_length,
                                     int chunked_upload,
                                     const char *content_type,
                                     unsigned char **out_buf,
                                     size_t *out_len);

#ifdef __cplusplus
}
#endif
