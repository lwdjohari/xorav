#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#include "xorav_http_headers.h"
#include "xorav_http_config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

static int appendf(uint8_t **pbuf, size_t *pcap, size_t *pn, const char *fmt,
                   ...)
{
  va_list ap;
  va_start(ap, fmt);
  int want = vsnprintf((char *)(*pbuf) + *pn, *pcap - *pn, fmt, ap);
  va_end(ap);
  if (want < 0) {
    return -1;
  }

  size_t need =
    *pn + (size_t)want + 1; /* +1 for trailing '\0' kept in buffer */
  if (need > *pcap) {
    size_t cap = *pcap ? *pcap : 256;
    while (cap < need) {
      cap <<= 1;
    }
    uint8_t *nb = (uint8_t *)realloc(*pbuf, cap);
    if (!nb) {
      return -1;
    }
    *pbuf = nb;
    *pcap = cap;

    /* reprint into the enlarged buffer */
    va_start(ap, fmt);
    want = vsnprintf((char *)(*pbuf) + *pn, *pcap - *pn, fmt, ap);
    va_end(ap);
    if (want < 0) {
      return -1;
    }
    need = *pn + (size_t)want + 1;
    if (need > *pcap) {
      return -1; /* extremely unlikely */
    }
  }
  *pn += (size_t)want;
  return 0;
}

static int ieq(const char *a, const char *b)
{
  for (;; a++, b++) {
    int ca = (unsigned char)*a, cb = (unsigned char)*b;
    if (ca >= 'A' && ca <= 'Z') {
      ca += 'a' - 'A';
    }
    if (cb >= 'A' && cb <= 'Z') {
      cb += 'a' - 'A';
    }
    if (ca != cb) {
      return 0;
    }
    if (!ca) {
      return 1;
    }
  }
}

void xorav_headers_init(xorav_headers_t *h)
{
  if (h) {
    h->list = NULL;
  }
}

void xorav_headers_free(xorav_headers_t *h)
{
  if (!h || !h->list) {
    return;
  }
  for (size_t i = 0; i < arrlen(h->list); ++i) {
    free(h->list[i].name);
    free(h->list[i].value);
  }
  arrfree(h->list);
  h->list = NULL;
}

static void remove_key_all(xorav_headers_t *h, const char *name)
{
  if (!h || !h->list) {
    return;
  }
  for (ptrdiff_t i = (ptrdiff_t)arrlen(h->list) - 1; i >= 0; --i) {
    if (ieq(h->list[i].name, name)) {
      free(h->list[i].name);
      free(h->list[i].value);
      arrdel(h->list, i);
    }
  }
}

int xorav_headers_set(xorav_headers_t *h, const char *name, const char *value)
{
  if (!h || !name || !value) {
    return -1;
  }
  remove_key_all(h, name);
  xorav_hdr_kv_t kv = { strdup(name), strdup(value) };
  if (!kv.name || !kv.value) {
    free(kv.name);
    free(kv.value);
    return -1;
  }
  arrpush(h->list, kv);
  return 0;
}

int xorav_headers_add(xorav_headers_t *h, const char *name, const char *value)
{
  if (!h || !name || !value) {
    return -1;
  }
  xorav_hdr_kv_t kv = { strdup(name), strdup(value) };
  if (!kv.name || !kv.value) {
    free(kv.name);
    free(kv.value);
    return -1;
  }
  arrpush(h->list, kv);
  return 0;
}

int xorav_headers_remove(xorav_headers_t *h, const char *name)
{
  if (!h || !name) {
    return -1;
  }
  remove_key_all(h, name);
  return 0;
}

int xorav_headers_has(const xorav_headers_t *h, const char *name)
{
  if (!h || !h->list) {
    return 0;
  }
  for (size_t i = 0; i < arrlen(h->list); ++i) {
    if (ieq(h->list[i].name, name)) {
      return 1;
    }
  }
  return 0;
}

size_t xorav_headers_count(const xorav_headers_t *h)
{
  return (h && h->list) ? (size_t)arrlen(h->list) : 0;
}

const xorav_hdr_kv_t *xorav_headers_at(const xorav_headers_t *h, size_t i)
{
  if (!h || !h->list) {
    return NULL;
  }
  if (i >= (size_t)arrlen(h->list)) {
    return NULL;
  }
  return &h->list[i];
}

/* ------------------- builder ------------------- */
int xorav_http_build_request_headers(const char *method, const char *path,
                                     const char *host, int keep_alive,
                                     const struct xorav_http_config_s *cfg,
                                     int disable_accept_encoding,
                                     const xorav_headers_t *extra, int has_body,
                                     size_t content_length, int chunked_upload,
                                     const char     *content_type,
                                     unsigned char **out_buf, size_t *out_len)
{
  if (!method || !path || !host || !out_buf || !out_len) {
    return -1;
  }

  size_t   cap = 2048;
  uint8_t *buf = (uint8_t *)malloc(cap);
  if (!buf) {
    return -1;
  }
  size_t n = 0;

  /* Request line + required */
  if (appendf(&buf, &cap, &n, "%s %s HTTP/1.1\r\n", method, path) != 0) {
    goto oom;
  }
  if (appendf(&buf, &cap, &n, "Host: %s\r\n", host) != 0) {
    goto oom;
  }
  if (appendf(&buf, &cap, &n, "User-Agent: xorav-http/1.2\r\n") != 0) {
    goto oom;
  }
  if (appendf(&buf, &cap, &n, "Accept: */*\r\n") != 0) {
    goto oom;
  }
  if (appendf(&buf, &cap, &n, "Connection: %s\r\n",
              keep_alive ? "keep-alive" : "close") != 0) {
    goto oom;
  }

  /* Accept-Encoding (unless disabled or user specified one) */
  int have_user_ae = (extra && xorav_headers_has(extra, "Accept-Encoding"));
  if (!disable_accept_encoding && !have_user_ae && cfg) {
    int  first  = 1;
    char ae[64] = { 0 };
    if (cfg->enable_brotli) {
      snprintf(ae + strlen(ae), sizeof(ae) - strlen(ae), "%sbr",
               first ? "" : ", ");
      first = 0;
    }
    if (cfg->enable_gzip) {
      snprintf(ae + strlen(ae), sizeof(ae) - strlen(ae), "%sgzip",
               first ? "" : ", ");
      first = 0;
    }
    if (cfg->enable_deflate) {
      snprintf(ae + strlen(ae), sizeof(ae) - strlen(ae), "%sdeflate",
               first ? "" : ", ");
      first = 0;
    }
    if (ae[0]) {
      if (appendf(&buf, &cap, &n, "Accept-Encoding: %s\r\n", ae) != 0) {
        goto oom;
      }
    }
  }

  /* Body headers */
  if (has_body) {
    if (content_type && *content_type) {
      if (appendf(&buf, &cap, &n, "Content-Type: %s\r\n", content_type) != 0) {
        goto oom;
      }
    }
    if (chunked_upload) {
      if (appendf(&buf, &cap, &n, "Transfer-Encoding: chunked\r\n") != 0) {
        goto oom;
      }
    } else if (content_length > 0) {
      if (appendf(&buf, &cap, &n, "Content-Length: %zu\r\n", content_length) !=
          0) {
        goto oom;
      }
    }
  }

  /* Extra headers (as provided, duplicates allowed) */
  if (extra && extra->list) {
    int m = arrlen(extra->list);
    for (int i = 0; i < m; ++i) {
      const char *k = extra->list[i].name;
      const char *v = extra->list[i].value;
      if (k && v) {
        if (appendf(&buf, &cap, &n, "%s: %s\r\n", k, v) != 0) {
          goto oom;
        }
      }
    }
  }

  /* End of headers */
  if (appendf(&buf, &cap, &n, "\r\n") != 0) {
    goto oom;
  }

  *out_buf = buf;
  *out_len = n;
  return 0;

oom:
  free(buf);
  return -1;
}
