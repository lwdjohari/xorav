#include "xorav_http_client.h"
#include "xorav_http_config.h"
#include "xorav_http_headers.h"
#include "xorav_http_compress.h"
#include "xorav_dns_ares.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <ares.h>
#include <uv.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <io.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <fcntl.h>
#  include <unistd.h>
#  include <errno.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "uthash.h"

/* ===========================
 * Internal config mirror
 * =========================== */
typedef xorav_http_config_t cfg_t;

/* ===========================
 * Client (queue + inflight + KA pool)
 * =========================== */
typedef struct request_s    request_t;
typedef struct conn_s       conn_t;

typedef struct pool_bucket_s {
  char          *host;
  int            port;
  int            use_tls;
  conn_t        *idle_head; /* singly-linked list of idle */
  int            idle_count;
  UT_hash_handle hh;
} pool_bucket_t;

struct xorav_http_client_s {
  uv_loop_t        *loop;
  xorav_dns_ares_t *resolver;
  int               resolver_owned;

  /* queue (thread-safe) */
  uv_mutex_t        q_mu;
  request_t        *q_head, *q_tail;
  int               q_len;
  int               q_max; /* 0 => unbounded */

  /* inflight (loop-thread only) */
  request_t        *in_head;
  int               in_count;
  int               in_max; /* concurrency */

  /* keep-alive pool (loop-thread only) */
  pool_bucket_t    *pool; /* uthash by (host) (port) (tls) */
  cfg_t             defcfg;

  /* signal for queue scheduling */
  uv_async_t        kick;

  /* accepting flag */
  int               accepting;
};

/* ===========================
 * Connections
 * =========================== */
struct conn_s {
  /* pool key */
  char                       *host;
  int                         port;
  int                         use_tls;

  /* owner */
  struct xorav_http_client_s *owner;

  /* uv + socket + TLS */
  uv_tcp_t                    tcp;
  int                         tcp_inited;
  uv_poll_t                   poll;
  int                         poll_inited;
  int                         fd;
  uv_connect_t                conn_req;

  SSL_CTX                    *ssl_ctx;
  SSL                        *ssl;
  int                         tls_ready;

  /* idle & reuse */
  conn_t                     *next_idle;
  uint64_t                    last_used_ms;
  int                         idle;

  /* attached request */
  request_t                  *cur;
};

/* ===========================
 * Request state & decoder
 * =========================== */
typedef enum {
  ST_INIT = 0,
  ST_RESOLVING,
  ST_CONNECTING,
  ST_TLS_HS,
  ST_REQ_WRITE,
  ST_STREAM_BODY,
  ST_READING,
  ST_DONE,
  ST_FAIL
} req_state_e;

typedef struct {
  xorav_dec_kind_e kind;
  xorav_decoder_t  dec;
} decoder_t;

typedef struct {
  uint8_t *data;
  size_t   len;
  size_t   off;
} outbuf_t;

struct request_s {
  /* queue/inflight linkage */
  request_t                  *q_next;
  request_t                  *in_next;

  /* owner */
  struct xorav_http_client_s *owner;

  /* user request */
  xorav_http_req_t            u;
  cfg_t                       cfg;

  /* parsed URL */
  int                         use_tls;
  char                       *host;
  int                         port;
  char                       *path;

  /* timers */
  uv_timer_t                  total_timer;
  int                         total_timer_started;

  /* connection */
  conn_t                     *conn;

  /* write pipeline */
  outbuf_t                    w_pending;
  const uint8_t              *body_ptr;
  size_t                      body_left;      /* fixed body */
  int                         chunked_upload; /* upload uses TE: chunked */
  int                         upload_eof;

  /* HTTP parsing */
  req_state_e                 st;
  char                       *hdr;
  size_t                      hdr_len, hdr_cap;
  int                         header_complete;
  int                         http_status;
  int                         te_chunked;
  int                         keep_alive_ok;

  /* decoder */
  decoder_t                   d;

  /* chunked body tracking */
  size_t                      chunk_rem;
  int                         chunk_done;

  int                         finished;
};

/* ===========================
 * Utilities
 * =========================== */
static int set_nonblock_socket(int fd)
{
#ifdef _WIN32
  u_long on = 1;
  return ioctlsocket((SOCKET)fd, FIONBIO, &on) == 0 ? 0 : -1;
#else
  int f = fcntl(fd, F_GETFL, 0);
  return fcntl(fd, F_SETFL, f | O_NONBLOCK);
#endif
}

static const void *memfind(const void *hay, size_t haylen, const char *needle,
                           size_t nlen)
{
  if (!hay || !needle || nlen == 0 || haylen < nlen) {
    return NULL;
  }
  const unsigned char *p = (const unsigned char *)hay;
  for (size_t i = 0; i + nlen <= haylen; i++) {
    if (memcmp(p + i, needle, nlen) == 0) {
      return p + i;
    }
  }
  return NULL;
}

static int ascii_ieq(const char *a, const char *b)
{
  while (*a && *b) {
    char ca = (*a >= 'A' && *a <= 'Z') ? *a - 'A' + 'a' : *a;
    char cb = (*b >= 'A' && *b <= 'Z') ? *b - 'A' + 'a' : *b;
    if (ca != cb) {
      return 0;
    }
    a++;
    b++;
  }
  return *a == 0 && *b == 0;
}

/* SSRF guard (v4/v6) */
static int is_private_v4(const struct in_addr *a)
{
  uint32_t x = ntohl(a->s_addr);
  if ((x & 0xFF000000u) == 0x0A000000u) {
    return 1; /* 10.0.0.0/8 */
  }
  if ((x & 0xFFF00000u) == 0xAC100000u) {
    return 1; /* 172.16.0.0/12 */
  }
  if ((x & 0xFFFF0000u) == 0xC0A80000u) {
    return 1; /* 192.168.0.0/16 */
  }
  if ((x & 0xFF000000u) == 0x7F000000u) {
    return 1; /* 127.0.0.0/8 */
  }
  if ((x & 0xFFFF0000u) == 0xA9FE0000u) {
    return 1; /* 169.254.0.0/16 */
  }
  return 0;
}

static int is_private_v6(const struct in6_addr *a6)
{
  const unsigned char *p = (const unsigned char *)a6->s6_addr;
  if ((p[0] & 0xFE) == 0xFC) {
    return 1; /* fc00::/7 */
  }
  if (p[0] == 0xFE && (p[1] & 0xC0) == 0x80) {
    return 1; /* fe80::/10 */
  }
  static const unsigned char loop[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 1 };
  if (memcmp(p, loop, 16) == 0) {
    return 1; /* ::1 */
  }
  return 0;
}

/* URL parse */
static int parse_url(const char *url, int *use_tls, char **host, int *port,
                     char **path)
{
  *use_tls      = 0;
  *host         = NULL;
  *port         = 0;
  *path         = NULL;
  const char *p = strstr(url, "://");
  if (!p) {
    return -1;
  }
  int https = (strncasecmp(url, "https", 5) == 0);
  int http  = (strncasecmp(url, "http", 4) == 0);
  if (!https && !http) {
    return -2;
  }

  *use_tls          = https ? 1 : 0;
  const char *h     = p + 3;
  const char *slash = strchr(h, '/');
  if (!slash) {
    slash = url + strlen(url);
  }
  const char *colon = memchr(h, ':', (size_t)(slash - h));
  int         prt   = https ? 443 : 80;
  size_t      hlen;
  if (colon && colon < slash) {
    hlen = (size_t)(colon - h);
    prt  = atoi(colon + 1);
  } else {
    hlen = (size_t)(slash - h);
  }

  char *H = (char *)malloc(hlen + 1);
  if (!H) {
    return -3;
  }
  memcpy(H, h, hlen);
  H[hlen] = 0;

  const char *pa = slash;
  if (!*pa) {
    pa = "/";
  }
  char *P = strdup(pa);
  if (!P) {
    free(H);
    return -3;
  }

  *host = H;
  *port = prt;
  *path = P;
  return 0;
}

/* ===========================
 * Pool helpers
 * =========================== */
static uint64_t now_ms(uv_loop_t *loop)
{
  return uv_now(loop);
}

static void pool_bucket_key(pool_bucket_t **h, const char *host, int port,
                            int use_tls, pool_bucket_t **out)
{
  for (pool_bucket_t *b = *h; b; b = b->hh.next) {
    if (b->port == port && b->use_tls == use_tls &&
        strcmp(b->host, host) == 0) {
      *out = b;
      return;
    }
  }
  *out = NULL;
}

static pool_bucket_t *pool_bucket_get_or_make(struct xorav_http_client_s *hc,
                                              const char *host, int port,
                                              int use_tls)
{
  pool_bucket_t *b = NULL;
  pool_bucket_key(&hc->pool, host, port, use_tls, &b);
  if (b) {
    return b;
  }
  b             = (pool_bucket_t *)calloc(1, sizeof(*b));
  b->host       = strdup(host);
  b->port       = port;
  b->use_tls    = use_tls;
  b->idle_head  = NULL;
  b->idle_count = 0;
  HASH_ADD_KEYPTR(hh, hc->pool, b->host, strlen(b->host), b);
  return b;
}

static conn_t *pool_take(struct xorav_http_client_s *hc, const char *host,
                         int port, int use_tls, uint64_t now)
{
  pool_bucket_t *b = NULL;
  pool_bucket_key(&hc->pool, host, port, use_tls, &b);
  if (!b || !b->idle_head) {
    return NULL;
  }
  conn_t *c    = b->idle_head;
  b->idle_head = c->next_idle;
  c->next_idle = NULL;
  b->idle_count--;
  c->idle         = 0;
  c->last_used_ms = now;
  return c;
}

static void conn_close_free(conn_t *c)
{
  if (!c) {
    return;
  }
  if (c->poll_inited) {
    uv_poll_stop(&c->poll);
    if (!uv_is_closing((uv_handle_t *)&c->poll)) {
      uv_close((uv_handle_t *)&c->poll, NULL);
    }
  }
  if (c->tcp_inited) {
    if (!uv_is_closing((uv_handle_t *)&c->tcp)) {
      uv_close((uv_handle_t *)&c->tcp, NULL);
    }
  }
  if (c->ssl) {
    if (c->use_tls) {
      SSL_shutdown(c->ssl);
    }
    SSL_free(c->ssl);
  }
  if (c->ssl_ctx) {
    SSL_CTX_free(c->ssl_ctx);
  }
  free(c->host);
  free(c);
}

static void pool_put(struct xorav_http_client_s *hc, conn_t *c, uint64_t now)
{
  pool_bucket_t *b = pool_bucket_get_or_make(hc, c->host, c->port, c->use_tls);
  if (b->idle_count >= hc->defcfg.max_keepalive_per_host) {
    conn_close_free(c);
    return;
  }
  c->idle         = 1;
  c->last_used_ms = now;
  c->next_idle    = b->idle_head;
  b->idle_head    = c;
  b->idle_count++;
}

/* ===========================
 * IO helpers
 * =========================== */
static int io_write(conn_t *c, const uint8_t *buf, size_t len, size_t *wrote)
{
  *wrote = 0;
  if (c->use_tls) {
    int w = SSL_write(c->ssl, buf, (int)len);
    if (w > 0) {
      *wrote = (size_t)w;
      return 0;
    }
    int e = SSL_get_error(c->ssl, w);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
      return 1;
    }
    return -1;
  } else {
#ifdef _WIN32
    int w = send(c->fd, (const char *)buf, (int)len, 0);
    if (w > 0) {
      *wrote = (size_t)w;
      return 0;
    }
    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK) {
      return 1;
    }
    return -1;
#else
    ssize_t w = send(c->fd, buf, len, MSG_NOSIGNAL);
    if (w > 0) {
      *wrote = (size_t)w;
      return 0;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 1;
    }
    return -1;
#endif
  }
}

static int io_read(conn_t *c, uint8_t *buf, size_t cap, int *got)
{
  *got = 0;
  if (c->use_tls) {
    int rr = SSL_read(c->ssl, buf, (int)cap);
    if (rr > 0) {
      *got = rr;
      return 0;
    }
    int e = SSL_get_error(c->ssl, rr);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
      return 1;
    }
    if (rr == 0) {
      *got = 0;
      return 0;
    } /* EOF */
    return -1;
  } else {
#ifdef _WIN32
    int rr = recv(c->fd, (char *)buf, (int)cap, 0);
    if (rr > 0) {
      *got = rr;
      return 0;
    }
    if (rr == 0) {
      *got = 0;
      return 0;
    }
    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK) {
      return 1;
    }
    return -1;
#else
    ssize_t rr = recv(c->fd, buf, cap, 0);
    if (rr > 0) {
      *got = (int)rr;
      return 0;
    }
    if (rr == 0) {
      *got = 0;
      return 0;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 1;
    }
    return -1;
#endif
  }
}

/* ===========================
 * Start-line + headers
 * =========================== */
static const char *method_str(xorav_http_method_e m)
{
  switch (m) {
    case XORAV_HTTP_GET:
      return "GET";
    case XORAV_HTTP_HEAD:
      return "HEAD";
    case XORAV_HTTP_POST:
      return "POST";
    case XORAV_HTTP_PUT:
      return "PUT";
    case XORAV_HTTP_DELETE:
      return "DELETE";
    case XORAV_HTTP_PATCH:
      return "PATCH";
    default:
      return "GET";
  }
}

static int build_start_headers(request_t *r, int keep_alive)
{
  unsigned char  *buf = NULL;
  size_t          n   = 0;

  /* Convert legacy pairs into a bag for uniform path (unless user provided a
   * bag) */
  xorav_headers_t bag, *use = NULL;
  xorav_headers_init(&bag);
  if (r->u.headers_map) {
    use = (xorav_headers_t *)
            r->u.headers_map; /* safe cast; constness: we don't modify */
  } 

  const int disable_ae = (r->u.flags & XORAV_HTTP_F_NO_COMPRESS) ? 1 : 0;
  const int has_body =
    (r->u.method == XORAV_HTTP_POST || r->u.method == XORAV_HTTP_PUT ||
     r->u.method == XORAV_HTTP_PATCH);
  const size_t clen    = (r->u.body && r->u.body_len)
                           ? r->u.body_len
                           : (r->u.on_body_read && r->u.content_length > 0 &&
                               !(r->u.flags & XORAV_HTTP_F_FORCE_CHUNKED)
                                ? r->u.content_length
                                : 0);
  const int    chunked = (r->u.on_body_read && (clen == 0)) ||
                      (r->u.flags & XORAV_HTTP_F_FORCE_CHUNKED);

  int rc = xorav_http_build_request_headers(
    method_str(r->u.method), r->path, r->host, keep_alive, &r->cfg, disable_ae,
    use, has_body, clen, chunked, r->u.content_type, &buf, &n);

  if (!r->u.headers_map) {
    xorav_headers_free(&bag);
  }
  if (rc != 0) {
    return -1;
  }

  r->w_pending.data = buf;
  r->w_pending.len  = n;
  r->w_pending.off  = 0;
  return 0;
}

/* ===========================
 * Header parse & decoder init
 * =========================== */
static int parse_headers_and_init_decoder(request_t *r)
{
  char *eoh = (char *)memfind(r->hdr, r->hdr_len, "\r\n\r\n", 4);
  if (!eoh) {
    return -1;
  }
  char *line1_end = (char *)memfind(r->hdr, r->hdr_len, "\r\n", 2);
  if (!line1_end) {
    return -1;
  }

  *line1_end = 0;
  if (strncmp(r->hdr, "HTTP/1.", 7) != 0) {
    *line1_end = '\r';
    return -1;
  }
  r->http_status = atoi(r->hdr + 9);
  *line1_end     = '\r';

  xorav_dec_kind_e codec = XORAV_DEC_ID;
  r->keep_alive_ok       = 1;
  int   te_chunked       = 0;

  char *p = line1_end + 2;
  while (p < eoh) {
    char *nl = strstr(p, "\r\n");
    if (!nl) {
      break;
    }
    *nl         = 0;
    char *colon = strchr(p, ':');
    if (colon) {
      *colon     = 0;
      char *name = p;
      char *val  = colon + 1;
      while (*val == ' ' || *val == '\t') {
        val++;
      }
      if (ascii_ieq(name, "Content-Encoding")) {
        if (strstr(val, "br")) {
          codec = XORAV_DEC_BR;
        } else if (strstr(val, "gzip") || strstr(val, "deflate")) {
          codec = XORAV_DEC_Z;
        }
      } else if (ascii_ieq(name, "Transfer-Encoding")) {
        if (strstr(val, "chunked")) {
          te_chunked = 1;
        }
      } else if (ascii_ieq(name, "Connection")) {
        if (strstr(val, "close")) {
          r->keep_alive_ok = 0;
        }
      }
      *colon = ':';
    }
    *nl = '\r';
    p   = nl + 2;
  }

  if ((r->u.flags & XORAV_HTTP_F_NO_DECOMPRESS)) {
    codec = XORAV_DEC_ID;
  }
  if (!r->cfg.enable_brotli && codec == XORAV_DEC_BR) {
    codec = XORAV_DEC_ID;
  }
  if (!r->cfg.enable_gzip && codec == XORAV_DEC_Z) {
    codec = XORAV_DEC_ID;
  }

  r->d.kind = codec;
  if (xorav_dec_init(&r->d.dec, codec, &r->cfg) != 0) {
    return -1;
  }

  r->te_chunked      = te_chunked;
  r->header_complete = 1;

  if (r->u.on_headers) {
    size_t raw_len = (size_t)((eoh + 4) - r->hdr);
    r->u.on_headers(r->http_status, r->hdr, raw_len, r->u.user);
  }
  return 0;
}

/* ===========================
 * Upload helpers
 * =========================== */
static int flush_pending(conn_t *c, outbuf_t *w)
{
  while (w->off < w->len) {
    size_t wrote = 0;
    int    rc    = io_write(c, w->data + w->off, w->len - w->off, &wrote);
    if (rc == 0) {
      w->off += wrote;
      continue;
    }
    if (rc == 1) {
      return 1;
    }
    return -1;
  }
  return 0;
}

static int upload_stream_chunked(request_t *r)
{
  uint8_t tmp[16 * 1024];
  while (!r->upload_eof) {
    int    eof = 0;
    size_t got = r->u.on_body_read(tmp, sizeof tmp, &eof, r->u.user);
    if (got == SIZE_MAX) {
      return -1;
    }
    if (eof && got == 0) {
      const char tail[] = "0\r\n\r\n";
      r->w_pending.data = (uint8_t *)malloc(sizeof(tail) - 1);
      if (!r->w_pending.data) {
        return -1;
      }
      memcpy(r->w_pending.data, tail, sizeof(tail) - 1);
      r->w_pending.len = sizeof(tail) - 1;
      r->w_pending.off = 0;
      int fp           = flush_pending(r->conn, &r->w_pending);
      free(r->w_pending.data);
      r->w_pending.data = NULL;
      if (fp != 0) {
        return (fp == 1) ? 1 : -1;
      }
      r->upload_eof = 1;
      return 0;
    }
    char     head[32];
    int      hn        = snprintf(head, sizeof head, "%zx\r\n", got);
    size_t   block_len = (size_t)hn + got + 2;
    uint8_t *blk       = (uint8_t *)malloc(block_len);
    if (!blk) {
      return -1;
    }
    memcpy(blk, head, hn);
    memcpy(blk + hn, tmp, got);
    blk[hn + got]     = '\r';
    blk[hn + got + 1] = '\n';
    r->w_pending.data = blk;
    r->w_pending.len  = block_len;
    r->w_pending.off  = 0;
    int fp            = flush_pending(r->conn, &r->w_pending);
    free(blk);
    r->w_pending.data = NULL;
    if (fp != 0) {
      return (fp == 1) ? 1 : -1;
    }
  }
  return 0;
}

static int upload_stream_fixed(request_t *r)
{
  uint8_t tmp[16 * 1024];
  size_t  remain = r->u.content_length;
  while (remain > 0) {
    int    eof  = 0;
    size_t want = remain < sizeof tmp ? remain : sizeof tmp;
    size_t got  = r->u.on_body_read(tmp, want, &eof, r->u.user);
    if (got == SIZE_MAX) {
      return -1;
    }
    if (got == 0 && eof) {
      return -1; /* premature EOF */
    }
    if (got > remain) {
      return -1;
    }

    r->w_pending.data = (uint8_t *)malloc(got);
    if (!r->w_pending.data) {
      return -1;
    }
    memcpy(r->w_pending.data, tmp, got);
    r->w_pending.len = got;
    r->w_pending.off = 0;
    int fp           = flush_pending(r->conn, &r->w_pending);
    free(r->w_pending.data);
    r->w_pending.data = NULL;
    if (fp != 0) {
      return (fp == 1) ? 1 : -1;
    }
    remain -= got;
  }
  return 0;
}

/* ===========================
 * Reading (headers + body)
 * =========================== */
static int drive_reading(request_t *r)
{
  uint8_t buf[16384];
  for (;;) {
    int got = 0;
    int rc  = io_read(r->conn, buf, sizeof buf, &got);
    if (rc == 1) {
      return 1;
    }
    if (rc < 0) {
      return -1;
    }
    if (got == 0) {
      if (!r->header_complete) {
        return -1;
      }
      if (r->u.on_complete) {
        r->u.on_complete(r->http_status, NULL, r->u.user);
      }
      r->st = ST_DONE;
      return 0;
    }

    size_t off = 0;

    if (!r->header_complete) {
      if (r->hdr_cap == 0) {
        r->hdr_cap = 8192;
        r->hdr     = (char *)malloc(r->hdr_cap);
      }
      while (!r->header_complete && off < (size_t)got) {
        if (r->hdr_len + 1 >= r->hdr_cap) {
          r->hdr_cap *= 2;
          r->hdr      = (char *)realloc(r->hdr, r->hdr_cap);
        }
        r->hdr[r->hdr_len++] = buf[off++];
        r->hdr[r->hdr_len]   = 0;
        if (r->hdr_len >= 4 && memfind(r->hdr, r->hdr_len, "\r\n\r\n", 4)) {
          if (parse_headers_and_init_decoder(r) != 0) {
            return -1;
          }
        }
      }
      if (!r->header_complete) {
        continue;
      }
    }

    const uint8_t *p = buf + off;
    size_t         n = (size_t)got - off;

    while (n) {
      if (r->te_chunked) {
        if (r->chunk_rem == 0 && !r->chunk_done) {
          const uint8_t *crlf = (const uint8_t *)memfind(p, n, "\r\n", 2);
          if (!crlf) {
            return 1;
          }
          char   szbuf[32] = { 0 };
          size_t line      = (size_t)(crlf - p);
          size_t cpy = (line < sizeof szbuf - 1) ? line : sizeof szbuf - 1;
          memcpy(szbuf, p, cpy);
          r->chunk_rem  = strtoul(szbuf, NULL, 16);
          p             = crlf + 2;
          n            -= (line + 2);
          if (r->chunk_rem == 0) {
            r->chunk_done = 1;
            r->st         = ST_DONE;
            if (r->u.on_complete) {
              r->u.on_complete(r->http_status, NULL, r->u.user);
            }
            return 0;
          }
        }
        size_t take = (n < r->chunk_rem) ? n : r->chunk_rem;
        if (take) {
          if (!(r->u.flags & XORAV_HTTP_F_NO_DECOMPRESS)) {
            if (xorav_dec_feed(&r->d.dec, p, take, r->u.on_data, r->u.user) !=
                0) {
              return -1;
            }
          } else {
            if (r->u.on_data && r->u.on_data(p, take, r->u.user) != 0) {
              return -1;
            }
          }
          p            += take;
          n            -= take;
          r->chunk_rem -= take;
        }
        if (r->chunk_rem == 0 && n >= 2) {
          if (p[0] == '\r' && p[1] == '\n') {
            p += 2;
            n -= 2;
          }
        }
      } else {
        if (!(r->u.flags & XORAV_HTTP_F_NO_DECOMPRESS)) {
          if (xorav_dec_feed(&r->d.dec, p, n, r->u.on_data, r->u.user) != 0) {
            return -1;
          }
        } else {
          if (r->u.on_data && r->u.on_data(p, n, r->u.user) != 0) {
            return -1;
          }
        }
        n = 0;
      }
    }
  }
}

/* ===========================
 * Events
 * =========================== */
static void request_fail(request_t *r, const char *msg)
{
  if (r->u.on_complete) {
    r->u.on_complete(-1, msg, r->u.user);
  }
  r->st = ST_FAIL;
}

static void total_timeout_cb(uv_timer_t *t)
{
  request_t *r = (request_t *)t->data;
  request_fail(r, "timeout");
}

static void on_poll(uv_poll_t *h, int status, int events)
{
  (void)status;
  (void)events;
  conn_t    *c = (conn_t *)h->data;
  request_t *r = c->cur;
  if (!r) {
    return;
  }

  if (r->st == ST_TLS_HS && c->use_tls) {
    int k = SSL_do_handshake(c->ssl);
    if (k == 1) {
      c->tls_ready = 1;
      r->st        = ST_REQ_WRITE;
    } else {
      return; /* WANT_{READ,WRITE} */
    }
  }

  if (r->st == ST_REQ_WRITE) {
    int fp = flush_pending(c, &r->w_pending);
    if (fp < 0) {
      request_fail(r, "write");
      return;
    }
    if (fp == 0) {
      if (r->u.on_body_read) {
        r->st = ST_STREAM_BODY;
      } else {
        r->st = ST_READING;
      }
    }
  }

  if (r->st == ST_STREAM_BODY) {
    int up_rc =
      r->chunked_upload ? upload_stream_chunked(r) : upload_stream_fixed(r);
    if (up_rc < 0) {
      request_fail(r, "upload");
      return;
    }
    if (up_rc == 1) {
      return; /* need poll again */
    }
    r->st = ST_READING;
  }

  if (r->st == ST_READING) {
    int rr = drive_reading(r);
    if (rr < 0) {
      request_fail(r, "read");
      return;
    }
    if (r->st == ST_DONE) {
      xorav_dec_free(&r->d.dec);
    }
  }
}

static void on_connect(uv_connect_t *req, int status)
{
  conn_t    *c = (conn_t *)req->handle->data;
  request_t *r = c->cur;
  if (status) {
    request_fail(r, uv_strerror(status));
    return;
  }

  if (uv_fileno((const uv_handle_t *)&c->tcp, &c->fd) != 0) {
    request_fail(r, "uv_fileno");
    return;
  }
  set_nonblock_socket(c->fd);

  if (c->use_tls) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    c->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ssl_ctx) {
      request_fail(r, "SSL_CTX_new");
      return;
    }
#ifdef TLS1_3_VERSION
    SSL_CTX_set_max_proto_version(c->ssl_ctx, TLS1_3_VERSION);
#else
    SSL_CTX_set_max_proto_version(c->ssl_ctx, XORAV_TLS1_3);
#endif
    SSL_CTX_set_min_proto_version(c->ssl_ctx, r->cfg.tls_min_version
                                                ? r->cfg.tls_min_version
                                                : XORAV_TLS1_2);

    if (!(r->u.flags & XORAV_HTTP_F_INSECURE_TLS)) {
      SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_PEER, NULL);
      SSL_CTX_set_default_verify_paths(c->ssl_ctx);
    }

    /* ALPN: h2 and http/1.1 (we use HTTP/1.1 code path) */
    const unsigned char alpn[] = { 2,   'h', '2', 8,   'h', 't',
                                   't', 'p', '/', '1', '.', '1' };
    SSL_CTX_set_alpn_protos(c->ssl_ctx, alpn, sizeof(alpn));
    c->ssl = SSL_new(c->ssl_ctx);
    if (!c->ssl) {
      request_fail(r, "SSL_new");
      return;
    }
    SSL_set_tlsext_host_name(c->ssl, r->host);
    if (!(r->u.flags & XORAV_HTTP_F_INSECURE_TLS)) {
      SSL_set1_host(c->ssl, r->host);
    }
    SSL_set_fd(c->ssl, c->fd);
    SSL_set_connect_state(c->ssl);
    r->st = ST_TLS_HS;
  } else {
    r->st = ST_REQ_WRITE;
  }

  if (build_start_headers(r, /*keep_alive*/ 1) != 0) {
    request_fail(r, "oom-headers");
    return;
  }

  int rc = uv_poll_init_socket(r->owner->loop, &c->poll, c->fd);
  if (rc) {
    request_fail(r, "uv_poll_init_socket");
    return;
  }
  c->poll_inited = 1;
  c->poll.data   = c;

  if (r->st == ST_TLS_HS) {
    int k = SSL_do_handshake(c->ssl);
    if (k == 1) {
      c->tls_ready = 1;
      r->st        = ST_REQ_WRITE;
    }
  }
  uv_poll_start(&c->poll, UV_READABLE | UV_WRITABLE, on_poll);
}

/* ===========================
 * DNS callback
 * =========================== */
static void dns_cb(int status, const char *host, const char *ip, void *user)
{
  (void)host;
  request_t *r = (request_t *)user;
  if (status != ARES_SUCCESS || !ip) {
    request_fail(r, "dns");
    return;
  }

  struct in_addr  v4;
  struct in6_addr v6;
  if (!r->cfg.allow_private_ip) {
    if (inet_pton(AF_INET, ip, &v4) == 1 && is_private_v4(&v4)) {
      request_fail(r, "ssrf_ipv4");
      return;
    }
    if (inet_pton(AF_INET6, ip, &v6) == 1 && is_private_v6(&v6)) {
      request_fail(r, "ssrf_ipv6");
      return;
    }
  }

  struct sockaddr_storage ss;
  int                     slen = 0;
  if (inet_pton(AF_INET, ip, &v4) == 1) {
    struct sockaddr_in sa = { 0 };
    sa.sin_family         = AF_INET;
    sa.sin_port           = htons((unsigned)r->port);
    sa.sin_addr           = v4;
    memcpy(&ss, &sa, sizeof sa);
    slen = sizeof sa;
  } else {
    struct sockaddr_in6 sa6 = { 0 };
    sa6.sin6_family         = AF_INET6;
    sa6.sin6_port           = htons((unsigned)r->port);
    sa6.sin6_addr           = v6;
    memcpy(&ss, &sa6, sizeof sa6);
    slen = sizeof sa6;
  }

  conn_t *c  = r->conn;
  int     rc = uv_tcp_init(r->owner->loop, &c->tcp);
  if (rc) {
    request_fail(r, "uv_tcp_init");
    return;
  }
  c->tcp_inited = 1;
  c->tcp.data   = c;

  rc = uv_tcp_connect(&c->conn_req, &c->tcp, (const struct sockaddr *)&ss,
                      on_connect);
  if (rc) {
    request_fail(r, "uv_tcp_connect");
    return;
  }
}

/* ===========================
 * Scheduling
 * =========================== */
static void request_free(request_t *r)
{
  if (!r) {
    return;
  }
  if (r->hdr) {
    free(r->hdr);
  }
  if (r->w_pending.data) {
    free(r->w_pending.data);
  }
  if (r->total_timer_started) {
    uv_timer_stop(&r->total_timer);
  }
  if (!uv_is_closing((uv_handle_t *)&r->total_timer)) {
    uv_close((uv_handle_t *)&r->total_timer, NULL);
  }
  free(r->host);
  free(r->path);
  free(r);
}

static void finish_request_and_recycle(request_t *r)
{
  xorav_http_client_t *hc = r->owner;
  conn_t              *c  = r->conn;

  int                  recycle = (r->st == ST_DONE) && r->keep_alive_ok;
  if (recycle && c && c->tcp_inited && c->poll_inited) {
    uv_poll_stop(&c->poll);
    c->cur = NULL;
    pool_put(hc, c, now_ms(hc->loop));
  } else {
    conn_close_free(c);
  }

  request_t **pp = &hc->in_head;
  while (*pp) {
    if (*pp == r) {
      *pp = r->in_next;
      break;
    }
    pp = &(*pp)->in_next;
  }
  hc->in_count--;
  request_free(r);
}

static void maybe_schedule(xorav_http_client_t *hc)
{
  while (hc->in_count < hc->in_max && hc->q_head) {
    request_t *r = hc->q_head;
    hc->q_head   = r->q_next;
    if (!hc->q_head) {
      hc->q_tail = NULL;
    }
    hc->q_len--;
    r->in_next  = hc->in_head;
    hc->in_head = r;
    hc->in_count++;

    uv_timer_init(hc->loop, &r->total_timer);
    r->total_timer.data    = r;
    r->total_timer_started = 1;
    uv_timer_start(&r->total_timer, total_timeout_cb, r->cfg.total_timeout_ms,
                   0);

    /* Try pool reuse */
    conn_t *c = pool_take(hc, r->host, r->port, r->use_tls, now_ms(hc->loop));
    if (c) {
      r->conn = c;
      c->cur  = r;
      if (!c->poll_inited) {
        uv_poll_init_socket(hc->loop, &c->poll, c->fd);
        c->poll_inited = 1;
        c->poll.data   = c;
      }
      if (build_start_headers(r, /*keep_alive*/ 1) != 0) {
        request_fail(r, "oom-headers");
        continue;
      }
      if (c->use_tls && !c->tls_ready) {
        r->st = ST_TLS_HS;
      } else {
        r->st = ST_REQ_WRITE;
      }
      uv_poll_start(&c->poll, UV_READABLE | UV_WRITABLE, on_poll);
      continue;
    }

    /* Fresh connection path: DNS first */
    c          = (conn_t *)calloc(1, sizeof(*c));
    c->owner   = hc;
    c->host    = strdup(r->host);
    c->port    = r->port;
    c->use_tls = r->use_tls;
    c->cur     = r;
    r->conn    = c;
    r->st      = ST_RESOLVING;
    if (xorav_dns_ares_resolve(hc->resolver, r->host, dns_cb, r) != 0) {
      request_fail(r, "dns-submit");
    }
  }

  /* Finish any completed/failed requests in the inflight list */
  request_t *prev = NULL, *cur = hc->in_head;
  while (cur) {
    if (cur->st == ST_DONE || cur->st == ST_FAIL) {
      request_t *dead = cur;
      cur             = cur->in_next;
      if (prev) {
        prev->in_next = cur;
      } else {
        hc->in_head = cur;
      }
      hc->in_count--;
      finish_request_and_recycle(dead);
    } else {
      prev = cur;
      cur  = cur->in_next;
    }
  }
}

static void kick_cb(uv_async_t *a)
{
  xorav_http_client_t *hc = (xorav_http_client_t *)a->data;
  maybe_schedule(hc);
}

/* ===========================
 * Public API
 * =========================== */
int xorav_http_client_init(uv_loop_t *loop, xorav_dns_ares_t *resolver,
                                xorav_http_client_t             **out,
                                const xorav_http_client_config_t *easy)
{
  if (!loop || !out) {
    return -1;
  }
  *out = NULL;

  xorav_http_client_t *hc = (xorav_http_client_t *)calloc(1, sizeof(*hc));
  if (!hc) {
    return -1;
  }
  hc->loop = loop;

  if (resolver) {
    hc->resolver       = resolver;
    hc->resolver_owned = 0;
  } else {
    if (xorav_dns_ares_init(&hc->resolver, loop) != ARES_SUCCESS) {
      free(hc);
      return -1;
    }
    hc->resolver_owned = 1;
  }

  uv_mutex_init(&hc->q_mu);
  hc->q_max     = (easy && easy->max_queued > 0) ? easy->max_queued : 0;
  hc->in_max    = (easy && easy->max_inflight > 0) ? easy->max_inflight : 32;
  hc->accepting = 1;
  hc->pool      = NULL;

  xorav_http_config_secure_defaults(&hc->defcfg);
  if (easy) {
    if (easy->total_timeout_ms) {
      hc->defcfg.total_timeout_ms = easy->total_timeout_ms;
    }
    hc->defcfg.allow_private_ip = easy->allow_private_ip;
    if (easy->tls_min_version) {
      hc->defcfg.tls_min_version = easy->tls_min_version;
    }
    hc->defcfg.enable_gzip    = easy->enable_gzip;
    hc->defcfg.enable_deflate = easy->enable_deflate;
    hc->defcfg.enable_brotli  = easy->enable_brotli;
    if (easy->max_keepalive_per_host > 0) {
      hc->defcfg.max_keepalive_per_host = easy->max_keepalive_per_host;
    }
    if (easy->keepalive_idle_ms > 0) {
      hc->defcfg.keepalive_idle_ms = easy->keepalive_idle_ms;
    }
  }

  uv_async_init(loop, &hc->kick, kick_cb);
  hc->kick.data = hc;

  *out = hc;
  return 0;
}

int xorav_http_client_submit(xorav_http_client_t    *hc,
                             const xorav_http_req_t *req)
{
  if (!hc || !req || !req->url || !req->on_complete) {
    return -1;
  }
  if (!hc->accepting) {
    return -1;
  }

  request_t *r = (request_t *)calloc(1, sizeof(*r));
  if (!r) {
    return -1;
  }
  r->owner = hc;
  r->u     = *req;
  r->cfg   = hc->defcfg;

  /* Per-request: disable negotiation entirely if NO_COMPRESS */
  if (req->flags & XORAV_HTTP_F_NO_COMPRESS) {
    r->cfg.enable_gzip    = 0;
    r->cfg.enable_deflate = 0;
    r->cfg.enable_brotli  = 0;
  }

  if (parse_url(req->url, &r->use_tls, &r->host, &r->port, &r->path) != 0) {
    free(r);
    return -2;
  }

  r->body_ptr  = (const uint8_t *)req->body;
  r->body_left = req->body_len;

  uv_mutex_lock(&hc->q_mu);
  if (hc->q_max > 0 && hc->q_len >= hc->q_max) {
    uv_mutex_unlock(&hc->q_mu);
    free(r->host);
    free(r->path);
    free(r);
    return -11; /* -EAGAIN */
  }
  if (!hc->q_tail) {
    hc->q_head = hc->q_tail = r;
  } else {
    hc->q_tail->q_next = r;
    hc->q_tail         = r;
  }
  hc->q_len++;
  uv_mutex_unlock(&hc->q_mu);

  uv_async_send(&hc->kick);
  return 0;
}

static void drain_queue(xorav_http_client_t *hc)
{
  uv_mutex_lock(&hc->q_mu);
  request_t *q = hc->q_head;
  while (q) {
    request_t *nx = q->q_next;
    if (q->u.on_complete) {
      q->u.on_complete(-1, "shutdown", q->u.user);
    }
    request_free(q);
    q = nx;
  }
  hc->q_head = hc->q_tail = NULL;
  hc->q_len               = 0;
  uv_mutex_unlock(&hc->q_mu);

  /* drop all pooled conns */
  pool_bucket_t *b, *tmp;
  HASH_ITER(hh, hc->pool, b, tmp)
  {
    conn_t *c = b->idle_head;
    while (c) {
      conn_t *nx = c->next_idle;
      conn_close_free(c);
      c = nx;
    }
    HASH_DEL(hc->pool, b);
    free(b->host);
    free(b);
  }
}

int xorav_http_client_shutdown(xorav_http_client_t *hc,
                               uint32_t             graceful_timeout_ms)
{
  (void)graceful_timeout_ms;
  if (!hc) {
    return -1;
  }
  hc->accepting = 0;

  drain_queue(hc);

  if (hc->resolver_owned && hc->resolver) {
    xorav_dns_ares_close(hc->resolver);
  }
  uv_close((uv_handle_t *)&hc->kick, NULL);
  uv_mutex_destroy(&hc->q_mu);
  free(hc);
  return 0;
}
