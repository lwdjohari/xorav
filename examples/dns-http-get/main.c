#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>
#include <ares.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#endif

#include "xorav_dns_ares.h"  

/* Callback signature:
 *   typedef void (*xorav_dns_result_cb)(int status,
 *                                       const char *host,
 *                                       const char *ip,
 *                                       void *user);
 */

typedef struct {
  uv_loop_t        *loop;
  xorav_dns_ares_t *R;
  const char       *host;       // e.g. "example.com"
  int               port;       // e.g. 80
  int               resolved;   // have we already received at least one IP?
  int               connected;  // did TCP connect succeed?
  uv_tcp_t          tcp;
  uv_connect_t      conn_req;
  uv_write_t        write_req;
  uv_buf_t          write_buf;
} http_demo_t;

/* Forward decls */
static void dns_cb(int status, const char *host, const char *ip, void *user);
static void on_connect(uv_connect_t *req, int status);
static void on_alloc(uv_handle_t *h, size_t suggested, uv_buf_t *buf);
static void on_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf);
static void on_write(uv_write_t *req, int status);
static void close_and_quit(http_demo_t *ctx, int exit_code);

/* Convert "ip string" + port to sockaddr (IPv4 or IPv6) */
static int  make_sockaddr_any(const char *ip, int port,
                              struct sockaddr_storage *ss, int *len)
{
  struct in_addr  v4;
  struct in6_addr v6;

  if (inet_pton(AF_INET, ip, &v4) == 1) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)port);
    sa.sin_addr   = v4;
    memcpy(ss, &sa, sizeof(sa));
    *len = sizeof(sa);
    return AF_INET;
  }
  if (inet_pton(AF_INET6, ip, &v6) == 1) {
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_port   = htons((unsigned short)port);
    sa6.sin6_addr   = v6;
    memcpy(ss, &sa6, sizeof(sa6));
    *len = sizeof(sa6);
    return AF_INET6;
  }
  return AF_UNSPEC; /* invalid ip string */
}

/* === DNS result callback ===
 * We attempt to connect to the FIRST IP we get (A or AAAA).
 * If you want retries over multiple IPs, collect them and attempt in order.
 */
static void dns_cb(int status, const char *host, const char *ip, void *user)
{
  http_demo_t *ctx = (http_demo_t *)user;

  if (status != ARES_SUCCESS || !ip) {
    fprintf(stderr, "[DNS] %s -> %s\n", host, ares_strerror(status));
    close_and_quit(ctx, 2);
    return;
  }

  fprintf(stdout, "[DNS] %s -> %s (using first result)\n", host, ip);

  if (ctx->resolved) {
    /* We already started a connect on the first IP; ignore further ones in this
     * simple demo. */
    return;
  }
  ctx->resolved = 1;

  /* Create destination sockaddr */
  struct sockaddr_storage ss;
  int                     slen = 0;
  int                     fam  = make_sockaddr_any(ip, ctx->port, &ss, &slen);
  if (fam == AF_UNSPEC) {
    fprintf(stderr, "[ERR] invalid IP address: %s\n", ip);
    close_and_quit(ctx, 2);
    return;
  }

  /* REAL-WORLD STEP: create a TCP client and connect */
  int rc = uv_tcp_init(ctx->loop, &ctx->tcp);
  if (rc != 0) {
    fprintf(stderr, "[ERR] uv_tcp_init: %s\n", uv_strerror(rc));
    close_and_quit(ctx, 2);
    return;
  }
  ctx->tcp.data = ctx;

  rc = uv_tcp_connect(&ctx->conn_req, &ctx->tcp, (const struct sockaddr *)&ss,
                      on_connect);
  if (rc != 0) {
    fprintf(stderr, "[ERR] uv_tcp_connect: %s\n", uv_strerror(rc));
    close_and_quit(ctx, 2);
    return;
  }
}

/* === TCP connect callback === */
static void on_connect(uv_connect_t *req, int status)
{
  http_demo_t *ctx = (http_demo_t *)req->handle->data;

  if (status != 0) {
    fprintf(stderr, "[CONN] failed: %s\n", uv_strerror(status));
    close_and_quit(ctx, 3);
    return;
  }

  ctx->connected = 1;
  fprintf(stdout, "[CONN] connected to %s:%d\n", ctx->host, ctx->port);

  /* Start reading the HTTP response */
  int rc = uv_read_start(req->handle, on_alloc, on_read);
  if (rc != 0) {
    fprintf(stderr, "[ERR] uv_read_start: %s\n", uv_strerror(rc));
    close_and_quit(ctx, 3);
    return;
  }

  /* REAL-WORLD STEP: send a simple HTTP/1.1 GET */
  char reqbuf[512];
  int  n = snprintf(reqbuf, sizeof(reqbuf),
                    "GET / HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: xorav-http-demo/1.0\r\n"
                     "Accept: */*\r\n"
                     "Connection: close\r\n\r\n",
                    ctx->host);
  if (n < 0 || n >= (int)sizeof(reqbuf)) {
    fprintf(stderr, "[ERR] request too large\n");
    close_and_quit(ctx, 3);
    return;
  }

  ctx->write_buf = uv_buf_init((char *)malloc((size_t)n), (unsigned int)n);
  if (!ctx->write_buf.base) {
    fprintf(stderr, "[ERR] OOM preparing request\n");
    close_and_quit(ctx, 3);
    return;
  }
  memcpy(ctx->write_buf.base, reqbuf, (size_t)n);

  rc = uv_write(&ctx->write_req, req->handle, &ctx->write_buf, 1, on_write);
  if (rc != 0) {
    fprintf(stderr, "[ERR] uv_write: %s\n", uv_strerror(rc));
    close_and_quit(ctx, 3);
    return;
  }
}

/* Alloc callback for incoming data */
static void on_alloc(uv_handle_t *h, size_t suggested, uv_buf_t *buf)
{
  (void)h;
  buf->base = (char *)malloc(suggested ? suggested : 1);
  buf->len  = (unsigned int)(suggested ? suggested : 1);
}

/* Read callback: print the payload; on EOF, close */
static void on_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf)
{
  http_demo_t *ctx = (http_demo_t *)s->data;

  if (nread > 0) {
    fwrite(buf->base, 1, (size_t)nread, stdout);
  } else if (nread == UV_EOF) {
    fprintf(stdout, "\n[HTTP] EOF\n");
    free(buf->base);
    close_and_quit(ctx, 0);
    return;
  } else if (nread < 0) {
    fprintf(stderr, "\n[ERR] read: %s\n", uv_strerror((int)nread));
    free(buf->base);
    close_and_quit(ctx, 4);
    return;
  }

  free(buf->base);
}

/* Write callback: free the request buffer */
static void on_write(uv_write_t *req, int status)
{
  http_demo_t *ctx = (http_demo_t *)req->handle->data;
  if (ctx->write_buf.base) {
    free(ctx->write_buf.base);
    ctx->write_buf = uv_buf_init(NULL, 0);
  }
  if (status != 0) {
    fprintf(stderr, "[ERR] write: %s\n", uv_strerror(status));
    close_and_quit(ctx, 4);
  }
}

/* Close helpers */
static void after_close(uv_handle_t *h)
{
  (void)h;
}

static void close_and_quit(http_demo_t *ctx, int exit_code)
{
  /* In a larger app, you might keep the loop running. For a demo we stop. */
  if (ctx->connected) {
    uv_read_stop((uv_stream_t *)&ctx->tcp);
  }
  if (!uv_is_closing((uv_handle_t *)&ctx->tcp)) {
    uv_close((uv_handle_t *)&ctx->tcp, after_close);
  }
  /* Stop the loop; your xorav_dns_ares_close() will clean c-ares/timers
   * elsewhere */
  uv_stop(ctx->loop);

  /* Store exit code in loop data if you want; here we just print */
  if (exit_code != 0) {
    fprintf(stderr, "[EXIT] code=%d\n", exit_code);
  }
}

/* Entry: resolve -> connect -> GET / -> print response */
int main(int argc, char **argv)
{
  const char *host = (argc > 1) ? argv[1] : "example.com";
  int         port = (argc > 2) ? atoi(argv[2]) : 80;

  uv_loop_t   loop;
  uv_loop_init(&loop);

  xorav_dns_ares_t *R  = NULL;
  int               rc = xorav_dns_ares_init(&R, &loop);
  if (rc != ARES_SUCCESS) {
    fprintf(stderr, "ares init failed: %s\n", ares_strerror(rc));
    return 1;
  }

  http_demo_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.loop = &loop;
  ctx.R    = R;
  ctx.host = host;
  ctx.port = port;

  /* Kick off resolution; real projects might also pass a timeout timer */
  rc = xorav_dns_ares_resolve(R, host, dns_cb, &ctx);
  if (rc != 0) {
    fprintf(stderr, "[SUBMIT ERR] %s -> %s\n", host, ares_strerror(rc));
    xorav_dns_ares_close(R);
    uv_loop_close(&loop);
    return 2;
  }

  uv_run(&loop, UV_RUN_DEFAULT);

  /* Tear-down resolver after loop stops */
  xorav_dns_ares_close(R);
  uv_loop_close(&loop);
  return 0;
}
