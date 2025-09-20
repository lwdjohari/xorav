#include "xorav_dns_ares.h"
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

typedef struct {
  xorav_dns_result_cb cb;    // your callback type (existing)
  char               *host;  // duplicated hostname
  void               *user;  // passthrough
  xorav_dns_ares_t   *R;     // resolver handle/channel wrapper
} xorav_ares_ctx_t;

/* Forward decls */
static void on_poll(uv_poll_t *h, int status, int events);
static void on_timer(uv_timer_t *t);

static void sock_state_cb(void *data, ares_socket_t fd, int readable,
                          int writable)
{
  xorav_dns_ares_t *R = (xorav_dns_ares_t *)data;

  poller_t         *p = NULL;
  HASH_FIND(hh, R->pollers, &fd, sizeof(fd), p);

  if (!readable && !writable) {
    if (p) {
      uv_poll_stop(&p->ph);
      uv_close((uv_handle_t *)&p->ph, (uv_close_cb)free);
      HASH_DEL(R->pollers, p);
    }
    return;
  }

  if (!p) {
    p     = (poller_t *)calloc(1, sizeof(*p));
    p->fd = fd;
    uv_poll_init_socket(R->loop, &p->ph, fd);
    p->ph.data = R;
    HASH_ADD(hh, R->pollers, fd, sizeof(fd), p);
  }

  int ev = 0;
  if (readable) {
    ev |= UV_READABLE;
  }
  if (writable) {
    ev |= UV_WRITABLE;
  }

  if (!p->watching || p->watching != ev) {
    uv_poll_start(&p->ph, ev, on_poll);
    p->watching = ev;
  }
}

static void on_poll(uv_poll_t *h, int status, int events)
{
  xorav_dns_ares_t *R  = (xorav_dns_ares_t *)h->data;
  ares_socket_t     fd = (ares_socket_t)((poller_t *)h)->fd;

  ares_process_fd(R->ch, (events & UV_READABLE) ? fd : ARES_SOCKET_BAD,
                  (events & UV_WRITABLE) ? fd : ARES_SOCKET_BAD);
}

static void arm_timer(xorav_dns_ares_t *R)
{
  struct timeval tv, *tvp;
  tvp = ares_timeout(R->ch, NULL, &tv);
  uint64_t ms =
    tvp ? (uint64_t)tvp->tv_sec * 1000 + (tvp->tv_usec + 999) / 1000 : 100;
  if (!R->timer_started) {
    uv_timer_init(R->loop, &R->timer);
    R->timer.data    = R;
    R->timer_started = 1;
  }
  uv_timer_start(&R->timer, on_timer, ms, 0);
}

static void on_timer(uv_timer_t *t)
{
  xorav_dns_ares_t *R = (xorav_dns_ares_t *)t->data;
  ares_process_fd(R->ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
  arm_timer(R);
}

/* ares host callback wrapper */
static void host_cb(void *arg, int status, int timeouts, struct hostent *host)
{
  (void)timeouts;

  struct {
    xorav_dns_result_cb cb;
    char               *host;
    void               *user;
    xorav_dns_ares_t   *R;
  }          *ctx = arg;

  const char *out_ip = NULL;
  char        ipbuf[INET6_ADDRSTRLEN];

  if (status == ARES_SUCCESS && host && host->h_addr_list &&
      host->h_addr_list[0]) {
    if (host->h_addrtype == AF_INET) {
      uv_inet_ntop(AF_INET, host->h_addr_list[0], ipbuf, sizeof(ipbuf));
      out_ip = ipbuf;
    } else if (host->h_addrtype == AF_INET6) {
      uv_inet_ntop(AF_INET6, host->h_addr_list[0], ipbuf, sizeof(ipbuf));
      out_ip = ipbuf;
    }
  }

  ctx->cb(status, ctx->host, out_ip, ctx->user);
  free(ctx->host);
  free(ctx);
}

static void addrinfo_cb(void *arg, int status, int timeouts,
                        struct ares_addrinfo *res)
{
  xorav_ares_ctx_t *ctx = (xorav_ares_ctx_t *)arg;

  if (status == ARES_SUCCESS && res) {
    for (struct ares_addrinfo_node *n = res->nodes; n; n = n->ai_next) {
      char ip[INET6_ADDRSTRLEN] = { 0 };

      if (n->ai_family == AF_INET &&
          n->ai_addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)n->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof ip);
      } else if (n->ai_family == AF_INET6 &&
                 n->ai_addrlen >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *sa6 =
          (const struct sockaddr_in6 *)n->ai_addr;
        inet_ntop(AF_INET6, &sa6->sin6_addr, ip, sizeof ip);
      } else {
        continue;
      }

      ctx->cb(ARES_SUCCESS, ctx->host, ip, ctx->user);
    }
  } else {
    ctx->cb(status, ctx->host, NULL, ctx->user);
  }

  if (res) {
    ares_freeaddrinfo(res);
  }
  free(ctx->host);
  free(ctx);
  (void)timeouts;
}

int xorav_dns_ares_init(xorav_dns_ares_t **out, uv_loop_t *loop)
{
  if (!out || !loop) {
    return ARES_EBADFAMILY;
  }
  ares_library_init(ARES_LIB_INIT_ALL);

  xorav_dns_ares_t *R = (xorav_dns_ares_t *)calloc(1, sizeof(*R));
  if (!R) {
    return ARES_ENOMEM;
  }
  R->loop = loop;

  struct ares_options opts;
  memset(&opts, 0, sizeof(opts));
  opts.sock_state_cb      = sock_state_cb;
  opts.sock_state_cb_data = R;

  int optmask = ARES_OPT_SOCK_STATE_CB;
  int rc      = ares_init_options(&R->ch, &opts, optmask);
  if (rc != ARES_SUCCESS) {
    free(R);
    return rc;
  }

  arm_timer(R);
  *out = R;
  return 0;
}


int xorav_dns_ares_resolve(xorav_dns_ares_t *R, const char *hostname,
                           xorav_dns_result_cb cb, void *user)
{
  if (!R || !hostname || !cb) return ARES_EBADQUERY;

  xorav_ares_ctx_t *ctx = (xorav_ares_ctx_t *)calloc(1, sizeof(*ctx));
  if (!ctx) return ARES_ENOMEM;

  ctx->cb   = cb;
  ctx->user = user;
  ctx->R    = R;
  ctx->host = strdup(hostname);
  if (!ctx->host) { free(ctx); return ARES_ENOMEM; }

  struct ares_addrinfo_hints hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;       // both IPv4 & IPv6
  hints.ai_socktype = 0;               // or SOCK_STREAM/UDP if you prefer
  hints.ai_flags    = ARES_AI_CANONNAME; // optional

  // service=NULL means "no specific port/service"
  ares_getaddrinfo(R->ch, hostname, NULL, &hints, addrinfo_cb, ctx);

  arm_timer(R); // keep your existing timer/drive logic
  return 0;
}

void xorav_dns_ares_close(xorav_dns_ares_t *R)
{
  if (!R) {
    return;
  }
  if (R->timer_started) {
    uv_timer_stop(&R->timer);
  }
  /* close pollers */
  poller_t *p;
  poller_t *tmp;
  HASH_ITER(hh, R->pollers, p, tmp)
  {
    uv_poll_stop(&p->ph);
    uv_close((uv_handle_t *)&p->ph, (uv_close_cb)free);
    HASH_DEL(R->pollers, p);
  }
  ares_destroy(R->ch);
  ares_library_cleanup();
  free(R);
}
