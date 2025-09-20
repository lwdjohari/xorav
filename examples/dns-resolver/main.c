#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>
#include <ares.h>

#include "xorav_dns_ares.h"  // your resolver API

//  App bookkeeping for demo 
typedef struct {
  const char *host;
  int         done;  // mark completion on first callback for this host
} req_entry_t;

typedef struct {
  uv_loop_t        *loop;
  xorav_dns_ares_t *R;
  req_entry_t      *reqs;
  int               nreq;
  int               pending;
} app_ctx_t;

//  Pretty print ares status 
static const char *ares_status_str(int st)
{
  return ares_strerror(st);
}

//  Your resolver callback 
// Signature: (int status, const char *host, const char *ip, void *user)
static void demo_dns_cb(int status, const char *host, const char *ip,
                        void *user)
{
  app_ctx_t *app = (app_ctx_t *)user;

  if (status == ARES_SUCCESS && ip) {
    fprintf(stdout, "[OK]   %-30s -> %s\n", host, ip);

    /*
     * ────────────────────────────────────────────────
     * REAL-WORLD USE CASE:
     *
     * At this point, you have an IP string (e.g., "93.184.216.34").
     * This is where you would typically:
     *
     *   1. Open a client socket:
     *        - uv_tcp_t for TCP connections (e.g., to port 80 or 443)
     *        - uv_udp_t for UDP services
     *
     *   2. Or create a higher-level client:
     *        - HTTP(S) client (libuv + OpenSSL/mbedTLS)
     *        - gRPC or custom protocol over TCP
     *
     *   3. Connect to (ip, port):
     *        struct sockaddr_in dest;
     *        uv_ip4_addr(ip, 80, &dest);
     *        uv_tcp_connect(..., (const struct sockaddr*)&dest, ...);
     *
     *   4. Once connected, exchange data as per your protocol.
     *
     * For example, resolving "example.com" to 93.184.216.34, then
     * making an HTTP GET request to that server.
     *
     * ────────────────────────────────────────────────
     */
  } else {
    fprintf(stdout, "[ERR]  %-30s -> %s\n", host, ares_status_str(status));
  }

  // Mark the request as 'done' on first callback for that host
  for (int i = 0; i < app->nreq; ++i) {
    if (!app->reqs[i].done && strcmp(app->reqs[i].host, host) == 0) {
      app->reqs[i].done = 1;
      if (--app->pending == 0) {
        uv_stop(app->loop);
      }
      break;
    }
  }
}

int main(void)
{
  // Positive cases
  const char *hosts_ok[] = {
    "google.com",  // has stable A/AAAA
    "localhost",    // should resolve to 127.0.0.1 / ::1
  };

  // Negative cases
  const char *hosts_ng[] = {
    "no-such-host.invalid",  // NXDOMAIN
    "bad host name",         // invalid syntax
  };

  // Build a static request list
  req_entry_t reqs[sizeof(hosts_ok) / sizeof(hosts_ok[0]) +
                   sizeof(hosts_ng) / sizeof(hosts_ng[0])];
  int         idx = 0;
  for (size_t i = 0; i < sizeof(hosts_ok) / sizeof(hosts_ok[0]); ++i) {
    reqs[idx++] = (req_entry_t){ hosts_ok[i], 0 };
  }
  for (size_t i = 0; i < sizeof(hosts_ng) / sizeof(hosts_ng[0]); ++i) {
    reqs[idx++] = (req_entry_t){ hosts_ng[i], 0 };
  }

  uv_loop_t loop;
  uv_loop_init(&loop);

  xorav_dns_ares_t *R  = NULL;
  int               rc = xorav_dns_ares_init(&R, &loop);
  if (rc != ARES_SUCCESS) {
    fprintf(stderr, "ares init failed: %s\n", ares_strerror(rc));
    return 1;
  }

  app_ctx_t app = { .loop    = &loop,
                    .R       = R,
                    .reqs    = reqs,
                    .nreq    = idx,
                    .pending = idx };

  // Submit positive requests
  for (size_t i = 0; i < sizeof(hosts_ok) / sizeof(hosts_ok[0]); ++i) {
    rc = xorav_dns_ares_resolve(R, hosts_ok[i], demo_dns_cb, &app);
    if (rc != 0) {
      fprintf(stderr, "[SUBMIT ERR] %s -> %s\n", hosts_ok[i],
              ares_strerror(rc));
      for (int j = 0; j < app.nreq; ++j) {
        if (!app.reqs[j].done && strcmp(app.reqs[j].host, hosts_ok[i]) == 0) {
          app.reqs[j].done = 1;
          app.pending--;
          break;
        }
      }
    }
  }

  // Submit negative requests
  for (size_t i = 0; i < sizeof(hosts_ng) / sizeof(hosts_ng[0]); ++i) {
    rc = xorav_dns_ares_resolve(R, hosts_ng[i], demo_dns_cb, &app);
    if (rc != 0) {
      fprintf(stderr, "[SUBMIT ERR] %s -> %s\n", hosts_ng[i],
              ares_strerror(rc));
      for (int j = 0; j < app.nreq; ++j) {
        if (!app.reqs[j].done && strcmp(app.reqs[j].host, hosts_ng[i]) == 0) {
          app.reqs[j].done = 1;
          app.pending--;
          break;
        }
      }
    }
  }

  // Also demonstrate immediate parameter validation failure
  rc = xorav_dns_ares_resolve(R, NULL, demo_dns_cb, &app);
  fprintf(stdout, "[SYNC NG] NULL hostname -> %s\n", ares_strerror(rc));

  // Drive the loop until all requests produced at least one callback
  if (app.pending > 0) {
    uv_run(&loop, UV_RUN_DEFAULT);
  }

  xorav_dns_ares_close(R);
  uv_loop_close(&loop);

  return 0;
}
