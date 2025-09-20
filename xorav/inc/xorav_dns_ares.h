#pragma once

#include <uv.h>
#include <ares.h>
#include <stddef.h>
#include "uthash.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef void (*xorav_dns_result_cb)(int status, /* 0 on success (ARES_SUCCESS), else ARES_* */
                                    const char *host_queried,
                                    const char *ip_string, /* first A/AAAA string or NULL */
                                    void       *user_data);

typedef struct poller_s {
  uv_poll_t      ph;
  uv_os_sock_t   fd;
  int            watching;
  UT_hash_handle hh;
} poller_t;

typedef struct xorav_dns_ares_s {
  uv_loop_t   *loop;
  ares_channel ch;
  uv_timer_t   timer;

  /* map: fd -> poller */
  poller_t    *pollers;
  int          timer_started;
} xorav_dns_ares_t;

/* Create resolver bound to a libuv loop.  Returns 0 on success. */
int  xorav_dns_ares_init(xorav_dns_ares_t **out, uv_loop_t *loop);

/* Resolve a hostname (A/AAAA). Non-blocking. */
int  xorav_dns_ares_resolve(xorav_dns_ares_t *R, const char *hostname, xorav_dns_result_cb cb,
                            void *user);

/* Shutdown & free. Safe to call from any thread via xorav_async marshalling;
   but typical usage: call from the loop thread. */
void xorav_dns_ares_close(xorav_dns_ares_t *R);

#ifdef __cplusplus
}
#endif
