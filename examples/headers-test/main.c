#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xorav_http_headers.h"
#include "xorav_http_config.h"

static void dump(const char *title, const unsigned char *buf, size_t n)
{
  printf("---------- %s ----------\n", title);
  fwrite(buf, 1, n, stdout);
}

int main(void)
{
  xorav_http_config_t cfg;
  xorav_http_config_secure_defaults(&cfg);

  /* Case 1: Default Accept-Encoding from cfg (br,gzip,deflate) */
  {
    xorav_headers_t H;
    xorav_headers_init(&H);
    xorav_headers_set(&H, "X-Demo", "alpha");
    xorav_headers_add(&H, "X-Feature", "A");
    xorav_headers_add(&H, "X-Feature", "B"); /* duplicates allowed */

    unsigned char *out     = NULL;
    size_t         out_len = 0;
    int            rc      = xorav_http_build_request_headers(
      "GET", "/api/v1/items?limit=10", "example.com", /*keep-alive*/ 1, &cfg,
      /*disable_accept_encoding*/ 0, &H,
      /*has_body*/ 0, /*content_length*/ 0, /*chunked_upload*/ 0,
      /*content_type*/ NULL, &out, &out_len);
    if (rc == 0) {
      dump("GET default AE", out, out_len);
      free(out);
    }
    xorav_headers_free(&H);
  }

  /* Case 2: User overrides Accept-Encoding (e.g., only gzip) */
  {
    xorav_headers_t H;
    xorav_headers_init(&H);
    xorav_headers_set(&H, "Accept-Encoding", "gzip");
    xorav_headers_set(&H, "X-Demo", "override-AE");
    unsigned char *out     = NULL;
    size_t         out_len = 0;
    int            rc      = xorav_http_build_request_headers(
      "GET", "/gzip", "example.com", 1, &cfg, /*disable_accept_encoding*/ 0, &H,
      0, 0, 0, NULL, &out, &out_len);
    if (rc == 0) {
      dump("GET user AE=gzip", out, out_len);
      free(out);
    }
    xorav_headers_free(&H);
  }

  /* Case 3: Disable negotiation entirely (no Accept-Encoding) */
  {
    xorav_headers_t H;
    xorav_headers_init(&H);
    xorav_headers_set(&H, "X-Demo", "no-AE");
    unsigned char *out     = NULL;
    size_t         out_len = 0;
    int            rc      = xorav_http_build_request_headers(
      "GET", "/no-enc", "example.com", 1, &cfg, /*disable_accept_encoding*/ 1,
      &H, 0, 0, 0, NULL, &out, &out_len);
    if (rc == 0) {
      dump("GET disable AE", out, out_len);
      free(out);
    }
    xorav_headers_free(&H);
  }

  /* Case 4: Fixed-length upload (Content-Length + Content-Type) */
  {
    xorav_headers_t H;
    xorav_headers_init(&H);
    xorav_headers_set(&H, "X-Trace-Id", "abc-123");
    size_t         content_length = 1024; /* pretend */
    unsigned char *out            = NULL;
    size_t         out_len        = 0;
    int            rc             = xorav_http_build_request_headers(
      "POST", "/upload/fixed", "upload.example", 1, &cfg, 0, &H,
      /*has_body*/ 1, content_length, /*chunked_upload*/ 0,
      "application/octet-stream", &out, &out_len);
    if (rc == 0) {
      dump("POST fixed-length", out, out_len);
      free(out);
    }
    xorav_headers_free(&H);
  }

  /* Case 5: Chunked upload (Transfer-Encoding: chunked) */
  {
    xorav_headers_t H;
    xorav_headers_init(&H);
    xorav_headers_set(&H, "X-Trace-Id", "xyz-789");
    unsigned char *out     = NULL;
    size_t         out_len = 0;
    int            rc      = xorav_http_build_request_headers(
      "PUT", "/upload/chunked", "upload.example", 1, &cfg, 0, &H,
      /*has_body*/ 1, /*content_length*/ 0, /*chunked_upload*/ 1,
      "application/octet-stream", &out, &out_len);
    if (rc == 0) {
      dump("PUT chunked", out, out_len);
      free(out);
    }
    xorav_headers_free(&H);
  }

  return 0;
}
