#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <zlib.h>
#include <brotli/encode.h>

#include "xorav_http_compress.h"
#include "xorav_http_config.h"

/*  tiny vector  */
typedef struct {
  uint8_t *p;
  size_t   n, cap;
} vec_u8;

static void vpush(vec_u8 *v, const uint8_t *d, size_t n)
{
  if (n == 0) {
    return;
  }
  if (v->n + n > v->cap) {
    size_t nc = v->cap ? v->cap : 256;
    while (nc < v->n + n) {
      nc <<= 1;
    }
    v->p   = (uint8_t *)realloc(v->p, nc);
    v->cap = nc;
  }
  memcpy(v->p + v->n, d, n);
  v->n += n;
}

static void vfree(vec_u8 *v)
{
  free(v->p);
  v->p = NULL;
  v->n = v->cap = 0;
}

/*  decoder output sink  */
static int sink_cb(const uint8_t *buf, size_t n, void *user)
{
  vec_u8 *acc = (vec_u8 *)user;
  vpush(acc, buf, n);
  return 0;
}

/*  helpers to make compressed test data  */

/* gzip (.gz) stream using zlib */
static int make_gzip(const uint8_t *src, size_t slen, vec_u8 *out)
{
  int      ret;
  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  /* 15+16 -> gzip wrapper */
  if ((ret = deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, 15 + 16, 8,
                          Z_DEFAULT_STRATEGY)) != Z_OK) {
    return -1;
  }
  uint8_t buf[16 * 1024];
  strm.next_in  = (Bytef *)src;
  strm.avail_in = (uInt)slen;
  int flush     = Z_FINISH;
  do {
    strm.next_out  = buf;
    strm.avail_out = sizeof buf;
    ret            = deflate(&strm, flush);
    size_t have    = sizeof(buf) - strm.avail_out;
    if (have) {
      vpush(out, buf, have);
    }
  } while (ret == Z_OK);
  deflateEnd(&strm);
  return (ret == Z_STREAM_END) ? 0 : -1;
}

/* zlib wrapper (often informally called “deflate” in HTTP) */
static int make_zlib(const uint8_t *src, size_t slen, vec_u8 *out)
{
  int      ret;
  z_stream strm;
  memset(&strm, 0, sizeof strm);
  if ((ret = deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, 15, 8,
                          Z_DEFAULT_STRATEGY)) != Z_OK) {
    return -1;
  }
  uint8_t buf[16 * 1024];
  strm.next_in  = (Bytef *)src;
  strm.avail_in = (uInt)slen;
  int flush     = Z_FINISH;
  do {
    strm.next_out  = buf;
    strm.avail_out = sizeof buf;
    ret            = deflate(&strm, flush);
    size_t have    = sizeof(buf) - strm.avail_out;
    if (have) {
      vpush(out, buf, have);
    }
  } while (ret == Z_OK);
  deflateEnd(&strm);
  return (ret == Z_STREAM_END) ? 0 : -1;
}

/* brotli stream using libbrotlienc */
static int make_brotli(const uint8_t *src, size_t slen, vec_u8 *out)
{
  size_t   out_size = BrotliEncoderMaxCompressedSize(slen);
  uint8_t *tmp      = (uint8_t *)malloc(out_size ? out_size : slen + 32);
  if (!tmp) {
    return -1;
  }
  size_t      encoded = out_size ? out_size : (slen + 32);

  BROTLI_BOOL ok =
    BrotliEncoderCompress(4,  /* quality */
                          22, /* lgwin (default-ish) */
                          BROTLI_MODE_GENERIC, slen, src, &encoded, tmp);
  if (!ok) {
    free(tmp);
    return -1;
  }
  vpush(out, tmp, encoded);
  free(tmp);
  return 0;
}

/*  one test runner  */
static int run_decode_test(const char *name, xorav_dec_kind_e kind,
                           const uint8_t *compressed, size_t clen,
                           const uint8_t *expect, size_t elen,
                           const xorav_http_config_t *limit_cfg_opt)
{
  printf("[%-18s] ", name);
  xorav_http_config_t        cfg_local;
  const xorav_http_config_t *cfg = limit_cfg_opt;
  if (!cfg) {
    xorav_http_config_secure_defaults(&cfg_local);
    cfg = &cfg_local;
  }

  xorav_decoder_t d;
  if (xorav_dec_init(&d, kind, cfg) != 0) {
    printf("INIT FAIL\n");
    return -1;
  }

  /* feed in odd chunk sizes to exercise streaming path */
  vec_u8 acc = { 0 };
  size_t off = 0;
  int    rc  = 0;
  while (off < clen) {
    size_t step = 1 + (off % 4093); /* pseudo-random-ish */
    if (step > clen - off) {
      step = clen - off;
    }
    rc = xorav_dec_feed(&d, compressed + off, step, sink_cb, &acc);
    if (rc != 0) {
      break;
    }
    off += step;
  }
  xorav_dec_free(&d);

  if (limit_cfg_opt && rc == -2) {
    printf("OK (hit max_out)\n");
    vfree(&acc);
    return 0;
  }

  if (rc != 0) {
    printf("DECODE ERR rc=%d\n", rc);
    vfree(&acc);
    return -1;
  }

  if (acc.n != elen || memcmp(acc.p, expect, elen) != 0) {
    printf("MISMATCH (got %zu, expected %zu)\n", acc.n, elen);
    vfree(&acc);
    return -1;
  }
  printf("OK (%zu bytes)\n", elen);
  vfree(&acc);
  return 0;
}

int main(void)
{
  /* Prepare original sample */
  vec_u8 original = { 0 };
  for (int i = 0; i < 2000; i++) {
    const char *line =
      "The quick brown fox jumps over the lazy dog. 1234567890\n";
    vpush(&original, (const uint8_t *)line, strlen(line));
  }

  /* Make compressed variants */
  vec_u8 gz = { 0 }, zl = { 0 }, br = { 0 };
  if (make_gzip(original.p, original.n, &gz) != 0) {
    fprintf(stderr, "gzip make failed\n");
    return 1;
  }
  if (make_zlib(original.p, original.n, &zl) != 0) {
    fprintf(stderr, "zlib make failed\n");
    return 1;
  }
  if (make_brotli(original.p, original.n, &br) != 0) {
    fprintf(stderr, "br make failed\n");
    return 1;
  }

  /* Identity test (no compression) */
  xorav_http_config_t cfg;
  xorav_http_config_secure_defaults(&cfg);
  if (run_decode_test("identity", XORAV_DEC_ID, original.p, original.n,
                      original.p, original.n, &cfg) != 0) {
    return 2;
  }

  /* GZIP decode */
  if (run_decode_test("gzip", XORAV_DEC_Z, gz.p, gz.n, original.p, original.n,
                      &cfg) != 0) {
    return 2;
  }

  /* ZLIB decode */
  if (run_decode_test("deflate(zlib)", XORAV_DEC_Z, zl.p, zl.n, original.p,
                      original.n, &cfg) != 0) {
    return 2;
  }

  /* Brotli decode */
  if (run_decode_test("brotli", XORAV_DEC_BR, br.p, br.n, original.p,
                      original.n, &cfg) != 0) {
    return 2;
  }

  /* Guard: max decompressed bytes */
  xorav_http_config_t tiny    = cfg;
  tiny.max_decompressed_bytes = 1024; /* less than original */
  if (run_decode_test("guard max_out", XORAV_DEC_Z, gz.p, gz.n, original.p,
                      original.n, &tiny) != 0) {
    return 2;
  }

  vfree(&original);
  vfree(&gz);
  vfree(&zl);
  vfree(&br);
  printf("All compression tests passed.\n");
  return 0;
}
