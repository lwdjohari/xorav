#include "xorav_http_compress.h"
#include "xorav_http_config.h"
#include <string.h>
#include <stdlib.h>
#include <zlib.h>
#include <brotli/decode.h>

typedef struct {
  z_stream z;
} zwrap_t;

static int dec_out(xorav_decoder_t *d, const uint8_t *buf, size_t len,
                   xorav_on_data_cb on_data, void *user)
{
  if (!len) {
    return 0;
  }
  if (d->max_out && d->total_out + len > d->max_out) {
    return -2;
  }
  d->total_out += len;
  return on_data ? on_data(buf, len, user) : 0;
}

int xorav_dec_init(xorav_decoder_t *d, xorav_dec_kind_e k,
                   const xorav_http_config_t *cfg)
{
  if (!d) {
    return -1;
  }
  memset(d, 0, sizeof(*d));
  d->kind    = k;
  d->max_out = cfg && cfg->max_decompressed_bytes ? cfg->max_decompressed_bytes
                                                  : (64ull << 20);
  d->max_ratio =
    cfg && cfg->max_decompress_ratio ? cfg->max_decompress_ratio : 30.0f;

  if (k == XORAV_DEC_Z) {
    zwrap_t *zw = (zwrap_t *)calloc(1, sizeof(*zw));
    if (!zw) {
      return -1;
    }
    zw->z.zalloc = Z_NULL;
    zw->z.zfree  = Z_NULL;
    zw->z.opaque = Z_NULL;
    if (inflateInit2(&zw->z, 15 + 32) != Z_OK) {
      free(zw);
      return -1;
    }
    d->z_inited = 1;
    d->z_stream = zw;
  } else if (k == XORAV_DEC_BR) {
    d->br_state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!d->br_state) {
      return -1;
    }
  }
  return 0;
}

int xorav_dec_feed(xorav_decoder_t *d, const uint8_t *in, size_t in_len,
                   xorav_on_data_cb on_data, void *user)
{
  if (!d) {
    return -1;
  }

  if (d->kind == XORAV_DEC_ID) {
    return dec_out(d, in, in_len, on_data, user);
  } else if (d->kind == XORAV_DEC_Z) {
    zwrap_t *zw = (zwrap_t *)d->z_stream;
    if (!zw) {
      return -1;
    }
    unsigned char outbuf[16 * 1024];
    zw->z.next_in  = (Bytef *)in;
    zw->z.avail_in = (uInt)in_len;
    while (zw->z.avail_in > 0) {
      zw->z.next_out  = outbuf;
      zw->z.avail_out = sizeof outbuf;
      int rc          = inflate(&zw->z, Z_NO_FLUSH);
      if (rc != Z_OK && rc != Z_STREAM_END) {
        return -1;
      }
      size_t have = sizeof(outbuf) - zw->z.avail_out;
      if (have) {
        int o = dec_out(d, outbuf, have, on_data, user);
        if (o) {
          return o;
        }
      }
      if (rc == Z_STREAM_END) {
        break;
      }
      if (zw->z.avail_out != 0 && zw->z.avail_in == 0) {
        break;
      }
    }
    return 0;
  } else { /* XORAV_DEC_BR */
    BrotliDecoderState *br = (BrotliDecoderState *)d->br_state;
    if (!br) {
      return -1;
    }
    unsigned char  outbuf[16 * 1024];
    size_t         avail_in = in_len;
    const uint8_t *next_in  = in;
    while (1) {
      size_t              avail_out = sizeof outbuf;
      uint8_t            *next_out  = outbuf;
      BrotliDecoderResult r         = BrotliDecoderDecompressStream(
        br, &avail_in, &next_in, &avail_out, &next_out, NULL);
      size_t produced = sizeof(outbuf) - avail_out;
      if (produced) {
        int o = dec_out(d, outbuf, produced, on_data, user);
        if (o) {
          return o;
        }
      }
      if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
        break;
      }
      if (r == BROTLI_DECODER_RESULT_SUCCESS) {
        break;
      }
      if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
        continue;
      }
      return -1;
    }
    return 0;
  }
}

void xorav_dec_free(xorav_decoder_t *d)
{
  if (!d) {
    return;
  }
  if (d->z_inited && d->z_stream) {
    zwrap_t *zw = (zwrap_t *)d->z_stream;
    inflateEnd(&zw->z);
    free(zw);
  }
  if (d->br_state) {
    BrotliDecoderDestroyInstance((BrotliDecoderState *)d->br_state);
  }
  memset(d, 0, sizeof(*d));
}
