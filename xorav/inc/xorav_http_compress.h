#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  XORAV_DEC_ID = 0,
  XORAV_DEC_Z,
  XORAV_DEC_BR
} xorav_dec_kind_e;

typedef int (*xorav_on_data_cb)(const uint8_t *buf, size_t n, void *user);

typedef struct xorav_http_config_s xorav_http_config_t;

typedef struct xorav_decoder_s {
  xorav_dec_kind_e kind;
  uint64_t         total_out, max_out;
  float            max_ratio;
  void            *z_stream; /* internal z_stream* */
  int              z_inited;
  void            *br_state; /* BrotliDecoderState* */
} xorav_decoder_t;

int  xorav_dec_init(xorav_decoder_t *d, xorav_dec_kind_e k,
                    const xorav_http_config_t *cfg);
int  xorav_dec_feed(xorav_decoder_t *d, const uint8_t *in, size_t in_len,
                    xorav_on_data_cb on_data, void *user);
void xorav_dec_free(xorav_decoder_t *d);

#ifdef __cplusplus
}
#endif
