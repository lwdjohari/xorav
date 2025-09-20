/* xorav_alloc.h */
#ifndef XORAV_ALLOC_H
#define XORAV_ALLOC_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h> /* for SIZE_MAX */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void *xorav_malloc(size_t size)
{
  void *p = malloc(size);
  if (!p && size) {
    fprintf(stderr, "FATAL: malloc(%zu) failed\n", size);
    abort();
  }
  return p;
}

static inline void *xorav_calloc(size_t nmemb, size_t size)
{
  /* overflow guard based on SIZE_MAX */
  if (size && nmemb > SIZE_MAX / size) {
    fprintf(stderr, "FATAL: calloc overflow (%zu,%zu)\n", nmemb, size);
    abort();
  }
  void *p = calloc(nmemb, size);
  if (!p && nmemb && size) {
    fprintf(stderr, "FATAL: calloc(%zu,%zu) failed\n", nmemb, size);
    abort();
  }
  return p;
}

static inline void *xorav_realloc(void *ptr, size_t size)
{
  void *p = realloc(ptr, size);
  if (!p && size != 0) {
    fprintf(stderr, "FATAL: realloc(%p,%zu) failed\n", ptr, size);
    abort();
  }
  return p;
}

/* Typed array helpers  */
static inline size_t xorav_size_mul(size_t n, size_t elem)
{
  if (elem && n > SIZE_MAX / elem) {
    fprintf(stderr, "FATAL: size overflow (%zu * %zu)\n", n, elem);
    abort();
  }
  return n * elem;
}

/* Safe bounded string copy.
 * - Always null terminates if dst_size > 0
 * - Truncates if src is longer than dst_size-1
 */

/* UTF-8 safe bounded copy
 * - Ensures dst is null-terminated if dst_size > 0
 * - Never cuts inside a UTF-8 sequence
 * - Copies as much as fits using memcpy
 */
static inline void xorav_ut8copy(char *dst, const char *src, size_t dst_size)
{
  if (!dst || dst_size == 0) {
    return;
  }
  if (!src) {
    dst[0] = '\0';
    return;
  }

  size_t maxbytes = dst_size - 1; /* leave space for '\0' */
  size_t i        = 0;
  while (i < maxbytes && src[i]) {
    unsigned char c    = (unsigned char)src[i];
    size_t        clen = 1;

    if (c >= 0x80) { /* multibyte */
      if ((c & 0xE0) == 0xC0) {
        clen = 2;
      } else if ((c & 0xF0) == 0xE0) {
        clen = 3;
      } else if ((c & 0xF8) == 0xF0) {
        clen = 4;
      } else { /* invalid byte, treat as 1 */
        clen = 1;
      }
    }

    /* stop if full character doesn’t fit */
    if (i + clen > maxbytes) {
      break;
    }

    i += clen;
  }

  memcpy(dst, src, i);
  dst[i] = '\0';
}

static inline void xorav_strmemcpy(char *dst, size_t dst_size, const char *src, size_t src_len)
{
  if (!dst || dst_size == 0) {
    return;
  }
  size_t n = (src_len < (dst_size - 1)) ? src_len : (dst_size - 1);
  if (src && n) {
    memcpy(dst, src, n);
  }
  dst[n] = '\0';
  /* optional: zero-pad tail
     if (n + 1 < dst_size) memset(dst + n + 1, 0, dst_size - (n + 1)); */
}

static inline char *xorav_stralloc(const char *src)
{
  if (!src) {
    return NULL;
  }
  size_t len = strlen(src) + 1; /* +1 for '\0' */
  char  *dst = (char *)xorav_malloc(len);
  if (!dst) {
    return NULL;
  }
  memcpy(dst, src, len);
  return dst;
}

static inline char *xorav_strnalloc(const char *src, size_t maxlen)
{
  if (!src) {
    return NULL;
  }
  size_t srclen = strlen(src);
  if (srclen > maxlen) {
    srclen = maxlen; /* truncate if too long */
  }
  char *dst = (char *)xorav_malloc(srclen + 1);
  if (!dst) {
    return NULL;
  }
  memcpy(dst, src, srclen);
  dst[srclen] = '\0'; /* force termination */
  return dst;
}

/* Safe bounded string copy.
 * - Always null terminates if dst_size > 0
 * - Truncates if src is longer than dst_size-1
 */
static inline size_t xorav_strcopy(char *dst, size_t bufsize, const char *src)
{
  if (!dst || bufsize == 0) {
    return 0;
  }
  if (!src) {
    dst[0] = '\0';
    return 0;
  }

  size_t slen = strlen(src);
  size_t n    = (slen < bufsize - 1) ? slen : (bufsize - 1);
  memcpy(dst, src, n);
  dst[n] = '\0';
  return n;
}

static inline size_t xorav_strncopy(char *dst, size_t bufsize, const char *src, size_t maxlen)
{
  if (!dst || bufsize == 0) {
    return 0;
  }
  if (!src) {
    dst[0] = '\0';
    return 0;
  }

  size_t slen = strlen(src);
  if (slen > maxlen) {
    slen = maxlen;
  }

  size_t n = (slen < bufsize - 1) ? slen : (bufsize - 1);
  memcpy(dst, src, n);
  dst[n] = '\0';
  return n;
}

/* Allocate array of T (uninitialized / zero-initialized / resize) */
/*
 *  Usage Examples
 *
 * // Allocate array of 100 ints (uninitialized)
 * int *a = XORAV_ALLOC_ARRAY(int, 100);
 *
 * // Allocate array of 50 doubles, zero-initialized
 * double *b = XORAV_CALLOC_ARRAY(double, 50);
 *
 * // Grow an array of structs to 200 elements
 * typedef struct {
 *     int id;
 *     char name[32];
 * } emp_t;
 *
 * emp_t *emps = NULL;
 * emps = XORAV_ALLOC_ARRAY(emp_t, 100);       // initial alloc
 * emps = XORAV_RESIZE_ARRAY(emps, emp_t, 200); // resize to 200
 *
 * // Always check result for NULL if your allocators can fail
 * if (!emps) {  handle out-of-memory  }
 * Don’t forget to free() via xorav_free() when done
 */
#define XORAV_ALLOC_ARRAY(T, n)       ((T *)xorav_malloc(xorav_size_mul((n), sizeof(T))))
#define XORAV_CALLOC_ARRAY(T, n)      ((T *)xorav_calloc((n), sizeof(T)))
#define XORAV_RESIZE_ARRAY(ptr, T, n) ((T *)xorav_realloc((ptr), xorav_size_mul((n), sizeof(T))))

/* Define char[def+1] with additional +1 for NUL terminator */
#define XORAV_ARRSTR(n) char[(n) + 1]

/* Macro to auto-pass correct size for fixed arrays */
#define XORAV_STRSET(field, src) xorav_strset((field), sizeof(field), (src))

#define XORAV_STRNSET(field, src, maxlen) xorav_strnset((field), sizeof(field), (src), (maxlen))

/* Free + NULL (safe in single-line ifs via do/while guard) */
#define xorav_free(ptr) \
  do {                  \
    free(ptr);          \
    (ptr) = NULL;       \
  } while (0)

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif
