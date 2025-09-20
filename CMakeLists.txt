cmake_minimum_required(VERSION 3.14)
project(libxorav C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)


find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)


# Brotli: prefer pkg-config for reliable version checks; fall back to manual
find_package(PkgConfig QUIET)

# Decoder is used by the library; encoder only used in tests/tools
find_library(BROTLIDEC_LIB     brotlidec     REQUIRED)
find_library(BROTLIENC_LIB     brotlienc     REQUIRED)      # for compression tests/tools
find_library(BROTLICOMMON_LIB  brotlicommon  REQUIRED)


# ---- Minimums Lib version ----
# We aim low but safe for the APIs we use (uv_poll_init_socket, etc.)
set(XORAV_MIN_LIBUV "1.9.0" CACHE STRING "Minimum libuv required")
set(XORAV_MIN_OPENSSL "1.1.1")   # TLS 1.3 & SSL_set1_host require >= 1.1.1
set(XORAV_MIN_ZLIB    "1.2.11")  # stable, widely available, fixes old CVEs
# Brotli headers expose BROTLI_VERSION (hex, e.g. 0x010009 for 1.0.9).
# 1.0.7+ is fine for our decoder usage.
set(XORAV_MIN_BROTLI_HEX "0x010007")
set(XORAV_MIN_BROTLI_VER "1.0.7")

# ---- OpenSSL version check ----
if(DEFINED OPENSSL_VERSION)
  if(OPENSSL_VERSION VERSION_LESS XORAV_MIN_OPENSSL)
    message(FATAL_ERROR
      "OpenSSL ${OPENSSL_VERSION} found, but >= ${XORAV_MIN_OPENSSL} is required "
      "(for TLS 1.3 and hostname verification APIs).")
  endif()
else()
  message(WARNING "FindOpenSSL did not expose OPENSSL_VERSION; assuming compatible.")
endif()

# ---- zlib version check ----
if(DEFINED ZLIB_VERSION_STRING)
  if(ZLIB_VERSION_STRING VERSION_LESS XORAV_MIN_ZLIB)
    message(FATAL_ERROR
      "zlib ${ZLIB_VERSION_STRING} found, but >= ${XORAV_MIN_ZLIB} is required.")
  endif()
else()
  message(WARNING "FindZLIB did not expose ZLIB_VERSION_STRING; assuming compatible.")
endif()

# ---- Brotli version check (prefer pkg-config) ----
# Try pkg-config modules that most distros ship:
#   libbrotlidec, libbrotlicommon, libbrotlienc
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_BROTLI_DEC  QUIET libbrotlidec>=1.0.7)
  pkg_check_modules(PC_BROTLI_COM  QUIET libbrotlicommon>=1.0.7)
  pkg_check_modules(PC_BROTLI_ENC  QUIET libbrotlienc>=1.0.7)
  pkg_check_modules(PC_LIBUV QUIET libuv>=${XORAV_MIN_LIBUV})
endif()

# If pkg-config didn’t confirm versions, compile-time check BROTLI_VERSION from headers.
include(CheckCSourceCompiles)
find_path(BROTLI_INCLUDE_DIR
  NAMES brotli/decode.h brotli/encode.h
  HINTS ${PC_BROTLI_DEC_INCLUDE_DIRS} ${PC_BROTLI_COM_INCLUDE_DIRS} ${PC_BROTLI_ENC_INCLUDE_DIRS}
)
if(NOT BROTLI_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find brotli headers (brotli/decode.h, brotli/encode.h).")
endif()

# Let the test see the headers
set(CMAKE_REQUIRED_INCLUDES "${BROTLI_INCLUDE_DIR}")
check_c_source_compiles("
  #include <brotli/decode.h>
  #include <brotli/encode.h>
  #ifndef BROTLI_VERSION
  # error No BROTLI_VERSION macro
  #endif
  #if (BROTLI_VERSION < ${XORAV_MIN_BROTLI_HEX})
  # error Brotli too old
  #endif
  int main(void){return 0;}
" XORAV_BROTLI_VERSION_OK)

if(NOT XORAV_BROTLI_VERSION_OK)
  # If pkg-config confirmed sufficient versions, accept; else fail.
  if(PC_BROTLI_DEC_FOUND AND PC_BROTLI_COM_FOUND AND PC_BROTLI_ENC_FOUND)
    message(STATUS "Brotli version assumed OK via pkg-config (>= 1.0.7).")
  else()
    message(FATAL_ERROR
      "Brotli headers are older than required (need >= 1.0.7). "
      "Check your distro’s brotli/brotli-devel packages.")
  endif()
endif()

# ---- Link interface variables you can reuse below ----
set(XORAV_BROTLI_DEPS
  ${BROTLIDEC_LIB}
  ${BROTLICOMMON_LIB}
)

set(XORAV_BROTLI_ENC_DEPS
  ${BROTLIENC_LIB}
  ${BROTLICOMMON_LIB}
)


if(PC_LIBUV_FOUND)
  set(LIBUV_FOUND TRUE)
  set(LIBUV_INCLUDE_DIRS ${PC_LIBUV_INCLUDE_DIRS})
  set(LIBUV_LIBRARIES ${PC_LIBUV_LINK_LIBRARIES})
else()
  # Fallback: plain find + compile-time version check using UV_VERSION_HEX
  find_path(LIBUV_INCLUDE_DIR NAMES uv.h uv/version.h)
  find_library(LIBUV_LIBRARY   NAMES uv libuv)

  include(CheckCSourceCompiles)
  set(CMAKE_REQUIRED_INCLUDES "${LIBUV_INCLUDE_DIR}")
  set(CMAKE_REQUIRED_LIBRARIES "${LIBUV_LIBRARY}")

  # Convert "X.Y.Z" to the UV_VERSION_HEX layout: (X<<16)|(Y<<8)|Z
  string(REPLACE "." ";" _uv_list ${XORAV_MIN_LIBUV})
  list(GET _uv_list 0 _uv_maj)
  list(GET _uv_list 1 _uv_min)
  list(GET _uv_list 2 _uv_pat)
  math(EXPR _UV_NEEDED_HEX "((${_uv_maj})<<16) | ((${_uv_min})<<8) | (${_uv_pat})")

  check_c_source_compiles("
    #include <uv/version.h>
    #ifndef UV_VERSION_HEX
    # error Missing UV_VERSION_HEX
    #endif
    #if (UV_VERSION_HEX < ${_UV_NEEDED_HEX})
    # error libuv too old
    #endif
    /* Also ensure uv_poll_init_socket is declared */
    #include <uv.h>
    int main(void) {
      (void)&uv_poll_init_socket; /* reference symbol */
      return 0;
    }" LIBUV_VERSION_OK)

  if(LIBUV_INCLUDE_DIR AND LIBUV_LIBRARY AND LIBUV_VERSION_OK)
    set(LIBUV_FOUND TRUE)
    set(LIBUV_INCLUDE_DIRS "${LIBUV_INCLUDE_DIR}")
    set(LIBUV_LIBRARIES "${LIBUV_LIBRARY}")
  endif()
endif()

if(NOT LIBUV_FOUND)
  message(FATAL_ERROR
    "libuv >= ${XORAV_MIN_LIBUV} is required. "
    "Install libuv-devel / libuv-dev and ensure pkg-config can find it.")
endif()


# Provide a uniform imported target for consumers
# add_library(libuv::uv INTERFACE IMPORTED)
# set_target_properties(libuv::uv PROPERTIES
#   INTERFACE_INCLUDE_DIRECTORIES "${LIBUV_INCLUDE_DIRS}"
#   INTERFACE_LINK_LIBRARIES     "${LIBUV_LIBRARIES}"
# )

add_subdirectory(third_party/c-ares)
option(JANSSON_BUILD_DOCS off)
set(JANSSON_BUILD_DOCS off)
add_subdirectory(third_party/jansson)


# ---- Include paths for compiled C (public headers) ----
include_directories(
  ${CMAKE_SOURCE_DIR}/lib/inc/
  ${CMAKE_SOURCE_DIR}/third_party/stb/inc
  ${CMAKE_SOURCE_DIR}/third_party/sds/
  ${CMAKE_SOURCE_DIR}/third_party/uthash/include/
)

# xorav-lib
add_subdirectory(xorav)

# xorav-examples
add_subdirectory(examples/dns-resolver)
add_subdirectory(examples/dns-http-get)

# Configuration summary (debug) 
# ----------------------------------------------

# String helpers for pretty output
function(_xorav_join OUT_VAR)
  # usage: _xorav_join(VAR a;b;c)
  if(ARGC GREATER 1)
    list(JOIN ARGN " " _tmp)
    set(${OUT_VAR} "${_tmp}" PARENT_SCOPE)
  else()
    set(${OUT_VAR} "" PARENT_SCOPE)
  endif()
endfunction()

# Compose lib lists as single lines
_xorav_join(_LIBUV_LIBS_LINE ${LIBUV_LIBRARIES})
_xorav_join(_LIBUV_INC_LINE  ${LIBUV_INCLUDE_DIRS})

set(_UV_ORIGIN "manual")
if(PC_LIBUV_FOUND)
  set(_UV_ORIGIN "pkg-config")
endif()

set(_OPENSSL_VER "${OPENSSL_VERSION}")
if(NOT DEFINED _OPENSSL_VER OR _OPENSSL_VER STREQUAL "")
  set(_OPENSSL_VER "unknown")
endif()

set(_ZLIB_VER "${ZLIB_VERSION_STRING}")
if(NOT DEFINED _ZLIB_VER OR _ZLIB_VER STREQUAL "")
  set(_ZLIB_VER "unknown")
endif()

set(_BROTLI_VIA_PC "no")
if(PC_BROTLI_DEC_FOUND AND PC_BROTLI_COM_FOUND AND PC_BROTLI_ENC_FOUND)
  set(_BROTLI_VIA_PC "yes")
endif()

message(STATUS "")
message(STATUS "================= xorav build summary =================")
message(STATUS "")
message(STATUS "Project          : ${PROJECT_NAME}")
message(STATUS "Build type       : ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler       : ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "C standard       : C${CMAKE_C_STANDARD}")
message(STATUS "OpenSSL          : ${_OPENSSL_VER} (>=${XORAV_MIN_OPENSSL})")
message(STATUS "Zlib             : ${_ZLIB_VER} (>=${XORAV_MIN_ZLIB})")
message(STATUS "Brotli headers   : ${BROTLI_INCLUDE_DIR} (>=${XORAV_MIN_BROTLI_VER}, via pkg-config: ${_BROTLI_VIA_PC})")
message(STATUS "  brotlidec lib  : ${BROTLIDEC_LIB}")
message(STATUS "  brotlienc lib  : ${BROTLIENC_LIB}")
message(STATUS "  brotlicommon   : ${BROTLICOMMON_LIB}")
message(STATUS "libuv            : origin=${_UV_ORIGIN} (>=${XORAV_MIN_LIBUV})")
message(STATUS "  include dirs   : ${_LIBUV_INC_LINE}")
message(STATUS "  libraries      : ${_LIBUV_LIBS_LINE}")
message(STATUS "c-ares           : added via add_subdirectory(third_party/c-ares)")
message(STATUS "jansson          : added via add_subdirectory(third_party/jansson)")
message(STATUS "stb/uthash/sds   : included from third_party paths")
message(STATUS "")
message(STATUS "=======================================================")
message(STATUS "")
