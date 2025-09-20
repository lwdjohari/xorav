cmake_minimum_required(VERSION 3.14)

# Compression-only test (no HTTP client requests)
add_executable(xorav_compress_test
  main.c
)
target_include_directories(xorav_compress_test
  PRIVATE
    ${CMAKE_SOURCE_DIR}/xorav/inc
)


target_link_libraries(xorav_compress_test
  PRIVATE
    xorav::xorav          # brings in brotlidec + zlib via the library
    ZLIB::ZLIB
    ${BROTLIENC_LIB}
    ${BROTLICOMMON_LIB}
)
