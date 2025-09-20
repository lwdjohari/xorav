cmake_minimum_required(VERSION 3.14)
project(xorav_project C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Threads flag if needed
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)


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

