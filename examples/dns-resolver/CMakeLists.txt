cmake_minimum_required(VERSION 3.14)

add_executable(xorav_dns_resolver_demo
  main.c
)

# libuv via pkg-config (top-level already did pkg_check_modules)
if (TARGET PkgConfig::LIBUV)
  set(_UV_LINK PkgConfig::LIBUV)
else()
  set(_UV_LINK ${LIBUV_LIBRARIES})
  target_include_directories(xorav_dns_resolver_demo PRIVATE ${LIBUV_INCLUDE_DIRS})
endif()

# c-ares target alias
if (TARGET c-ares::cares)
  set(_CARES_TARGET c-ares::cares)
else()
  set(_CARES_TARGET cares)
endif()

target_link_libraries(xorav_dns_resolver_demo
  PRIVATE
    xorav::xorav
    ${_UV_LINK}
    ${_CARES_TARGET}
    jansson
    Threads::Threads
)

set_target_properties(xorav_dns_resolver_demo PROPERTIES
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
)

if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(xorav_dns_resolver_demo PRIVATE -Wall -Wextra -Wpedantic)
elseif (MSVC)
  target_compile_options(xorav_dns_resolver_demo PRIVATE /W4)
endif()
