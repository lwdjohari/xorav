# xorav/CMakeLists.txt
cmake_minimum_required(VERSION 3.14)

# -------------------------------
# 1) Sources: list them explicitly
# -------------------------------
set(XORAV_SOURCES
   ${CMAKE_CURRENT_SOURCE_DIR}/src/xorav_dns_ares.c
   ${CMAKE_CURRENT_SOURCE_DIR}/src/xorav_http_config.c
   ${CMAKE_CURRENT_SOURCE_DIR}/src/xorav_http_headers.c
   ${CMAKE_CURRENT_SOURCE_DIR}/src/xorav_http_compress.c  
)

# (Optional) If you plan to "install" public headers later, list them here.
# NOTE: These do NOT need to be in add_library() for compilation;
#       we keep a separate list just to use in install(FILES ...).
set(XORAV_PUBLIC_HEADERS
  ${CMAKE_SOURCE_DIR}/lib/inc/xorav_alloc.h
  ${CMAKE_SOURCE_DIR}/lib/inc/xorav_error.h
  ${CMAKE_SOURCE_DIR}/lib/inc/xorav_lib.h
)

# -------------------------------
# 2) Library target
# -------------------------------
add_library(xorav STATIC ${XORAV_SOURCES})
add_library(xorav::xorav ALIAS xorav)

set_target_properties(xorav PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
  OUTPUT_NAME xorav
)

# Public include dir for consumers; no need to list headers as sources.
target_include_directories(xorav
  PUBLIC
    "${CMAKE_SOURCE_DIR}/lib/inc"
    "${CMAKE_CURRENT_SOURCE_DIR}/inc"
    "${CMAKE_SOURCE_DIR}/third_party/stb_ds/inc"

  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

# -------------------------------
# 3) Dependencies
# -------------------------------
# libuv from pkg-config (top-level already did pkg_check_modules)
if (TARGET PkgConfig::LIBUV)
  set(_UV_LINK PkgConfig::LIBUV)
else()
  set(_UV_LINK ${LIBUV_LIBRARIES})
  target_include_directories(xorav PRIVATE ${LIBUV_INCLUDE_DIRS})
endif()

# c-ares: prefer namespaced alias if present
if (TARGET c-ares::cares)
  set(_CARES_TARGET c-ares::cares)
else()
  set(_CARES_TARGET cares)
endif()

target_link_libraries(xorav
  PUBLIC
    Threads::Threads
    ${_UV_LINK}
    OpenSSL::SSL OpenSSL::Crypto
    ZLIB::ZLIB
    brotlidec
  PRIVATE
    ${_CARES_TARGET}
    jansson
)

# Warnings (tune to taste)
if (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(xorav PRIVATE -Wall -Wextra -Wpedantic)
elseif (MSVC)
  target_compile_options(xorav PRIVATE /W4)
endif()

# -------------------------------
# 4) (Optional) Install & Export
#    Enable with -DXORAV_ENABLE_INSTALL=ON
#    This lets downstreams do: find_package(xorav CONFIG REQUIRED)
# -------------------------------
option(XORAV_ENABLE_INSTALL "Enable install & export of xorav target" OFF)
if (XORAV_ENABLE_INSTALL)
  include(GNUInstallDirs)

  # Install the static library
  install(TARGETS xorav
    EXPORT xoravTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )

  # Install headers (only if you maintain XORAV_PUBLIC_HEADERS above)
  # Comment this block out if you don't want to ship headers.
  install(FILES ${XORAV_PUBLIC_HEADERS}
          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/xorav)

  # Export targets file (used by find_package with CONFIG mode)
  install(EXPORT xoravTargets
    NAMESPACE xorav::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xorav
  )

  # Generate a basic package config files so downstream can do:
  #   find_package(xorav CONFIG REQUIRED)
  include(CMakePackageConfigHelpers)

  # Minimal xoravConfig.cmake (uses only the exported targets)
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/xoravConfig.cmake
"include(\"\${CMAKE_CURRENT_LIST_DIR}/xoravTargets.cmake\")
")

  # Version file for find_package version checks
  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/xoravConfigVersion.cmake
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion
  )

  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/xoravConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/xoravConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xorav
  )
endif()