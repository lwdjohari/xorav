cmake_minimum_required(VERSION 3.14)

add_executable(xorav_headers_test
  main.c
)
target_include_directories(xorav_headers_test
  PRIVATE
    ${CMAKE_SOURCE_DIR}/xorav/inc
    ${CMAKE_SOURCE_DIR}/third_party/stb_ds
)
target_link_libraries(xorav_headers_test
  PRIVATE
    xorav::xorav
)
