# Copyright 2020 Haofan Zheng
# See accompanying file LICENSE

cmake_minimum_required(VERSION 3.14)

project(mbedTLScpp_test VERSION 0.1 LANGUAGES CXX)

################################################################################
# Fetching dependencise
################################################################################

include(FetchContent)

FetchContent_Declare(
  git_googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.10.0
)
FetchContent_MakeAvailable(git_googletest)

FetchContent_Declare(
  git_mbedtls
  GIT_REPOSITORY https://github.com/ARMmbed/mbedtls.git
  GIT_TAG        v2.24.0
)
FetchContent_MakeAvailable(git_mbedtls)

################################################################################
# Adding testing environment and executable
################################################################################

set(CMAKE_CXX_STANDARD 11)

set(SOURCES_DIR_PATH ${CMAKE_CURRENT_LIST_DIR}/src)

file(GLOB_RECURSE SOURCES ${SOURCES_DIR_PATH}/*.[ch]*)

add_executable(mbedTLScpp_test ${SOURCES})

target_compile_definitions(mbedTLScpp_test PUBLIC MBEDTLSCPP_TEST)

target_link_libraries(mbedTLScpp_test mbedtls mbedTLScpp gtest)
