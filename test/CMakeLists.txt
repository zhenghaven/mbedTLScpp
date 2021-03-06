# Copyright 2020 Haofan Zheng
# See accompanying file LICENSE

cmake_minimum_required(VERSION 3.14)

project(mbedTLScpp_test VERSION 0.1 LANGUAGES CXX)

################################################################################
# Set compile options
################################################################################

if(MSVC)
	set(COMMON_OPTIONS /W3 /wd4996 /we4239 /we4002 /we4700 /we4305 /EHsc /MP)
	set(DEBUG_OPTIONS /MTd /Od /Zi /DDEBUG)
	set(RELEASE_OPTIONS /MT /Ox /Oi /Ob2 /fp:fast /GR-)# /DNDEBUG
else()
	set(COMMON_OPTIONS -pthread)
	set(DEBUG_OPTIONS -O0 -g -DDEBUG)
	set(RELEASE_OPTIONS -O2) #-DNDEBUG defined by default
endif()

set(DEBUG_OPTIONS ${COMMON_OPTIONS} ${DEBUG_OPTIONS})
set(RELEASE_OPTIONS ${COMMON_OPTIONS} ${RELEASE_OPTIONS})

if(MSVC)
	set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /DEBUG")
endif()

add_compile_options(
	"$<$<CONFIG:Debug>:${DEBUG_OPTIONS}>"
	"$<$<CONFIG:Release>:${RELEASE_OPTIONS}>"
)

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_CXX_STANDARD 20)

################################################################################
# Fetching dependencise
################################################################################

set(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests." FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs." FORCE)

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
include($ENV{MBEDTLSCPP_HOME}/cmake/mbedTLScpp_UseMbedtlsHeaders.cmake)
mbedTLScpp_UseMbedtlsHeaders_Normal(mbedcrypto)
mbedTLScpp_UseMbedtlsHeaders_Normal(mbedx509)
mbedTLScpp_UseMbedtlsHeaders_Normal(mbedtls)

################################################################################
# Adding testing executable
################################################################################

set(SOURCES_DIR_PATH ${CMAKE_CURRENT_LIST_DIR}/src)

file(GLOB_RECURSE SOURCES ${SOURCES_DIR_PATH}/*.[ch]*)

add_executable(mbedTLScpp_test ${SOURCES})

target_compile_definitions(mbedTLScpp_test
	PRIVATE
		MBEDTLSCPP_MEMORY_TEST
		MBEDTLSCPPTEST_TEST_STD_NS
)

target_link_libraries(mbedTLScpp_test mbedtls mbedTLScpp gtest)
