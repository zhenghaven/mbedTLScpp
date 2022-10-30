# Copyright (c) 2022 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.


cmake_minimum_required(VERSION 3.14)

OPTION(MBEDTLSCPP_TEST_CXX_STANDARD
	"C++ standard version used to build mbedTLScpp test executable." 11)
OPTION(MBEDTLSCPP_TEST_LCOV "Option to turn on test code coverage." OFF)

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


################################################################################
# Fetching dependencise
################################################################################

include(FetchContent)

FetchContent_Declare(
	git_simplecmakescripts
	GIT_REPOSITORY https://github.com/zhenghaven/SimpleCMakeScripts.git
	GIT_TAG        v0.3
)
FetchContent_MakeAvailable(git_simplecmakescripts)
simplecmakescripts_enable()

# GTest
FetchContent_Declare(
  git_googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.11.0
)
FetchContent_MakeAvailable(git_googletest)

# MbedTLS
set(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests." FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs." FORCE)
FetchContent_Declare(
  git_mbedtls
  GIT_REPOSITORY https://github.com/zhenghaven/mbedtls.git
  GIT_TAG        decent-enclave
)
FetchContent_MakeAvailable(git_mbedtls)
mbedTLScpp_UseMbedtlsHeaders_Normal(mbedcrypto)
mbedTLScpp_UseMbedtlsHeaders_Normal(mbedx509)
mbedTLScpp_UseMbedtlsHeaders_Normal(mbedtls)


################################################################################
# Adding testing executable
################################################################################

set(SOURCES_DIR_PATH ${CMAKE_CURRENT_LIST_DIR}/src)

file(GLOB_RECURSE SOURCES ${SOURCES_DIR_PATH}/*.[ch]*)

add_executable(mbedTLScpp_test ${SOURCES})

target_compile_options(mbedTLScpp_test
	PRIVATE $<$<CONFIG:>:${DEBUG_OPTIONS}>
			$<$<CONFIG:Debug>:${DEBUG_OPTIONS}>
			$<$<CONFIG:Release>:${RELEASE_OPTIONS}>)

target_compile_definitions(mbedTLScpp_test
	PRIVATE
		MBEDTLSCPP_MEMORY_TEST
		MBEDTLSCPPTEST_TEST_STD_NS
)

set_property(TARGET mbedTLScpp_test
	PROPERTY CXX_STANDARD ${MBEDTLSCPP_TEST_CXX_STANDARD})

target_link_libraries(mbedTLScpp_test mbedtls mbedTLScpp gtest)

add_test(NAME mbedTLScpp_test
	COMMAND mbedTLScpp_test)


if (MBEDTLSCPP_TEST_LCOV)
	include(SimpleTestCoverage)
	message(STATUS "Setting up test coverage target...")
	simple_cxx_test_coverage(mbedTLScpp_test "${PROJECT_SOURCE_DIR}/include")
endif()
