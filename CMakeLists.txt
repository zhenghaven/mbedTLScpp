# Copyright 2020 Haofan Zheng
# See accompanying file LICENSE

cmake_minimum_required(VERSION 3.14)

project(mbedTLScpp VERSION 0.1.2 LANGUAGES CXX)

add_subdirectory(include)

OPTION(MBEDTLSCPP_TEST "Option to build mbedTLScpp test executable." OFF)
# SET(MBEDTLSCPP_TEST ON CACHE BOOL "Option to build mbedTLScpp test executable." FORCE)

set(ENV{MBEDTLSCPP_HOME} ${CMAKE_CURRENT_LIST_DIR})
set(MBEDTLSCPP_HOME ${CMAKE_CURRENT_LIST_DIR})

set(ENV{MBEDTLSCPP_INCLUDE} $ENV{MBEDTLSCPP_HOME}/include)
set(MBEDTLSCPP_INCLUDE ${MBEDTLSCPP_HOME}/include)

set(ENV{MBEDTLSCPP_MBEDTLS_HEADERS}
	$ENV{MBEDTLSCPP_INCLUDE}/mbedTLScpp/mbedtls-headers)
set(MBEDTLSCPP_MBEDTLS_HEADERS
	${MBEDTLSCPP_INCLUDE}/mbedTLScpp/mbedtls-headers)

add_library(mbedTLScpp INTERFACE)

target_include_directories(mbedTLScpp INTERFACE include)

if(${MBEDTLSCPP_TEST})
	add_subdirectory(test)
endif(${MBEDTLSCPP_TEST})
