# Copyright 2020 Haofan Zheng
# See accompanying file LICENSE

cmake_minimum_required(VERSION 3.14)

project(mbedTLScpp VERSION 0.1 LANGUAGES CXX)

OPTION(MBEDTLSCPP_TEST "Option to build mbedTLScpp test executable." OFF)
# SET(MBEDTLSCPP_TEST ON CACHE BOOL "Option to build mbedTLScpp test executable." FORCE)

add_library(mbedTLScpp INTERFACE)

target_include_directories(mbedTLScpp INTERFACE include)

if(${MBEDTLSCPP_TEST})
	add_subdirectory(test)
endif(${MBEDTLSCPP_TEST})
