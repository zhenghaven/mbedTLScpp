#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/Entropy.hpp>

#ifdef MBEDTLSCPP_MEMORY_TEST
#include <mbedTLScpp/Internal/Memory.hpp>

#	ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScppMemoryLeakNS = mbedTLScpp::Internal;
#	else
namespace mbedTLScppMemoryLeakNS = MBEDTLSCPP_CUSTOMIZED_NAMESPACE::Internal;
#	endif

#endif

#ifdef MBEDTLSCPP_MEMORY_TEST
#	define MEMORY_LEAK_TEST_COUNT(X) EXPECT_EQ(mbedTLScppMemoryLeakNS::gs_allocationLeft, X)
#	define MEMORY_LEAK_TEST_INCR_COUNT(INIT, X) MEMORY_LEAK_TEST_COUNT(INIT + X)
#	define MEMORY_LEAK_TEST_GET_COUNT(D) {D = mbedTLScppMemoryLeakNS::gs_allocationLeft;}
#else
#	define MEMORY_LEAK_TEST_COUNT(X)
#	define MEMORY_LEAK_TEST_INCR_COUNT(INIT, X)
#	define MEMORY_LEAK_TEST_GET_COUNT(D)
#endif

inline void SettleMemTestCountOnEntropy()
{
#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
	using namespace mbedTLScpp;
#else
	using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

	EXPECT_NE(GetSharedEntropy()->GetRawPtr(), nullptr);
}
