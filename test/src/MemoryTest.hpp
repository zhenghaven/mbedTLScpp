#include <gtest/gtest.h>

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
#else
#	define MEMORY_LEAK_TEST_COUNT(X)
#endif
