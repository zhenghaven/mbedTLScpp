#include <gtest/gtest.h>

#include <mbedTLScpp/SecretArray.hpp>

#include "MemoryTest.hpp"

#ifdef MBEDTLSCPPTEST_TEST_STD_NS
using namespace std;
#endif

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

namespace mbedTLScpp_Test
{
	extern size_t g_numOfTestFile;
}

GTEST_TEST(TestSecretArray, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestSecretArray, Initialization)
{
	SecretArray<uint8_t, 100> a;
	for (size_t i = 0; i < a.size(); ++i)
	{
		EXPECT_EQ(a[i], 0);
	}
}
