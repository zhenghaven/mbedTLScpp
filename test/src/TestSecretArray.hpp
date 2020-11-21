#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/SecretArray.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestSecretArray, Initialization)
{
	SecretArray<uint8_t, 100> a;
	for (size_t i = 0; i < a.size(); ++i)
	{
		EXPECT_EQ(a[i], 0);
	}
}
