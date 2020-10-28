#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/CtrDrbg.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestRbg, CtrDrbgClass)
{
	SettleMemTestCountOnEntropy();
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);

		CtrDrbg<> rbg1;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);

		CtrDrbg<> rbg2;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);

		rbg1 = std::move(rbg1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);

		rbg2 = std::move(rbg1);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);

		// Moved to initialize new one, allocation should remain the same.
		CtrDrbg<> rbg3(std::move(rbg2));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);

		// This should success.
		rbg3.NullCheck();

		//hmacBase1.NullCheck();
		EXPECT_THROW(rbg1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(rbg2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestRbg, CtrDrbgGetRand)
{
	CtrDrbg<> rbg;
	for(size_t i = 0; i < 10000; ++i)
	{
		EXPECT_NE(rbg.GetRand<uint64_t>(), rbg.GetRand<uint64_t>());
	}
}

GTEST_TEST(TestRbg, CppWrap)
{
	RbgCppWrap<uint64_t, CtrDrbg<> > gen;
	std::uniform_int_distribution<int> dist(10, 50);

	for(size_t i = 0; i < 1000; ++i)
	{
		int randInt = dist(gen);
		EXPECT_TRUE((10 <= randInt && randInt <= 50));
	}
}
