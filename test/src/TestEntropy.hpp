#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/Entropy.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestEntropy, EntropyClass)
{
	{
		MEMORY_LEAK_TEST_COUNT(0);

		Entropy<> entropy1;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(1);

		Entropy<> entropy2;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(2);

		entropy1 = std::move(entropy1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_COUNT(2);

		entropy2 = std::move(entropy1);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_COUNT(1);

		// Moved to initialize new one, allocation should remain the same.
		Entropy<> entropy3(std::move(entropy2));

		// This should success.
		entropy3.NullCheck();

		//hmacBase1.NullCheck();
		EXPECT_THROW(entropy1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(entropy2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestEntropy, SharedEntropy)
{
	void* sharedPtr = nullptr;

	{
		MEMORY_LEAK_TEST_COUNT(0);

		std::unique_ptr<EntropyInterface> shared = GetSharedEntropy();

		EXPECT_NE(shared->GetRawPtr(), nullptr);
		sharedPtr = shared->GetRawPtr();

		MEMORY_LEAK_TEST_COUNT(1);

		Entropy<> entropy1;

		EXPECT_NE(shared->GetRawPtr(), entropy1.GetRawPtr());

		MEMORY_LEAK_TEST_COUNT(2);
	}

	for(size_t i = 0; i < 10000; ++i)
	{
		MEMORY_LEAK_TEST_COUNT(1);

		std::unique_ptr<EntropyInterface> shared = GetSharedEntropy();

		MEMORY_LEAK_TEST_COUNT(1);

		EXPECT_EQ(shared->GetRawPtr(), sharedPtr);
	}

	MEMORY_LEAK_TEST_COUNT(1);
}

GTEST_TEST(TestEntropy, GetEntropy)
{
	std::unique_ptr<EntropyInterface> shared = GetSharedEntropy();
	for(size_t i = 0; i < 10000; ++i)
	{
		EXPECT_NE(shared->GetEntropy<uint64_t>(), shared->GetEntropy<uint64_t>());
	}
}
