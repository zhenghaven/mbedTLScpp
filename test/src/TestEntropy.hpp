#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/Entropy.hpp>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestEntropy, EntropyClass)
{
	{
		EXPECT_EQ(Internal::gs_allocationLeft, 0);

		Entropy<> entropy1;

		// after successful initialization, we should have its allocation remains.
		EXPECT_EQ(Internal::gs_allocationLeft, 1);

		Entropy<> entropy2;

		// after successful initialization, we should have its allocation remains.
		EXPECT_EQ(Internal::gs_allocationLeft, 2);

		entropy1 = std::move(entropy1);

		// Nothing moved, allocation should stay the same.
		EXPECT_EQ(Internal::gs_allocationLeft, 2);

		entropy2 = std::move(entropy1);

		// Moved, allocation should reduce.
		EXPECT_EQ(Internal::gs_allocationLeft, 1);

		// Moved to initialize new one, allocation should remain the same.
		Entropy<> entropy3(std::move(entropy2));

		// This should success.
		entropy3.NullCheck();

		//hmacBase1.NullCheck();
		EXPECT_THROW(entropy1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(entropy2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	EXPECT_EQ(Internal::gs_allocationLeft, 0);
}

GTEST_TEST(TestEntropy, SharedEntropy)
{
	mbedtls_entropy_context* sharedPtr = nullptr;

	{
		EXPECT_EQ(Internal::gs_allocationLeft, 0);

		std::unique_ptr<EntropyInterface> shared = GetSharedEntropy();

		EXPECT_NE(shared->Get(), nullptr);
		sharedPtr = shared->Get();

		EXPECT_EQ(Internal::gs_allocationLeft, 1);

		Entropy<> entropy1;

		EXPECT_NE(shared->Get(), entropy1.Get());

		EXPECT_EQ(Internal::gs_allocationLeft, 2);
	}

	for(size_t i = 0; i < 10000; ++i)
	{
		EXPECT_EQ(Internal::gs_allocationLeft, 1);

		std::unique_ptr<EntropyInterface> shared = GetSharedEntropy();

		EXPECT_EQ(Internal::gs_allocationLeft, 1);

		EXPECT_EQ(shared->Get(), sharedPtr);
	}

	EXPECT_EQ(Internal::gs_allocationLeft, 1);
}
