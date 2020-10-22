#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/BigNumber.hpp>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestBigNumber, BigNumberClass)
{
	{
		BigNumberBase<DefaultBigNumObjTrait> bigNum1;

		// after successful initialization, we should have its allocation remains.
		EXPECT_EQ(Internal::gs_allocationLeft, 1);

		BigNumberBase<DefaultBigNumObjTrait> bigNum2;

		// after successful initialization, we should have its allocation remains.
		EXPECT_EQ(Internal::gs_allocationLeft, 2);

		bigNum1 = std::move(bigNum1);

		// Nothing moved, allocation should stay the same.
		EXPECT_EQ(Internal::gs_allocationLeft, 2);

		bigNum1 = std::move(bigNum2);

		// Moved, allocation should reduce.
		EXPECT_EQ(Internal::gs_allocationLeft, 1);

		// Moved to initialize new one, allocation should remain the same.
		BigNumberBase<DefaultBigNumObjTrait> bigNum3(std::move(bigNum1));

		// This should success.
		bigNum3.NullCheck();

		//bigNum1.NullCheck();
		EXPECT_THROW(bigNum1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(bigNum2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	EXPECT_EQ(Internal::gs_allocationLeft, 0);
}
