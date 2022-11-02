// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <gtest/gtest.h>

#include <mbedTLScpp/Internal/PemHelper.hpp>


namespace mbedTLScpp_Test
{
	extern size_t g_numOfTestFile;
}


#ifdef MBEDTLSCPPTEST_TEST_STD_NS
using namespace std;
#endif

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

using namespace mbedTLScpp_Test;


GTEST_TEST(TestInternalPemHelper, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestInternalPemHelper, Base64EncodedSize)
{
	// has padding
	EXPECT_EQ(Internal::Base64EncodedSize<true>(0), 0);

	EXPECT_EQ(Internal::Base64EncodedSize<true>(1), 4);
	EXPECT_EQ(Internal::Base64EncodedSize<true>(2), 4);
	EXPECT_EQ(Internal::Base64EncodedSize<true>(3), 4);

	EXPECT_EQ(Internal::Base64EncodedSize<true>(4), 8);
	EXPECT_EQ(Internal::Base64EncodedSize<true>(5), 8);
	EXPECT_EQ(Internal::Base64EncodedSize<true>(6), 8);

	EXPECT_EQ(Internal::Base64EncodedSize<true>(7), 12);
	EXPECT_EQ(Internal::Base64EncodedSize<true>(8), 12);



	// no padding
	EXPECT_EQ(Internal::Base64EncodedSize<false>(0), 0);

	EXPECT_EQ(Internal::Base64EncodedSize<false>(1), 2);
	EXPECT_EQ(Internal::Base64EncodedSize<false>(2), 3);
	EXPECT_EQ(Internal::Base64EncodedSize<false>(3), 4);

	EXPECT_EQ(Internal::Base64EncodedSize<false>(4), 6);
	EXPECT_EQ(Internal::Base64EncodedSize<false>(5), 7);
	EXPECT_EQ(Internal::Base64EncodedSize<false>(6), 8);

	EXPECT_EQ(Internal::Base64EncodedSize<false>(7), 10);
	EXPECT_EQ(Internal::Base64EncodedSize<false>(8), 11);
	EXPECT_EQ(Internal::Base64EncodedSize<false>(9), 12);
}
