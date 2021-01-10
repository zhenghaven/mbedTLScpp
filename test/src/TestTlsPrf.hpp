#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/TlsPrf.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestTlsPrf, TlsPrfCalc)
{
	SKey<256> skey256({
		0,1,2,3,4,5,6,7,
		0,1,2,3,4,5,6,7,
		0,1,2,3,4,5,6,7,
		0,1,2,3,4,5,6,7,
	});

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	std::string testLabel = "Test_Label";
	std::string testRand  = "Test_Rand";

	{
		SKey<256> resKey1 = TlsPrf<TlsPrfType::SHA256, 256>(CtnFullR(skey256), testLabel, CtnFullR(testRand));

		SKey<256> resKey2 = TlsPrf<TlsPrfType::SHA256, 256>(CtnFullR(skey256), testLabel, CtnFullR(testRand));

		SKey<256> resKey3 = TlsPrf<TlsPrfType::SHA256, 256>(CtnFullR(skey256), testLabel + "x", CtnFullR(testRand));

		SKey<256> resKey4 = TlsPrf<TlsPrfType::SHA256, 256>(CtnFullR(skey256), testLabel, CtnFullR(testRand + "x"));

		SKey<256> resKey5 = TlsPrf<TlsPrfType::SHA256, 256>(CtnFullR(skey256), testLabel + "x", CtnFullR(testRand + "x"));

		EXPECT_EQ(resKey1, resKey2);

		EXPECT_NE(resKey2, resKey3);
		EXPECT_NE(resKey2, resKey4);
		EXPECT_NE(resKey2, resKey5);
	}

	{
		EXPECT_NO_THROW((
			[skey256, testLabel, testRand]()
			{
				auto key = TlsPrf<TlsPrfType::TLS1  , 128>(CtnFullR(skey256), testLabel, CtnFullR(testRand));
			}()
		));
		EXPECT_NO_THROW((
			[skey256, testLabel, testRand]()
			{
				auto key = TlsPrf<TlsPrfType::SHA256, 256>(CtnFullR(skey256), testLabel, CtnFullR(testRand));
			}()
		));
		EXPECT_NO_THROW((
			[skey256, testLabel, testRand]()
			{
				auto key = TlsPrf<TlsPrfType::SHA384, 512>(CtnFullR(skey256), testLabel, CtnFullR(testRand));
			}()
		));
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
