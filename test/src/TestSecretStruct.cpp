#include <gtest/gtest.h>

#include <mbedTLScpp/SecretStruct.hpp>

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

namespace
{
	extern "C"
	{
#pragma pack(push, 1)
		struct TestStruct1
		{
			uint16_t a;
			uint32_t b;
		};

		struct TestStruct2
		{
			TestStruct1 a;
			uint8_t     b[16];
			uint64_t    c[32];
		};
#pragma pack(pop)
	}
}

GTEST_TEST(TestSecretStruct, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestSecretStruct, ClassTest)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		static_assert(sizeof(TestStruct2) == 278, "Size doesn't match.");

		SecretStruct<TestStruct2> s1{{{1, 2}, {3}, {4}}};
#ifdef MBEDTLSCPP_MEMORY_TEST
			gs_secretAllocationLeft += sizeof(TestStruct2);
#endif

		SecretStruct<TestStruct2> s2{{{1, 2}, {3}, {4}}};
#ifdef MBEDTLSCPP_MEMORY_TEST
			gs_secretAllocationLeft += sizeof(TestStruct2);
#endif

		SecretStruct<TestStruct2> s3{{{1, 5}, {3}, {4}}};
#ifdef MBEDTLSCPP_MEMORY_TEST
			gs_secretAllocationLeft += sizeof(TestStruct2);
#endif

		SecretStruct<TestStruct2> s21 = s2;
#ifdef MBEDTLSCPP_MEMORY_TEST
			gs_secretAllocationLeft += sizeof(TestStruct2);
#endif

		SecretStruct<TestStruct2> s22;
#ifdef MBEDTLSCPP_MEMORY_TEST
			gs_secretAllocationLeft += sizeof(TestStruct2);
#endif
		s22 = s2;

		EXPECT_EQ(s1, s2);
		EXPECT_EQ(s2, s21);
		EXPECT_EQ(s2, s22);

		EXPECT_NE(s3, s1);
		EXPECT_NE(s3, s2);
		EXPECT_NE(s3, s21);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
