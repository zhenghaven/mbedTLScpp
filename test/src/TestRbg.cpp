#include <random>

#include <gtest/gtest.h>

#include <mbedTLScpp/CtrDrbg.hpp>
#include <mbedTLScpp/HmacDrbg.hpp>

#include "MemoryTest.hpp"
#include "SelfMoveTest.hpp"

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

#ifdef MBEDTLS_THREADING_C
	static constexpr bool gsk_threadEnabled = true;
#else
	static constexpr bool gsk_threadEnabled = false;
#endif

GTEST_TEST(TestRbg, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestRbg, CtrDrbgClass)
{
	SettleMemTestCountOnEntropy();
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);

		CtrDrbg<> rbg1;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1 + (gsk_threadEnabled ? 1 : 0));

		CtrDrbg<> rbg2;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2 + (gsk_threadEnabled ? 2 : 0));

		MBEDTLSCPPTEST_SELF_MOVE_TEST(rbg1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2 + (gsk_threadEnabled ? 2 : 0));

		rbg2 = std::move(rbg1);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1 + (gsk_threadEnabled ? 1 : 0));

		// Moved to initialize new one, allocation should remain the same.
		CtrDrbg<> rbg3(std::move(rbg2));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1 + (gsk_threadEnabled ? 1 : 0));

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
	for(size_t i = 0; i < 1000; ++i)
	{
		EXPECT_NE(rbg.GetRand<uint64_t>(), rbg.GetRand<uint64_t>());
	}
}

GTEST_TEST(TestRbg, HmacDrbgClass)
{
	SettleMemTestCountOnEntropy();
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);

		HmacDrbg<> rbg1;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1 + (gsk_threadEnabled ? 1 : 0));

		HmacDrbg<> rbg2;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2 + (gsk_threadEnabled ? 2 : 0));

		MBEDTLSCPPTEST_SELF_MOVE_TEST(rbg1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2 + (gsk_threadEnabled ? 2 : 0));

		rbg2 = std::move(rbg1);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1 + (gsk_threadEnabled ? 1 : 0));

		// Moved to initialize new one, allocation should remain the same.
		HmacDrbg<> rbg3(std::move(rbg2));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1 + (gsk_threadEnabled ? 1 : 0));

		// This should success.
		rbg3.NullCheck();

		//hmacBase1.NullCheck();
		EXPECT_THROW(rbg1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(rbg2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestRbg, HmacDrbgGetRand)
{
	HmacDrbg<> rbg;
	for(size_t i = 0; i < 1000; ++i)
	{
		EXPECT_NE(rbg.GetRand<uint64_t>(), rbg.GetRand<uint64_t>());
	}
}

GTEST_TEST(TestRbg, CppWrap)
{
	{
		RbgCppWrap<uint64_t, CtrDrbg<> > gen;
		std::uniform_int_distribution<int> dist(10, 50);

		for(size_t i = 0; i < 1000; ++i)
		{
			int randInt = dist(gen);
			EXPECT_TRUE((10 <= randInt && randInt <= 50));
		}
	}

	{
		RbgCppWrap<uint64_t, HmacDrbg<> > gen;
		std::uniform_int_distribution<int> dist(60, 90);

		for(size_t i = 0; i < 1000; ++i)
		{
			int randInt = dist(gen);
			EXPECT_TRUE((60 <= randInt && randInt <= 90));
		}
	}
}

inline int TestDrbgCallBack(std::unique_ptr<RbgInterface> rbg)
{
	int res;
	EXPECT_EQ(RbgInterface::CallBack(rbg.get(), reinterpret_cast<unsigned char*>(&res), sizeof(res)), MBEDTLS_EXIT_SUCCESS);
	return res;
}

GTEST_TEST(TestRbg, DefaultRbg)
{
	using DefaultRbg = CtrDrbg<>;
	using DefaultRbgCpp = RbgCppWrap<uint64_t, DefaultRbg>;

	DefaultRbg rbg;
	DefaultRbgCpp gen;
	std::uniform_int_distribution<int> dist(110, 150);

	for(size_t i = 0; i < 100; ++i)
	{
		EXPECT_NE(DefaultRbg().GetRand<uint64_t>(), DefaultRbg().GetRand<uint64_t>());
	}

	for(size_t i = 0; i < 100; ++i)
	{
		int randInt1 = 0;
		int randInt2 = 0;

		randInt1 = TestDrbgCallBack(Internal::make_unique<DefaultRbg>());
		randInt2 = TestDrbgCallBack(Internal::make_unique<DefaultRbg>());

		EXPECT_NE(randInt1, randInt2);
	}

	for(size_t i = 0; i < 100; ++i)
	{
		int randInt = dist(gen);
		EXPECT_TRUE((110 <= randInt && randInt <= 150));
	}
}
