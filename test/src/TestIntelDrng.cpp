#include <gtest/gtest.h>

#include <set>
#include <array>

#include <mbedTLScpp/Internal/PlatformIntel/Drng.hpp>

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

GTEST_TEST(TestIntelDrng, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestIntelDrng, AvailabilityTest)
{
	EXPECT_TRUE(Internal::PlatformIntel::IsIntelProcessor());
	EXPECT_TRUE(Internal::PlatformIntel::IsRdSeedSupportedCached());
	EXPECT_TRUE(Internal::PlatformIntel::IsRdRandSupportedCached());
}

GTEST_TEST(TestIntelDrng, RdSeedTest)
{

	// uint16_t
	{
		std::set<uint16_t> randSet;

		uint16_t tmp = 0;
		for(size_t i = 0; i < 10; ++i)
		{
			bool insertRes = false;
			size_t maxRetries = Internal::PlatformIntel::gsk_rdSeedRcRetryPerStep;
			EXPECT_NO_THROW(
				Internal::PlatformIntel::Internal::rdseed(&tmp, maxRetries);
			);
			std::tie(std::ignore, insertRes) = randSet.insert(tmp);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), 10);
	}

	// uint32_t
	{
		std::set<uint32_t> randSet;

		uint32_t tmp = 0;
		for(size_t i = 0; i < 100; ++i)
		{
			bool insertRes = false;
			size_t maxRetries = Internal::PlatformIntel::gsk_rdSeedRcRetryPerStep;
			EXPECT_NO_THROW(
				Internal::PlatformIntel::Internal::rdseed(&tmp, maxRetries);
			);
			std::tie(std::ignore, insertRes) = randSet.insert(tmp);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), 100);
	}
	// uint64_t
	{
		std::set<uint64_t> randSet;

		uint64_t tmp = 0;
		for(size_t i = 0; i < 100; ++i)
		{
			bool insertRes = false;
			size_t maxRetries = Internal::PlatformIntel::gsk_rdSeedRcRetryPerStep;
			EXPECT_NO_THROW(
				Internal::PlatformIntel::Internal::rdseed(&tmp, maxRetries);
			);
			std::tie(std::ignore, insertRes) = randSet.insert(tmp);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), 100);
	}
}

GTEST_TEST(TestIntelDrng, SeedBytesTest)
{
	// uint64_t
	{
		std::array<uint64_t, 11000> randArr;
		constexpr size_t maxRetries = 10 * ((sizeof(uint64_t) * 10000) / sizeof(uint64_t));
		size_t offset = 2;

		size_t generated = 0;
		EXPECT_NO_THROW(
			generated = Internal::PlatformIntel::Internal::rdseed_get_bytes(
				(sizeof(uint64_t) * 10000),
				((uint8_t*)randArr.data()) + offset,
				0,
				maxRetries
			);
		);
		EXPECT_EQ(generated, sizeof(uint64_t) * 10000);

		std::set<uint64_t> randSet;

		for (size_t i = 0; i < 10000; ++i)
		{
			bool insertRes = false;
			std::tie(std::ignore, insertRes) = randSet.insert(randArr[i]);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), 10000);
	}
}

GTEST_TEST(TestIntelDrng, ReadSeedTest)
{
	// uint64_t
	{
		std::array<uint64_t, 10000> randArr;

		size_t generated = 0;
		EXPECT_NO_THROW(
			generated = Internal::PlatformIntel::ReadSeed(
				((uint8_t*)randArr.data()),
				(sizeof(uint64_t) * randArr.size())
			);
		);
		EXPECT_EQ(generated, sizeof(uint64_t) * randArr.size());

		std::set<uint64_t> randSet;

		for (size_t i = 0; i < randArr.size(); ++i)
		{
			bool insertRes = false;
			std::tie(std::ignore, insertRes) = randSet.insert(randArr[i]);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), randArr.size());
	}
}

GTEST_TEST(TestIntelDrng, RdRandTest)
{

	// uint16_t
	{
		std::set<uint16_t> randSet;

		uint16_t tmp = 0;
		for(size_t i = 0; i < 10; ++i)
		{
			bool insertRes = false;
			EXPECT_NO_THROW(
				Internal::PlatformIntel::Internal::rdrand(&tmp, true);
			);
			std::tie(std::ignore, insertRes) = randSet.insert(tmp);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), 10);
	}

	// uint32_t
	{
		std::set<uint32_t> randSet;

		uint32_t tmp = 0;
		for(size_t i = 0; i < 100; ++i)
		{
			bool insertRes = false;
			EXPECT_NO_THROW(
				Internal::PlatformIntel::Internal::rdrand(&tmp, true);
			);
			std::tie(std::ignore, insertRes) = randSet.insert(tmp);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), 100);
	}
	// uint64_t
	{
		std::set<uint64_t> randSet;

		uint64_t tmp = 0;
		for(size_t i = 0; i < 100; ++i)
		{
			bool insertRes = false;
			EXPECT_NO_THROW(
				Internal::PlatformIntel::Internal::rdrand(&tmp, true);
			);
			std::tie(std::ignore, insertRes) = randSet.insert(tmp);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), 100);
	}
}

GTEST_TEST(TestIntelDrng, RandBytesTest)
{
	// uint64_t
	{
		std::array<uint64_t, 11000> randArr;
		size_t offset = 2;

		EXPECT_NO_THROW(
			Internal::PlatformIntel::Internal::rdrand_get_bytes(
				(sizeof(uint64_t) * 10000),
				((uint8_t*)randArr.data()) + offset
			);
		);

		std::set<uint64_t> randSet;

		for (size_t i = 0; i < 10000; ++i)
		{
			bool insertRes = false;
			std::tie(std::ignore, insertRes) = randSet.insert(randArr[i]);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), 10000);
	}
}

GTEST_TEST(TestIntelDrng, ReadRandTest)
{
	// uint64_t
	{
		std::array<uint64_t, 10000> randArr;

		EXPECT_NO_THROW(
			Internal::PlatformIntel::ReadRand(
				((uint8_t*)randArr.data()),
				(sizeof(uint64_t) * randArr.size())
			);
		);

		std::set<uint64_t> randSet;

		for (size_t i = 0; i < randArr.size(); ++i)
		{
			bool insertRes = false;
			std::tie(std::ignore, insertRes) = randSet.insert(randArr[i]);
			EXPECT_TRUE(insertRes);
		}

		EXPECT_EQ(randSet.size(), randArr.size());
	}
}
