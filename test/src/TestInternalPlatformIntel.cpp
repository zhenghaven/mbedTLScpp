#include <gtest/gtest.h>

#include <set>
#include <array>

// This architecture checks derived from:
// https://stackoverflow.com/questions/152016/detecting-cpu-architecture-compile-time
#if defined(__x86_64__) || defined(_M_X64)
#	define MBEDTLSCPPTEST_ARCH_X86_64
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#	define MBEDTLSCPPTEST_ARCH_X86_32
#endif

#if defined(MBEDTLSCPPTEST_ARCH_X86_64) || defined(MBEDTLSCPPTEST_ARCH_X86_32)
#	define MBEDTLSCPPTEST_ARCH_X86
#endif

#ifdef MBEDTLSCPPTEST_ARCH_X86
#include <mbedTLScpp/Internal/PlatformIntel/Drng.hpp>
#endif

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

GTEST_TEST(TestInternalPlatformIntel, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestInternalPlatformIntel, AvailabilityTest)
{
#ifdef MBEDTLSCPPTEST_ARCH_X86
	EXPECT_TRUE(Internal::PlatformIntel::IsIntelProcessor());
	EXPECT_TRUE(Internal::PlatformIntel::IsRdSeedSupportedCached());
	EXPECT_TRUE(Internal::PlatformIntel::IsRdRandSupportedCached());
	std::cout<< "Intel CPU detected, " <<
		"RdSeed and RdRand are expected to be supported." << std::endl;
#else
	EXPECT_FALSE(Internal::PlatformIntel::IsIntelProcessor());
	EXPECT_FALSE(Internal::PlatformIntel::IsRdSeedSupportedCached());
	EXPECT_FALSE(Internal::PlatformIntel::IsRdRandSupportedCached());
	std::cout<< "Non-Intel CPU detected, " <<
		"RdSeed and RdRand tests are disabled." << std::endl;
#endif
}

template<typename _SetType>
static void RdSeedTest(_SetType& set)
{
	size_t maxRetries =
		Internal::PlatformIntel::gsk_rdSeedRcRetryPerStep;

	ASSERT_NO_THROW(
		try
		{
			bool insertRes = false;
			uint16_t tmp = 0;
			Internal::PlatformIntel::Internal::rdseed(&tmp, maxRetries);
			std::tie(std::ignore, insertRes) = set.insert(tmp);
			ASSERT_TRUE(insertRes);
		}
		catch(const Internal::PlatformIntel::PlatformBusyException&)
		{
			// platform is busy, that's ok
			std::cerr << "Platform was busy" << std::endl;
		}
	);
}

#ifdef MBEDTLSCPPTEST_ARCH_X86
GTEST_TEST(TestInternalPlatformIntel, RdSeedTest)
{

	// uint16_t
	{
		std::set<uint16_t> randSet;
		for(size_t i = 0; i < 10; ++i)
		{
			RdSeedTest(randSet);
		}
		EXPECT_GT(randSet.size(), 0);
	}

	// uint32_t
	{
		std::set<uint32_t> randSet;
		for(size_t i = 0; i < 10; ++i)
		{
			RdSeedTest(randSet);
		}
		EXPECT_GT(randSet.size(), 0);
	}

	// uint64_t
	{
		std::set<uint64_t> randSet;
		for(size_t i = 0; i < 10; ++i)
		{
			RdSeedTest(randSet);
		}
		EXPECT_GT(randSet.size(), 0);
	}
}

GTEST_TEST(TestInternalPlatformIntel, SeedBytesTest)
{
	// uint64_t
	{
		std::array<uint64_t, 110> randArr;
		constexpr size_t maxRetries =
			10 * ((sizeof(uint64_t) * 100) / sizeof(uint64_t));
		size_t offset = 2;

		size_t generated = 0;
		ASSERT_NO_THROW(
			try
			{
				generated = Internal::PlatformIntel::Internal::rdseed_get_bytes(
					(sizeof(uint64_t) * 100),
					((uint8_t*)randArr.data()) + offset,
					0,
					maxRetries
				);
				EXPECT_EQ(generated, sizeof(uint64_t) * 100);

				std::set<uint64_t> randSet;
				for (size_t i = 0; i < 100; ++i)
				{
					bool insertRes = false;
					std::tie(std::ignore, insertRes) =
						randSet.insert(randArr[i]);
					ASSERT_TRUE(insertRes);
				}
				EXPECT_EQ(randSet.size(), 100);
			}
			catch(const Internal::PlatformIntel::PlatformBusyException&)
			{
				// platform is busy, that's ok
				std::cerr << "Platform was busy" << std::endl;
			}
		);
	}
}

GTEST_TEST(TestInternalPlatformIntel, ReadSeedTest)
{
	// uint64_t
	{
		std::array<uint64_t, 1000> randArr;

		size_t generated = 0;
		ASSERT_NO_THROW(
			try
			{
				generated = Internal::PlatformIntel::ReadSeed(
					((uint8_t*)randArr.data()),
					(sizeof(uint64_t) * randArr.size())
				);
				EXPECT_EQ(generated, sizeof(uint64_t) * randArr.size());

				std::set<uint64_t> randSet;
				for (size_t i = 0; i < randArr.size(); ++i)
				{
					bool insertRes = false;
					std::tie(std::ignore, insertRes) =
						randSet.insert(randArr[i]);
					ASSERT_TRUE(insertRes);
				}
				EXPECT_EQ(randSet.size(), randArr.size());
			}
			catch(const Internal::PlatformIntel::PlatformBusyException&)
			{
				// platform is busy, that's ok
				std::cerr << "Platform was busy" << std::endl;
			}
		);
	}
}


template<typename _SetType>
static void RdRandTest(_SetType& set)
{
	ASSERT_NO_THROW(
		try
		{
			bool insertRes = false;
			uint16_t tmp = 0;
			Internal::PlatformIntel::Internal::rdrand(&tmp, true);
			std::tie(std::ignore, insertRes) = set.insert(tmp);
			ASSERT_TRUE(insertRes);
		}
		catch(const Internal::PlatformIntel::PlatformBusyException&)
		{
			// platform is busy, that's ok
			std::cerr << "Platform was busy" << std::endl;
		}
	);
}


GTEST_TEST(TestInternalPlatformIntel, RdRandTest)
{

	// uint16_t
	{
		std::set<uint16_t> randSet;
		for(size_t i = 0; i < 10; ++i)
		{
			RdRandTest(randSet);
		}
		EXPECT_GT(randSet.size(), 0);
	}

	// uint32_t
	{
		std::set<uint32_t> randSet;
		for(size_t i = 0; i < 10; ++i)
		{
			RdRandTest(randSet);
		}
		EXPECT_GT(randSet.size(), 0);
	}
	// uint64_t
	{
		std::set<uint64_t> randSet;
		for(size_t i = 0; i < 10; ++i)
		{
			RdRandTest(randSet);
		}
		EXPECT_GT(randSet.size(), 0);
	}
}

GTEST_TEST(TestInternalPlatformIntel, RandBytesTest)
{
	// uint64_t
	{
		std::array<uint64_t, 110> randArr;
		size_t offset = 2;

		ASSERT_NO_THROW(
			try{
				Internal::PlatformIntel::Internal::rdrand_get_bytes(
					(sizeof(uint64_t) * 100),
					((uint8_t*)randArr.data()) + offset
				);

				std::set<uint64_t> randSet;
				for (size_t i = 0; i < 100; ++i)
				{
					bool insertRes = false;
					std::tie(std::ignore, insertRes) =
						randSet.insert(randArr[i]);
					ASSERT_TRUE(insertRes);
				}
				EXPECT_EQ(randSet.size(), 100);
			}
			catch(const Internal::PlatformIntel::PlatformBusyException&)
			{
				// platform is busy, that's ok
				std::cerr << "Platform was busy" << std::endl;
			}
		);

	}
}

GTEST_TEST(TestInternalPlatformIntel, ReadRandTest)
{
	// uint64_t
	{
		std::array<uint64_t, 1000> randArr;

		EXPECT_NO_THROW(
			try
			{
				Internal::PlatformIntel::ReadRand(
					((uint8_t*)randArr.data()),
					(sizeof(uint64_t) * randArr.size())
				);

				std::set<uint64_t> randSet;
				for (size_t i = 0; i < randArr.size(); ++i)
				{
					bool insertRes = false;
					std::tie(std::ignore, insertRes) =
						randSet.insert(randArr[i]);
					ASSERT_TRUE(insertRes);
				}
				EXPECT_EQ(randSet.size(), randArr.size());
			}
			catch(const Internal::PlatformIntel::PlatformBusyException&)
			{
				// platform is busy, that's ok
				std::cerr << "Platform was busy" << std::endl;
			}
		);

	}
}
#endif // MBEDTLSCPPTEST_ARCH_X86
