#include <gtest/gtest.h>

#include <mbedTLScpp/Hash.hpp>
#include <mbedTLScpp/Internal/Codec.hpp>

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

GTEST_TEST(TestHash, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestHash, MsgDigestBaseClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		// An invalid initialization should fail.
		EXPECT_THROW({MsgDigestBase<> mdBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_NONE), false);}, mbedTLSRuntimeError);

		// Failed initialization should delete the allocated memory.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		MsgDigestBase<> mdBase1(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256), false);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		MsgDigestBase<> mdBase2(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256), false);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		mdBase1 = std::move(mdBase1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		mdBase1 = std::move(mdBase2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		MsgDigestBase<> mdBase3(std::move(mdBase1));

		// This should success.
		mdBase3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(mdBase1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(mdBase2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestHash, HasherBaseClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		// An invalid initialization should fail.
		EXPECT_THROW({HasherBase hashBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_NONE));}, mbedTLSRuntimeError);

		// Failed initialization should delete the allocated memory.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		HasherBase hashBase1(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		HasherBase hashBase2(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		hashBase1 = std::move(hashBase1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		hashBase2 = std::move(hashBase1);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		HasherBase hashBase3(std::move(hashBase2));

		// This should success.
		hashBase3.NullCheck();

		//hashBase1.NullCheck();
		EXPECT_THROW(hashBase1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(hashBase2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestHash, HasherBaseCalc)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		HasherBase hashBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256));

		hashBase.Update(CtnItemRgR<0, 12>("TestMessage1"));

		auto hash = hashBase.Finish();
		auto hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash));

		EXPECT_EQ(hashHex, "6f336af9d06109a1e98d77f57f959f98364c28c17223728d68f4e8a98a7e1308");

		hashBase = HasherBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA512));

		hashBase.Update(CtnItemRgR<0, 12>("TestMessage1"));

		hash = hashBase.Finish();
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash));

		EXPECT_EQ(hashHex, "c8dfe09cea32f4d23a24a35aa6adcc6b7136f3a7ba3a8c1617e9c125983aade277a2ffb253bebb150eb59aafcd2d2b385699d7e08b280692d569b41258f8b675");

		hashBase = HasherBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA384));

		hashBase.Update(CtnItemRgR<0, 12>("TestMessage1"));

		hash = hashBase.Finish();
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash));

		EXPECT_EQ(hashHex, "c17505af5ad0fa0ae6588bd34f3f443214ddc2f10de91118f798d4a6e8259c46fc66cedfb89f84e8c7662c2fb4f87a10");

		hashBase = HasherBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA224));

		hashBase.Update(CtnItemRgR<0, 12>("TestMessage1"));

		hash = hashBase.Finish();
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash));

		EXPECT_EQ(hashHex, "e735384ee0cd4af03e52e2612ceb51d7a44a2ff160b33de68a96882a");
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestHash, HasherClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{

		Hasher<HashType::SHA256> hash2561;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		Hasher<HashType::SHA256> hash2562;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		hash2561 = std::move(hash2561);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		hash2562 = std::move(hash2561);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		Hasher<HashType::SHA256> hash2563(std::move(hash2562));

		// This should success.
		hash2563.NullCheck();

		//hashBase1.NullCheck();
		EXPECT_THROW(hash2561.NullCheck(), InvalidObjectException);
		EXPECT_THROW(hash2562.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestHash, HasherCalc)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		Hasher<HashType::SHA256> hasher256;

		hasher256.Update(CtnFullR("TestMessage1"));

		Hash<HashType::SHA256> hash256 = hasher256.Finish();
		auto hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash256));

		EXPECT_EQ(hashHex, "1b8efccafb73f0f4dc83aa63e94d674f727fc926f2c6be8fbef6abdf33c28800");

		hasher256.Restart();
		hash256 = hasher256.Calc(CtnFullR("TestMessage2"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash256));

		EXPECT_EQ(hashHex, "f1ddaf127eced80d80df121393494c74da9e3e3b91c60e6cbfb9097127bf0149");

		Hasher<HashType::SHA512> hasher512;

		hasher512.Update(CtnFullR("TestMessage1"));

		Hash<HashType::SHA512> hash512 = hasher512.Finish();
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash512));

		EXPECT_EQ(hashHex, "252d5e0d62e9dc32e7ec833f545c868b62ee4a53850f349aea9e02ad36b4b138bf81ecfd2a2f06fd5f3cb1042b6bd56e8ef740abfbfb85c7d20bd76827b35ed7");

		hasher512.Restart();
		hash512 = hasher512.Calc(CtnFullR("TestMessage2"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash512));

		EXPECT_EQ(hashHex, "9b8898e392559997183830c80000dd49c854479b89f21aaad571896fdd27e21c67098c8ed90d7431b4ba0946e9804ce3836ba741d712647268e322d8c290e1fb");

		hash512 = Hasher<HashType::SHA512>().Calc(CtnFullR("TestMessage3"),
												CtnFullR("TestMessage4"),
												CtnFullR("TestMessage5"),
												CtnFullR("TestMessage6"),
												CtnFullR("TestMessage7"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash512));

		EXPECT_EQ(hashHex, "347a9b8d79fafebb246e3b3d1b0c8b5b85db65f207277dfbf2821027bc6170ef8dc941c309e5f9356c087d2fa33d9da9c037dfa0edc46dc81e8cabcbba354b90");

		Hasher<HashType::SHA384> hasher384;

		hasher384.Update(CtnItemRgR<0, 12>("TestMessage1"));

		Hash<HashType::SHA384> hash384 = hasher384.Finish();
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash384));

		EXPECT_EQ(hashHex, "c17505af5ad0fa0ae6588bd34f3f443214ddc2f10de91118f798d4a6e8259c46fc66cedfb89f84e8c7662c2fb4f87a10");

		hasher384.Restart();
		hash384 = hasher384.Calc(CtnFullR("TestMessage2"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash384));

		EXPECT_EQ(hashHex, "47b4993c5cfee74444ba4333be9feeac794adeb3161b2deb6af8b948742c72a7fa9ff22fb5a2addfc00d9106df6bfab6");

		hash384 = Hasher<HashType::SHA384>().Calc(CtnFullR("TestMessage3"),
												CtnFullR("TestMessage4"),
												CtnFullR("TestMessage5"),
												CtnFullR("TestMessage6"),
												CtnFullR("TestMessage7"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash384));

		EXPECT_EQ(hashHex, "5bd7824205df29d2b6eed4ddf37a2256e73e3c10684fc6e506ffdb774d4f9e9af5664001b886d2a59e56250eb4dd49da");

		Hasher<HashType::SHA224> hasher224;

		hasher224.Update(CtnItemRgR<0, 12>("TestMessage1"));

		Hash<HashType::SHA224> hash224 = hasher224.Finish();
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash224));

		EXPECT_EQ(hashHex, "e735384ee0cd4af03e52e2612ceb51d7a44a2ff160b33de68a96882a");

		hasher224.Restart();
		hash224 = hasher224.Calc(CtnFullR("TestMessage2"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash224));

		EXPECT_EQ(hashHex, "326669f84022068f500fc8cb5eafbc938ef2c15393c26215d36bd5b3");

		hash224 = Hasher<HashType::SHA224>().Calc(CtnFullR("TestMessage3"),
												CtnFullR("TestMessage4"),
												CtnFullR("TestMessage5"),
												CtnFullR("TestMessage6"),
												CtnFullR("TestMessage7"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash224));

		EXPECT_EQ(hashHex, "a6b3572ff8d6150724e31295cb7448bc19b2642646b41cc9d54ef06f");
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
