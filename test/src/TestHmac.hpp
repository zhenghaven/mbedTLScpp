#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/Hmac.hpp>
#include <mbedTLScpp/Internal/Codec.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestHmac, HmacerBaseClass)
{
	SecretArray<uint8_t, 32> testKey;

	{
		// An invalid initialization should fail.
		EXPECT_THROW({HmacerBase hmacBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_NONE), CtnFullR(testKey));}, mbedTLSRuntimeError);

		// Failed initialization should delete the allocated memory.
		MEMORY_LEAK_TEST_COUNT(0);

		HmacerBase hmacBase1(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256), CtnFullR(testKey));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(1);

		HmacerBase hmacBase2(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256), CtnFullR(testKey));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(2);

		hmacBase1 = std::move(hmacBase1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_COUNT(2);

		hmacBase2 = std::move(hmacBase1);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_COUNT(1);

		// Moved to initialize new one, allocation should remain the same.
		HmacerBase hmacBase3(std::move(hmacBase2));

		// This should success.
		hmacBase3.NullCheck();

		//hmacBase1.NullCheck();
		EXPECT_THROW(hmacBase1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(hmacBase2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestHmac, HmacerBaseCalc)
{
	static constexpr char const testKeyStr[] = "TestKey1";
	SecretArray<uint8_t, 8> testKey;
	std::copy(std::begin(testKeyStr), std::end(testKeyStr) - 1, testKey.Get().begin());

	{
		HmacerBase hmacBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256), CtnFullR(testKey));

		hmacBase.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		auto hmac = hmacBase.Finish();
		auto hmacHex = Internal::Bytes2HexLitEnd(CtnFullR(hmac));

		EXPECT_EQ(hmacHex, "a68f6df80c440703b65d3d593ffe8a96e0a622c698a55414e8324a52d36cb00c");

		hmacBase = HmacerBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA512), CtnFullR(testKey));

		hmacBase.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		hmac = hmacBase.Finish();
		hmacHex = Internal::Bytes2HexLitEnd(CtnFullR(hmac));

		EXPECT_EQ(hmacHex, "2bf089af4f15fa001124097430f4afd7b532a5120e17f0927bbec061161f7f07df65e34dbc9b2b1774172e78b2da05b0b388a1d317bdb47409838ad9a4c5bb22");

		hmacBase = HmacerBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA384), CtnFullR(testKey));

		hmacBase.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		hmac = hmacBase.Finish();
		hmacHex = Internal::Bytes2HexLitEnd(CtnFullR(hmac));

		EXPECT_EQ(hmacHex, "9dcf85aea45e72d79d695992e17910e4508354dd5f35cf6f20fade6f0e2a8d99ac169b4a613ddb30681f3eb6eb884b4e");

		hmacBase = HmacerBase(*mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA224), CtnFullR(testKey));

		hmacBase.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		hmac = hmacBase.Finish();
		hmacHex = Internal::Bytes2HexLitEnd(CtnFullR(hmac));

		EXPECT_EQ(hmacHex, "ba703e5ddf696985179e2386d786d6eae027b6eb0bc0de314bcad31d");
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestHmac, HmacerClass)
{
	static constexpr char const testKeyStr[] = "TestKey1";
	SecretArray<uint8_t, 8> testKey;
	std::copy(std::begin(testKeyStr), std::end(testKeyStr) - 1, testKey.Get().begin());

	{
		Hmacer<HashType::SHA256> hmac2561(CtnFullR(testKey));
		hmac2561.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(1);

		Hmacer<HashType::SHA256> hmac2562(CtnFullR(testKey));
		hmac2562.Update(CtnItemRangeR<0, 12>("TestMessage2"));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(2);

		hmac2561 = std::move(hmac2561);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_COUNT(2);

		hmac2562 = std::move(hmac2561);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_COUNT(1);

		// Moved to initialize new one, allocation should remain the same.
		Hmacer<HashType::SHA256> hmac2563(std::move(hmac2562));

		// This should success.
		auto hmac = hmac2563.Finish();
		auto hmacHex = Internal::Bytes2HexLitEnd(CtnFullR(hmac));
		EXPECT_EQ(hmacHex, "a68f6df80c440703b65d3d593ffe8a96e0a622c698a55414e8324a52d36cb00c");

		//hmacBase1.NullCheck();
		EXPECT_THROW(hmac2561.NullCheck(), InvalidObjectException);
		EXPECT_THROW(hmac2562.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestHmac, HmacerCalc)
{
	static constexpr char const testKeyStr[] = "TestKey1";
	SecretArray<uint8_t, 8> testKey;
	std::copy(std::begin(testKeyStr), std::end(testKeyStr) - 1, testKey.Get().begin());

	{
		Hmacer<HashType::SHA256> hmacer256(CtnFullR(testKey));

		hmacer256.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		Hmac<HashType::SHA256> hash256 = hmacer256.Finish();
		auto hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash256));

		EXPECT_EQ(hashHex, "a68f6df80c440703b65d3d593ffe8a96e0a622c698a55414e8324a52d36cb00c");

		hmacer256.Restart(CtnFullR(testKey));
		hash256 = hmacer256.Calc(CtnItemRangeR<0, 12>("TestMessage2"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash256));

		EXPECT_EQ(hashHex, "185a94d7e04dcb54ac9d36758b8e1477ba8e8e144695808ca146c90748f75408");

		Hmacer<HashType::SHA512> hmacer512(CtnFullR(testKey));

		hmacer512.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		Hmac<HashType::SHA512> hash512 = hmacer512.Finish();
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash512));

		EXPECT_EQ(hashHex, "2bf089af4f15fa001124097430f4afd7b532a5120e17f0927bbec061161f7f07df65e34dbc9b2b1774172e78b2da05b0b388a1d317bdb47409838ad9a4c5bb22");

		hmacer512.Restart(CtnFullR(testKey));
		hash512 = hmacer512.Calc(CtnItemRangeR<0, 12>("TestMessage2"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash512));

		EXPECT_EQ(hashHex, "7a4aa0def7071b6610bd10abab78d6602f3d4710b5f32441d61ecea65dbf8ba0a3af9403a9e6da7f7680464a5b49af21be59b6082d3cf81425e444a72abf21a9");

		hash512 = Hmacer<HashType::SHA512>(CtnFullR(testKey)).Calc(
			                                    CtnItemRangeR<0, 12>("TestMessage3"),
												CtnItemRangeR<0, 12>("TestMessage4"),
												CtnItemRangeR<0, 12>("TestMessage5"),
												CtnItemRangeR<0, 12>("TestMessage6"),
												CtnItemRangeR<0, 12>("TestMessage7"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash512));

		EXPECT_EQ(hashHex, "7ebf504ab294b0bd67af6f950519609bea6299d32ecdae65718a9f8d030db140152b01ce297853c646f4ae857766aa835b4948db8888571213441dd1549ea865");

		Hmacer<HashType::SHA384> hmacer384(CtnFullR(testKey));

		hmacer384.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		Hmac<HashType::SHA384> hash384 = hmacer384.Finish();
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash384));

		EXPECT_EQ(hashHex, "9dcf85aea45e72d79d695992e17910e4508354dd5f35cf6f20fade6f0e2a8d99ac169b4a613ddb30681f3eb6eb884b4e");

		hmacer384.Restart(CtnFullR(testKey));
		hash384 = hmacer384.Calc(CtnItemRangeR<0, 12>("TestMessage2"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash384));

		EXPECT_EQ(hashHex, "670225995da117fd3f57faeb48ea81447ef93771c18589cc61914fec61e607a7cea56b337e4dbba33c57cf029eac093f");

		hash384 = Hmacer<HashType::SHA384>(CtnFullR(testKey)).Calc(
			                                    CtnItemRangeR<0, 12>("TestMessage3"),
												CtnItemRangeR<0, 12>("TestMessage4"),
												CtnItemRangeR<0, 12>("TestMessage5"),
												CtnItemRangeR<0, 12>("TestMessage6"),
												CtnItemRangeR<0, 12>("TestMessage7"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash384));

		EXPECT_EQ(hashHex, "cbd96c4212587e618e668a9d332470eb2ea5a7db4b40e309f53e972e2224cc2110cb4718e39b0c92b1e80f310d213686");

		Hmacer<HashType::SHA224> hmacer224(CtnFullR(testKey));

		hmacer224.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		Hmac<HashType::SHA224> hash224 = hmacer224.Finish();
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash224));

		EXPECT_EQ(hashHex, "ba703e5ddf696985179e2386d786d6eae027b6eb0bc0de314bcad31d");

		hmacer224.Restart(CtnFullR(testKey));
		hash224 = hmacer224.Calc(CtnItemRangeR<0, 12>("TestMessage2"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash224));

		EXPECT_EQ(hashHex, "af6358d8b4cd2626a4bfead05759e531ed88697263f2e827d661b92b");

		hash224 = Hmacer<HashType::SHA224>(CtnFullR(testKey)).Calc(
			                                    CtnItemRangeR<0, 12>("TestMessage3"),
												CtnItemRangeR<0, 12>("TestMessage4"),
												CtnItemRangeR<0, 12>("TestMessage5"),
												CtnItemRangeR<0, 12>("TestMessage6"),
												CtnItemRangeR<0, 12>("TestMessage7"));
		hashHex = Internal::Bytes2HexLitEnd(CtnFullR(hash224));

		EXPECT_EQ(hashHex, "c32df832563368163f8b854e7bcb045212bc92bbfbd4a13756b6f95e");
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}
