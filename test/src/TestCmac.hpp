#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/Cmac.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestCipher, CmacerBaseClass)
{
	SecretArray<uint8_t, 32> testKey;

	{
		// An invalid initialization should fail.
		EXPECT_THROW({CmacerBase cmacBase(*mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_NONE), SCtnFullR(testKey));}, mbedTLSRuntimeError);

		// Failed initialization should delete the allocated memory.
		MEMORY_LEAK_TEST_COUNT(0);

		CmacerBase cmacBase1(GetCipherInfo(CipherType::AES, 256, CipherMode::ECB), SCtnFullR(testKey));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(1);

		CmacerBase cmacBase2(GetCipherInfo(CipherType::AES, 256, CipherMode::ECB), SCtnFullR(testKey));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(2);

		cmacBase1 = std::move(cmacBase1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_COUNT(2);

		cmacBase1 = std::move(cmacBase2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_COUNT(1);

		// Moved to initialize new one, allocation should remain the same.
		CmacerBase cmacBase3(std::move(cmacBase1));

		// This should success.
		cmacBase3.NullCheck();

		//cmacBase1.NullCheck();
		EXPECT_THROW(cmacBase1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(cmacBase2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestCmac, CmacerBaseCalc)
{
	static constexpr char const testKey128Str[] = "TestKey1\0\0\0\0\0\0\0";
	//546573744B6579310000000000000000
	SecretArray<uint8_t, sizeof(testKey128Str)> test128Key;
	std::copy(std::begin(testKey128Str), std::end(testKey128Str), test128Key.Get().begin());

	static constexpr char const testKey192Str[] = "TestKey1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	//546573744B65793100000000000000000000000000000000
	SecretArray<uint8_t, sizeof(testKey192Str)> test192Key;
	std::copy(std::begin(testKey192Str), std::end(testKey192Str), test192Key.Get().begin());

	static constexpr char const testKey256Str[] = "TestKey1\0\0\0\0\0\0\0\0TestKey1\0\0\0\0\0\0\0";
	//546573744B6579310000000000000000546573744B6579310000000000000000
	SecretArray<uint8_t, sizeof(testKey256Str)> test256Key;
	std::copy(std::begin(testKey256Str), std::end(testKey256Str), test256Key.Get().begin());

	{
		CmacerBase cmacBase(GetCipherInfo(CipherType::AES, 128, CipherMode::ECB), SCtnFullR(test128Key));

		cmacBase.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		auto cmac = cmacBase.Finish();
		auto cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));

		EXPECT_EQ(cmacHex, "d5102239eab3db7190b7c3e79ccba537");
		cmacBase.Restart();

		cmacBase.Update(CtnItemRangeR<0, 12>("TestMessage2"));

		cmac = cmacBase.Finish();
		cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));

		EXPECT_EQ(cmacHex, "b337e6976b75a2458d86dd7abb737f9f");

		cmacBase = CmacerBase(GetCipherInfo(CipherType::AES, 192, CipherMode::ECB), SCtnFullR(test192Key));

		cmacBase.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		cmac = cmacBase.Finish();
		cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));

		EXPECT_EQ(cmacHex, "1ec7434c627af04468d7808c7e3240e3");
		cmacBase.Restart();

		cmacBase.Update(CtnItemRangeR<0, 12>("TestMessage2"));

		cmac = cmacBase.Finish();
		cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));

		EXPECT_EQ(cmacHex, "b76362c4d9f26fde563ce35dae1d2628");

		cmacBase = CmacerBase(GetCipherInfo(CipherType::AES, 256, CipherMode::ECB), SCtnFullR(test256Key));

		cmacBase.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		cmac = cmacBase.Finish();
		cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));

		EXPECT_EQ(cmacHex, "90514dec0f6ddca0135f513dc4548c41");
		cmacBase.Restart();

		cmacBase.Update(CtnItemRangeR<0, 12>("TestMessage2"));

		cmac = cmacBase.Finish();
		cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));

		EXPECT_EQ(cmacHex, "dcc4da0241a62d8d173669a2754d7fea");

	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestHmac, CmacerClass)
{
	static constexpr char const testKey128Str[] = "TestKey1\0\0\0\0\0\0\0";
	//546573744B6579310000000000000000
	SecretArray<uint8_t, sizeof(testKey128Str)> test128Key;
	std::copy(std::begin(testKey128Str), std::end(testKey128Str), test128Key.Get().begin());

	{
		Cmacer<CipherType::AES, 128, CipherMode::ECB> cmac1281(SCtnFullR(test128Key));
		cmac1281.Update(CtnItemRangeR<0, 12>("TestMessage2"));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(1);

		Cmacer<CipherType::AES, 128, CipherMode::ECB> cmac1282(SCtnFullR(test128Key));
		cmac1282.Update(CtnItemRangeR<0, 12>("TestMessage1"));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(2);

		cmac1281 = std::move(cmac1281);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_COUNT(2);

		cmac1281 = std::move(cmac1282);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_COUNT(1);

		// Moved to initialize new one, allocation should remain the same.
		Cmacer<CipherType::AES, 128, CipherMode::ECB> cmac1283(std::move(cmac1281));

		// This should success.
		auto cmac = cmac1283.Finish();
		auto cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));
		EXPECT_EQ(cmacHex, "d5102239eab3db7190b7c3e79ccba537");

		//cmacBase1.NullCheck();
		EXPECT_THROW(cmac1281.NullCheck(), InvalidObjectException);
		EXPECT_THROW(cmac1282.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestCmac, CmacerCalc)
{
	static constexpr char const testKey128Str[] = "TestKey1\0\0\0\0\0\0\0";
	//546573744B6579310000000000000000
	SecretArray<uint8_t, sizeof(testKey128Str)> test128Key;
	std::copy(std::begin(testKey128Str), std::end(testKey128Str), test128Key.Get().begin());

	static constexpr char const testKey192Str[] = "TestKey1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	//546573744B65793100000000000000000000000000000000
	SecretArray<uint8_t, sizeof(testKey192Str)> test192Key;
	std::copy(std::begin(testKey192Str), std::end(testKey192Str), test192Key.Get().begin());

	static constexpr char const testKey256Str[] = "TestKey1\0\0\0\0\0\0\0\0TestKey1\0\0\0\0\0\0\0";
	//546573744B6579310000000000000000546573744B6579310000000000000000
	SecretArray<uint8_t, sizeof(testKey256Str)> test256Key;
	std::copy(std::begin(testKey256Str), std::end(testKey256Str), test256Key.Get().begin());

	{
		Cmacer<CipherType::AES, 128, CipherMode::ECB> cmac128(SCtnFullR(test128Key));

		auto cmac = cmac128.Calc(CtnItemRangeR<0, 12>("TestMessage1"),
								CtnItemRangeR<0, 12>("TestMessage2"),
								CtnItemRangeR<0, 12>("TestMessage3"));
		auto cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));

		EXPECT_EQ(cmacHex, "91f63489d8fe8b6182f3f77579d4e4e8");


		Cmacer<CipherType::AES, 192, CipherMode::ECB> cmac192(SCtnFullR(test192Key));

		cmac = cmac192.Calc(CtnItemRangeR<0, 12>("TestMessage1"),
							CtnItemRangeR<0, 12>("TestMessage2"),
							CtnItemRangeR<0, 12>("TestMessage3"));
		cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));

		EXPECT_EQ(cmacHex, "a824c002cc220dc2ee1e247048f0513d");


		Cmacer<CipherType::AES, 256, CipherMode::ECB> cmac256(SCtnFullR(test256Key));

		cmac = cmac256.Calc(CtnItemRangeR<0, 12>("TestMessage1"),
							CtnItemRangeR<0, 12>("TestMessage2"),
							CtnItemRangeR<0, 12>("TestMessage3"));
		cmacHex = Internal::Bytes2HexLitEnd(CtnFullR(cmac));

		EXPECT_EQ(cmacHex, "98ec5ae33826ee3d13fb3608206e50cc");

	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}
