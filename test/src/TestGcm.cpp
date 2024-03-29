#include <gtest/gtest.h>

#include <mbedTLScpp/SKey.hpp>
#include <mbedTLScpp/Gcm.hpp>

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

GTEST_TEST(TestGcmBase, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestGcmBase, GcmBaseClass)
{
	SKey<128> skey({
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	});

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		GcmBase<> gcm1(CtnFullR(skey), CipherType::AES);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		GcmBase<> gcm2(CtnFullR(skey), CipherType::AES);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		MBEDTLSCPPTEST_SELF_MOVE_TEST(gcm1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		gcm1 = std::move(gcm2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		GcmBase<> gcm3(std::move(gcm1));

		// This should success.
		gcm3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(gcm1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(gcm2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestGcmBase, GcmBaseCryption)
{
	SKey<128> skey({
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	});

	std::array<uint8_t, 12> iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	std::string add = "### Additional Data ###";
	std::string data = "PLAIN DATA.";

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		// Encrypt
		GcmBase<> gcm(CtnFullR(skey), CipherType::AES);

		std::vector<uint8_t> cipher;
		std::array<uint8_t, 16> tag;

		std::tie(cipher, tag) = gcm.Encrypt(
			CtnFullR(data),
			CtnFullR(iv),
			CtnFullR(add)
		);

		EXPECT_EQ(data.size(), cipher.size());
		std::string cipherStr(data.size(), '\0');
		memcpy(&cipherStr[0], cipher.data(), cipher.size());
		EXPECT_NE(data, cipherStr);

		SecretVector<uint8_t> plain;
		plain = gcm.Decrypt(
			CtnFullR(cipher),
			CtnFullR(iv),
			CtnFullR(add),
			CtnFullR(tag)
		);

		EXPECT_EQ(data.size(), plain.size());
		std::string plainStr(data.size(), '\0');
		memcpy(&plainStr[0], plain.data(), plain.size());
		EXPECT_EQ(data, plainStr);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestGcm, GcmClass)
{
	SKey<256> skey({
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	});

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		Gcm<CipherType::AES, 128> gcm1(CtnItemRgR<0, 16>(skey));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		Gcm<CipherType::AES, 128> gcm2(CtnItemRgR<0, 16>(skey));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		MBEDTLSCPPTEST_SELF_MOVE_TEST(gcm1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		gcm1 = std::move(gcm2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		GcmBase<> gcm3(std::move(gcm1));

		// This should success.
		gcm3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(gcm1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(gcm2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestGcm, GcmCryption)
{
	SKey<256> skey({
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7,
	});

	std::array<uint8_t, 12> iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	std::string add = "### Additional Data ###";
	std::string data = "PLAIN DATA.";

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	std::vector<uint8_t> cipher;
	std::array<uint8_t, 16> tag;

	// 128 Encrypt
	{
		Gcm<CipherType::AES, 128> gcm(CtnItemRgR<0, 16>(skey));

		std::tie(cipher, tag) = gcm.Encrypt(
			CtnFullR(data),
			CtnFullR(iv),
			CtnFullR(add)
		);

		EXPECT_EQ(data.size(), cipher.size());
		std::string cipherStr(data.size(), '\0');
		memcpy(&cipherStr[0], cipher.data(), cipher.size());
		EXPECT_NE(data, cipherStr);
	}

	// 128 Decrypt
	{
		Gcm<CipherType::AES, 128> gcm(CtnItemRgR<0, 16>(skey));

		auto plain = gcm.Decrypt(
			CtnFullR(cipher),
			CtnFullR(iv),
			CtnFullR(add),
			CtnFullR(tag)
		);

		EXPECT_EQ(data.size(), plain.size());
		std::string plainStr(data.size(), '\0');
		memcpy(&plainStr[0], plain.data(), plain.size());
		EXPECT_EQ(data, plainStr);
	}

	// 192 Encrypt
	{
		Gcm<CipherType::AES, 192> gcm(CtnItemRgR<0, 24>(skey));

		std::tie(cipher, tag) = gcm.Encrypt(
			CtnFullR(data),
			CtnFullR(iv),
			CtnFullR(add)
		);

		EXPECT_EQ(data.size(), cipher.size());
		std::string cipherStr(data.size(), '\0');
		memcpy(&cipherStr[0], cipher.data(), cipher.size());
		EXPECT_NE(data, cipherStr);
	}

	// 192 Decrypt
	{
		Gcm<CipherType::AES, 192> gcm(CtnItemRgR<0, 24>(skey));

		auto plain = gcm.Decrypt(
			CtnFullR(cipher),
			CtnFullR(iv),
			CtnFullR(add),
			CtnFullR(tag)
		);

		EXPECT_EQ(data.size(), plain.size());
		std::string plainStr(data.size(), '\0');
		memcpy(&plainStr[0], plain.data(), plain.size());
		EXPECT_EQ(data, plainStr);
	}

	// 256 Encrypt
	{
		Gcm<CipherType::AES, 256> gcm(CtnItemRgR<0, 32>(skey));

		std::tie(cipher, tag) = gcm.Encrypt(
			CtnFullR(data),
			CtnFullR(iv),
			CtnFullR(add)
		);

		EXPECT_EQ(data.size(), cipher.size());
		std::string cipherStr(data.size(), '\0');
		memcpy(&cipherStr[0], cipher.data(), cipher.size());
		EXPECT_NE(data, cipherStr);
	}

	// 256 Decrypt
	{
		Gcm<CipherType::AES, 256> gcm(CtnItemRgR<0, 32>(skey));

		auto plain = gcm.Decrypt(
			CtnFullR(cipher),
			CtnFullR(iv),
			CtnFullR(add),
			CtnFullR(tag)
		);

		EXPECT_EQ(data.size(), plain.size());
		std::string plainStr(data.size(), '\0');
		memcpy(&plainStr[0], plain.data(), plain.size());
		EXPECT_EQ(data, plainStr);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
