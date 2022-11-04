#include <gtest/gtest.h>

#include <mbedTLScpp/CipherBase.hpp>

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

GTEST_TEST(TestCipher, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestCipher, TestGetCipherInfo)
{
	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 128, CipherMode::ECB), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_ECB));
	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 192, CipherMode::ECB), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_ECB));
	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 256, CipherMode::ECB), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_ECB));

	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 128, CipherMode::CBC), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_CBC));
	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 192, CipherMode::CBC), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_CBC));
	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 256, CipherMode::CBC), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_CBC));

	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 128, CipherMode::CTR), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_CTR));
	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 192, CipherMode::CTR), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_CTR));
	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 256, CipherMode::CTR), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_CTR));

	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 128, CipherMode::GCM), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_GCM));
	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 192, CipherMode::GCM), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_192_GCM));
	EXPECT_EQ(&GetCipherInfo(CipherType::AES, 256, CipherMode::GCM), mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_256_GCM));

	EXPECT_THROW(GetCipherInfo(CipherType::AES, 512, CipherMode::ECB), InvalidArgumentException);
	EXPECT_THROW(GetCipherInfo(CipherType::AES, 512, CipherMode::CBC), InvalidArgumentException);
	EXPECT_THROW(GetCipherInfo(CipherType::AES, 512, CipherMode::CTR), InvalidArgumentException);
	EXPECT_THROW(GetCipherInfo(CipherType::AES, 512, CipherMode::GCM), InvalidArgumentException);
}

GTEST_TEST(TestCipher, CipherBaseClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		// An invalid initialization should fail.
		EXPECT_THROW({CipherBase<> cpBase(*mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_NONE));}, mbedTLSRuntimeError);

		// Failed initialization should delete the allocated memory.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		CipherBase<> cpBase1(GetCipherInfo(CipherType::AES, 256, CipherMode::GCM));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		CipherBase<> cpBase2(GetCipherInfo(CipherType::AES, 256, CipherMode::GCM));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		MBEDTLSCPPTEST_SELF_MOVE_TEST(cpBase1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		cpBase1 = std::move(cpBase2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		CipherBase<> cpBase3(std::move(cpBase1));

		// This should success.
		cpBase3.NullCheck();

		//cpBase1.NullCheck();
		EXPECT_THROW(cpBase1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(cpBase2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
