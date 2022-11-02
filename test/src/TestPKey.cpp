// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#include <gtest/gtest.h>

#include <mbedTLScpp/DefaultRbg.hpp>
#include <mbedTLScpp/PKey.hpp>

#include "SharedVars.hpp"
#include "MemoryTest.hpp"

#include "SharedVars.hpp"


namespace mbedTLScpp_Test
{
	extern size_t g_numOfTestFile;
}

#ifdef MBEDTLS_THREADING_C
	static constexpr bool gsk_threadEnabled = true;
#else
	static constexpr bool gsk_threadEnabled = false;
#endif


#ifdef MBEDTLSCPPTEST_TEST_STD_NS
using namespace std;
#endif

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

using namespace mbedTLScpp_Test;


GTEST_TEST(TestPKey, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestPKey, PKeyBaseConstructAndMove)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		// Default
		PKeyBase<> pkey;
		EXPECT_NE(pkey.Get(), nullptr);

		mbedtls_pk_context* pkeyPtr = pkey.Get();

		// Move
		PKeyBase<> pkey2(std::move(pkey));
		EXPECT_EQ(pkey.Get(), nullptr);
		EXPECT_EQ(pkey2.Get(), pkeyPtr);

		// Move assignment
		PKeyBase<> pkey3;
		EXPECT_NE(pkey3.Get(), nullptr);
		EXPECT_NE(pkey3.Get(), pkeyPtr);

		pkey3 = std::move(pkey2);
		EXPECT_EQ(pkey2.Get(), nullptr);
		EXPECT_EQ(pkey3.Get(), pkeyPtr);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestPKey, PemParseAndKeyTypes)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// RSA Private Key
	{
		PKeyBase<> pkey = PKeyBase<>::FromPEM(
			SecretString(
				GetTestRsaPrivKeyPem().data(), GetTestRsaPrivKeyPem().size()
			),
			*rand
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1 + (gsk_threadEnabled ? 1 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(pkey.GetAlgorithmCat(), PKeyAlgmCat::RSA);
		EXPECT_EQ(pkey.GetKeyType(),      PKeyType::Private);
		EXPECT_TRUE(pkey.HasPubKey());

		// Private PEM
		EXPECT_NO_THROW(
			auto pem = pkey.GetPrivatePem();
			std::string oriPem(GetTestRsaPrivKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);

		// Public PEM
		EXPECT_NO_THROW(
			auto pem = pkey.GetPublicPem();
			EXPECT_GT(pem.size(), 0);
		);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// RSA Public Key
	{
		PKeyBase<> pkey = PKeyBase<>::FromPEM(
			std::string(
				GetTestRsaPubKeyPem().data(), GetTestRsaPubKeyPem().size()
			)
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1 + (gsk_threadEnabled ? 1 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(pkey.GetAlgorithmCat(), PKeyAlgmCat::RSA);
		EXPECT_EQ(pkey.GetKeyType(),      PKeyType::Public);
		EXPECT_TRUE(pkey.HasPubKey());

		// Private PEM
		EXPECT_THROW(
			auto pem = pkey.GetPrivatePem();,
			mbedTLSRuntimeError
		);

		// Public PEM
		EXPECT_NO_THROW(
			auto pem = pkey.GetPublicPem();
			std::string oriPem(GetTestRsaPubKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// EC Private Key
	{
		PKeyBase<> pkey = PKeyBase<>::FromPEM(
			SecretString(
				GetTestEcPrivKeyPem().data(), GetTestEcPrivKeyPem().size()
			),
			*rand
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(pkey.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(pkey.GetKeyType(),      PKeyType::Private);
		EXPECT_TRUE(pkey.HasPubKey());

		// Private PEM
		EXPECT_NO_THROW(
			auto pem = pkey.GetPrivatePem();
			std::string oriPem(GetTestEcPrivKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);

		// Public PEM
		EXPECT_NO_THROW(
			auto pem = pkey.GetPublicPem();
			EXPECT_GT(pem.size(), 0);
		);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// EC Public Key
	{
		PKeyBase<> pkey = PKeyBase<>::FromPEM(
			std::string(
				GetTestEcPubKeyPem().data(), GetTestEcPubKeyPem().size()
			)
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(pkey.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(pkey.GetKeyType(),      PKeyType::Public);
		EXPECT_TRUE(pkey.HasPubKey());

		// // Private PEM
		// EXPECT_THROW(
		// 	auto pem = pkey.GetPrivatePem();,
		// 	mbedTLSRuntimeError
		// );

		// Public PEM
		EXPECT_NO_THROW(
			auto pem = pkey.GetPublicPem();
			std::string oriPem(GetTestEcPubKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestPKey, DerParseAndKeyTypes)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// RSA Private Key
	{
		PKeyBase<> pkey1 = PKeyBase<>::FromPEM(
			SecretString(
				GetTestRsaPrivKeyPem().data(), GetTestRsaPrivKeyPem().size()
			),
			*rand
		);

		auto der = pkey1.GetPrivateDer();

		PKeyBase<> pkey2 = PKeyBase<>::FromDER(
			CtnFullR(der),
			*rand
		);

		EXPECT_EQ(pkey2.GetAlgorithmCat(), PKeyAlgmCat::RSA);
		EXPECT_EQ(pkey2.GetKeyType(),      PKeyType::Private);
		EXPECT_TRUE(pkey2.HasPubKey());
	}

	// EC Public Key
	{
		PKeyBase<> pkey1 = PKeyBase<>::FromPEM(
			std::string(
				GetTestEcPubKeyPem().data(), GetTestEcPubKeyPem().size()
			)
		);

		auto der = pkey1.GetPublicDer();

		PKeyBase<> pkey2 = PKeyBase<>::FromDER(
			CtnFullR(der)
		);

		EXPECT_EQ(pkey2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(pkey2.GetKeyType(),      PKeyType::Public);
		EXPECT_TRUE(pkey2.HasPubKey());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestPKey, SignAndVerifySign)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;

	Hash<HashType::SHA256> testHash1 =
		Hasher<HashType::SHA256>().Calc(CtnFullR("TestString"));
	Hash<HashType::SHA256> testHash2 =
		Hasher<HashType::SHA256>().Calc(CtnFullR("XTestStringX"));

	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);


	// RSA Private Key
	{
		PKeyBase<> pkey = PKeyBase<>::FromPEM(
			SecretString(
				GetTestRsaPrivKeyPem().data(), GetTestRsaPrivKeyPem().size()
			),
			*rand
		);

		auto sign = pkey.SignInDer<HashType::SHA256>(testHash1, *rand);

		EXPECT_NO_THROW(
			pkey.VerifyDerSign(testHash1, CtnFullR(sign));
		);
		EXPECT_THROW(
			pkey.VerifyDerSign(testHash2, CtnFullR(sign));,
			mbedTLSRuntimeError
		);
	}

	// EC Private Key
	{
		PKeyBase<> pkey = PKeyBase<>::FromPEM(
			SecretString(
				GetTestEcPrivKeyPem().data(), GetTestEcPrivKeyPem().size()
			),
			*rand
		);

		auto sign = pkey.SignInDer<HashType::SHA256>(testHash1, *rand);

		EXPECT_NO_THROW(
			pkey.VerifyDerSign(testHash1, CtnFullR(sign));
		);
		EXPECT_THROW(
			pkey.VerifyDerSign(testHash2, CtnFullR(sign));,
			mbedTLSRuntimeError
		);
	}


	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
