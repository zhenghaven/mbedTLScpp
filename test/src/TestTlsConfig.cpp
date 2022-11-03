// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <gtest/gtest.h>

#include <mbedTLScpp/TlsConfig.hpp>

#include <mbedTLScpp/DefaultRbg.hpp>
#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/TlsSessTktMgr.hpp>
#include <mbedTLScpp/X509Cert.hpp>

#include "MemoryTest.hpp"


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


GTEST_TEST(TestTlsConfig, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestTlsConfig, TlsConfigClass)
{
	using TestingTktMgtType =
		TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM, 86400>;

	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	std::shared_ptr<EcKeyPair<EcType::SECP256R1> > testPrvKey =
		std::make_shared<EcKeyPair<EcType::SECP256R1> >(
			EcKeyPair<EcType::SECP256R1>::Generate(*rand)
		);

	auto testCertDer = X509CertWriter::SelfSign(
		HashType::SHA256,
		*testPrvKey,
		"C=US,CN=Test CA"
	).SetBasicConstraints(
		true, -1
	).SetKeyUsage(
		MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
		MBEDTLS_X509_KU_NON_REPUDIATION   |
		MBEDTLS_X509_KU_KEY_CERT_SIGN     |
		MBEDTLS_X509_KU_CRL_SIGN
	).SetNsType(
		MBEDTLS_X509_NS_CERT_TYPE_SSL_CA |
		MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA |
		MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA
	).SetSerialNum(
		BigNumber<>(12345)
	).SetValidationTime(
		"20210101000000", "29991231235959"
	).GetDer(*rand);

	std::shared_ptr<X509Cert> testCert =
	std::make_shared<X509Cert>(
		X509Cert::FromDER(CtnFullR(testCertDer))
	);

	std::shared_ptr<TestingTktMgtType> testTktMgr =
		std::make_shared<TestingTktMgtType>(Internal::make_unique<DefaultRbg>());

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		TlsConfig tlsConf1(
			true, true, false,
			MBEDTLS_SSL_PRESET_SUITEB,
			testCert,
			nullptr,
			testCert,
			testPrvKey,
			Internal::make_unique<DefaultRbg>(),
			testTktMgr
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2 + (gsk_threadEnabled ? 1 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		TlsConfig tlsConf2(
			true, false, true,
			MBEDTLS_SSL_PRESET_SUITEB,
			testCert,
			nullptr,
			testCert,
			testPrvKey,
			Internal::make_unique<DefaultRbg>(),
			testTktMgr
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4 + (gsk_threadEnabled ? 2 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tlsConf1 = std::move(tlsConf1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4 + (gsk_threadEnabled ? 2 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tlsConf1 = std::move(tlsConf2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2 + (gsk_threadEnabled ? 1 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		TlsConfig tlsConf3(std::move(tlsConf1));

		// This should success.
		tlsConf3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(tlsConf1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(tlsConf2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
