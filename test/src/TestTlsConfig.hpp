#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/TlsConfig.hpp>

#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/X509Cert.hpp>
#include <mbedTLScpp/TlsSessTktMgr.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestTlsConfig, TlsConfigClass)
{
	std::shared_ptr<EcKeyPair<EcType::SECP256R1> > testPrvKey =
	std::make_shared<EcKeyPair<EcType::SECP256R1> >(EcKeyPair<EcType::SECP256R1>::Generate());

	std::shared_ptr<X509Cert> testCert =
	std::make_shared<X509Cert>(
		X509Cert::FromDER(CtnFullR(
			X509CertWriter::SelfSign(HashType::SHA256, *testPrvKey, "C=US,CN=Test CA").
				SetBasicConstraints(true, -1).
				SetKeyUsage(MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
					MBEDTLS_X509_KU_NON_REPUDIATION   |
					MBEDTLS_X509_KU_KEY_CERT_SIGN     |
					MBEDTLS_X509_KU_CRL_SIGN).
				SetNsType(MBEDTLS_X509_NS_CERT_TYPE_SSL_CA |
					MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA |
					MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA).
				SetSerialNum(BigNumber<>(12345)).
				SetValidationTime("20210101000000", "20211231235959").GetDer()
		))
	);

	std::shared_ptr<TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM> > testTktMgr =
		std::make_shared<TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM> >();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		TlsConfig tlsConf1(true, true, true, false,
			MBEDTLS_SSL_PRESET_SUITEB, testCert, nullptr, testCert, testPrvKey, testTktMgr);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		TlsConfig tlsConf2(true, false, true, true,
			MBEDTLS_SSL_PRESET_SUITEB, testCert, nullptr, testCert, testPrvKey, testTktMgr);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tlsConf1 = std::move(tlsConf1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tlsConf1 = std::move(tlsConf2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
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
