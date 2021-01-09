#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/X509Cert.hpp>

#include "SharedVars.hpp"
#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestX509CertWrt, X509CertWrtClass)
{
	EcKeyPair<EcType::SECP256R1> testKey = EcKeyPair<EcType::SECP256R1>::Generate();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509CertWriter writer1 = X509CertWriter::SelfSign(HashType::SHA256, testKey, "C=UK,O=ARM,CN=mbed TLS Server 1");

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		X509CertWriter writer2 = X509CertWriter::SelfSign(HashType::SHA256, testKey, "C=UK,O=ARM,CN=mbed TLS Server 2");

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		writer1 = std::move(writer1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		writer1 = std::move(writer2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		X509CertWriter writer3(std::move(writer1));

		// This should success.
		writer3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(writer1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(writer2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestX509Cert, X509CertClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Cert cert1 = X509Cert::FromPEM(gsk_testX509CertPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		X509Cert cert2 =  X509Cert::FromDER(CtnFullR(cert1.GetDer()));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		cert1 = std::move(cert1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		cert1 = std::move(cert2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		X509Cert cert3(std::move(cert1));

		// This should success.
		cert3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(cert1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(cert2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestX509CertWrt, X509CertWrtSign)
{
	EcKeyPair<EcType::SECP256R1> testCaKey  = EcKeyPair<EcType::SECP256R1>::Generate();
	EcKeyPair<EcType::SECP256R1> testSubKey = EcKeyPair<EcType::SECP256R1>::Generate();

	std::string largeExtData = std::string(gsk_testRsaPubKeyPem) + std::string(gsk_testRsaPubKeyPem);
	largeExtData += largeExtData + largeExtData;
	largeExtData += largeExtData + largeExtData;

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	std::string          caPem;
	std::vector<uint8_t> caDer;
	{
		X509CertWriter writerCa = X509CertWriter::SelfSign(HashType::SHA256, testCaKey, "C=UK,O=ARM,CN=mbed TLS Server 1");
		writerCa.SetBasicConstraints(true, -1);
		writerCa.SetKeyUsage(
			MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
			MBEDTLS_X509_KU_NON_REPUDIATION   |
			MBEDTLS_X509_KU_KEY_CERT_SIGN     |
			MBEDTLS_X509_KU_CRL_SIGN);
		writerCa.SetNsType(
			MBEDTLS_X509_NS_CERT_TYPE_SSL_CA |
			MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA |
			MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA);
		writerCa.SetSerialNum(
			BigNumber<>(12345)
		);
		writerCa.SetV3Extensions({
			std::make_pair("1.2.3.4.5.6.7.1", std::make_pair(false, "TestData1")),
			std::make_pair("1.2.3.4.5.6.7.2", std::make_pair(false, "TestData2")),
			std::make_pair("1.2.3.4.5.6.7.3", std::make_pair(false, largeExtData)),
		});
		writerCa.SetValidationTime("20210101000000", "20211231235959");

		caPem = writerCa.GetPem();
		caDer = writerCa.GetDer();
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	std::string          subPem;
	std::vector<uint8_t> subDer;
	{
		X509Cert certCa = X509Cert::FromDER(CtnFullR(caDer));
		X509CertWriter writerSub = X509CertWriter::CaSign(HashType::SHA256, certCa, testCaKey, testSubKey, "C=UK,O=ARM,CN=mbed TLS Client 1");
		writerSub.SetBasicConstraints(false, -1);
		writerSub.SetKeyUsage(
			MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
			MBEDTLS_X509_KU_NON_REPUDIATION   |
			MBEDTLS_X509_KU_KEY_ENCIPHERMENT  |
			MBEDTLS_X509_KU_DATA_ENCIPHERMENT |
			MBEDTLS_X509_KU_KEY_AGREEMENT);
		writerSub.SetNsType(
			MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT |
			MBEDTLS_X509_NS_CERT_TYPE_EMAIL      |
			MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING);
		writerSub.SetSerialNum(
			BigNumber<>(12345)
		);
		writerSub.SetV3Extensions({
			std::make_pair("1.2.3.4.5.6.7.1", std::make_pair(false, "TestData1")),
			std::make_pair("1.2.3.4.5.6.7.2", std::make_pair(false, "TestData2")),
		});
		writerSub.SetValidationTime("20210101000000", "20211231235959");

		subPem = writerSub.GetPem();
		subDer = writerSub.GetDer();

		EXPECT_NO_THROW(X509Cert testCert = X509Cert::FromPEM(subPem););
		EXPECT_NO_THROW(X509Cert testCert = X509Cert::FromDER(CtnFullR(subDer)););
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// Verify signatures
	{
		X509Cert certCa  = X509Cert::FromDER(CtnFullR(caDer));
		X509Cert certSub = X509Cert::FromDER(CtnFullR(subDer));

		EXPECT_NO_THROW(certCa.VerifySignature(););
		EXPECT_NO_THROW(certCa.VerifySignature(certCa.BorrowPublicKey()););
		EXPECT_NO_THROW(certCa.VerifySignature(certCa.GetPublicKey<EcPublicKey<EcType::SECP256R1> >()););
		EXPECT_NO_THROW(certCa.VerifySignature(testCaKey););
		EXPECT_THROW(certCa.VerifySignature(testSubKey);, mbedTLSRuntimeError);

		EXPECT_NO_THROW(certSub.VerifySignature(certCa.BorrowPublicKey()););
		EXPECT_NO_THROW(certSub.VerifySignature(certCa.GetPublicKey<EcPublicKey<EcType::SECP256R1> >()););
		EXPECT_NO_THROW(certSub.VerifySignature(testCaKey););
		EXPECT_THROW(certSub.VerifySignature(testSubKey);, mbedTLSRuntimeError);

		uint32_t flag = 0;
		EXPECT_NO_THROW(certSub.VerifyChainWithCa(certCa, nullptr, "mbed TLS Client 1", flag, mbedtls_x509_crt_profile_default, [](void *, mbedtls_x509_crt *, int, uint32_t *){return 0;}, nullptr););
		EXPECT_EQ(flag, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// Cert chains
	{
		X509Cert certCa  = X509Cert::FromPEM(caPem);
		X509Cert certSub = X509Cert::FromPEM(caPem + "\n" + subPem);

		EXPECT_FALSE(certCa.HasNext());
		EXPECT_TRUE (certSub.HasNext());

		auto ptr = certCa.Get();
		EXPECT_THROW(certCa.PrevCert();, RuntimeException);
		EXPECT_EQ(ptr, certCa.Get());
		EXPECT_EQ(ptr, certCa.GetCurr());
		EXPECT_THROW(certCa.NextCert();, RuntimeException);
		EXPECT_EQ(ptr, certCa.Get());
		EXPECT_EQ(ptr, certCa.GetCurr());
		EXPECT_NO_THROW(certCa.GoToFirstCert(););
		EXPECT_EQ(ptr, certCa.Get());
		EXPECT_EQ(ptr, certCa.GetCurr());
		EXPECT_NO_THROW(certCa.GoToLastCert(););
		EXPECT_EQ(ptr, certCa.Get());
		EXPECT_EQ(ptr, certCa.GetCurr());

		ptr = certSub.Get();
		EXPECT_NO_THROW(certSub.NextCert(););
		EXPECT_EQ(ptr, certSub.Get());
		EXPECT_EQ(ptr->next, certSub.GetCurr());
		EXPECT_NO_THROW(certSub.PrevCert(););
		EXPECT_EQ(ptr, certSub.Get());
		EXPECT_EQ(ptr, certSub.GetCurr());
		EXPECT_NO_THROW(certSub.GoToLastCert(););
		EXPECT_EQ(ptr, certSub.Get());
		EXPECT_EQ(ptr->next, certSub.GetCurr());
		EXPECT_NO_THROW(certSub.GoToFirstCert(););
		EXPECT_EQ(ptr, certSub.Get());
		EXPECT_EQ(ptr, certSub.GetCurr());

		certSub = X509Cert::FromPEM(caPem + "\n" + subPem + "\n" + caPem);
		ptr = certSub.Get()->next;
		EXPECT_NO_THROW(certSub.ShrinkChain(certCa););
		EXPECT_EQ(ptr, certSub.Get());
		EXPECT_EQ(ptr, certSub.GetCurr());
		EXPECT_EQ(certSub.Get()->next, nullptr);
		EXPECT_FALSE(certSub.HasNext());

		certSub = X509Cert::FromPEM(caPem + "\n" + subPem + "\n" + caPem);
		certSub = X509Cert::FromPEM(certSub.GetPemChain());
		EXPECT_NE(certSub.Get()->next, nullptr);
		EXPECT_NE(certSub.Get()->next->next, nullptr);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestX509Cert, X509CertGetters)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Cert cert = X509Cert::FromPEM(gsk_testX509CertPem);

		EXPECT_EQ(cert.GetCommonName(), "mbed TLS Server 1");

		EXPECT_EQ(cert.GetHashType(), HashType::SHA256);

		EXPECT_EQ(cert.GetV3Extension("1.2.3.4.5.6.7.1").second, "TestData1");
		EXPECT_EQ(cert.GetV3Extension("1.2.3.4.5.6.7.2").second, "TestData2");

		auto exts = cert.GetV3Extensions();
		EXPECT_EQ(exts["1.2.3.4.5.6.7.1"].second, "TestData1");
		EXPECT_EQ(exts["1.2.3.4.5.6.7.2"].second, "TestData2");
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
