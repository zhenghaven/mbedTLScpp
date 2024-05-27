// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <gtest/gtest.h>

#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/DefaultRbg.hpp>
#include <mbedTLScpp/X509Cert.hpp>

#include "SharedVars.hpp"
#include "MemoryTest.hpp"
#include "SelfMoveTest.hpp"


namespace mbedTLScpp_Test
{
	extern size_t g_numOfTestFile;
}


#ifdef MBEDTLSCPPTEST_TEST_STD_NS
using namespace std;
#endif

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

using namespace mbedTLScpp_Test;


class TestX509CertExt :
	public mbedTLScpp::X509Cert
{
public: // static members:

	using Base = mbedTLScpp::X509Cert;

	static TestX509CertExt Empty()
	{
		return TestX509CertExt();
	}

public:

	TestX509CertExt() :
		Base()
	{}

	virtual int mbedTLSParseExt(
		mbedtls_x509_crt const* crt,
		mbedtls_x509_buf const* oid,
		int critical,
		const unsigned char* p,
		const unsigned char* end
	) override
	{
		static const std::string sk_expOid = "1.2.3.4.5.6.7.1";
		if (
			oid->len == sk_expOid.size() &&
			std::memcmp(oid->p, sk_expOid.data(), sk_expOid.size()) == 0
		)
		{
			size_t dataLen = static_cast<size_t>(end - p);
			m_extData.resize(dataLen);
			std::memcpy(&(m_extData[0]), p, dataLen);
			return 0;
		}
		return Base::mbedTLSParseExt(crt, oid, critical, p, end);
	}

	std::string m_extData;

}; // class TestX509CertExt


GTEST_TEST(TestX509CertWrt, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestX509CertWrt, X509CertWrtConstructionAndMove)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	auto testKey = EcKeyPair<EcType::SECP256R1>::Generate(*rand);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509CertWriter writer1 =
			X509CertWriter::SelfSign(
				HashType::SHA256,
				testKey,
				"C=UK,O=ARM,CN=mbed TLS Server 1"
			);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		X509CertWriter writer2 =
			X509CertWriter::SelfSign(
				HashType::SHA256,
				testKey,
				"C=UK,O=ARM,CN=mbed TLS Server 2"
			);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		MBEDTLSCPPTEST_SELF_MOVE_TEST(writer1);

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


GTEST_TEST(TestX509CertWrt, X509CertWrtSettersAndPEM)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	auto testKey = EcKeyPair<EcType::SECP256R1>::Generate(*rand);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509CertWriter writer1 =
			X509CertWriter::SelfSign(
				HashType::SHA256,
				testKey,
				"C=UK,O=ARM,CN=mbed TLS Server 1"
			);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		std::string testExtData = "TestData1";

		EXPECT_NO_THROW(
			writer1.SetSerialNum(
				BigNum::Rand(32, *rand)
			).SetValidationTime(
				"20210101000000", "29991231235959"
			).SetBasicConstraints(
				true, 0
			).SetKeyUsage(
				MBEDTLS_X509_KU_DIGITAL_SIGNATURE
			).SetNsType(
				MBEDTLS_X509_NS_CERT_TYPE_SSL_CA
			).SetV3Extension(
				"1.2.3.4.5.6.7.1", false, CtnFullR(testExtData)
			);
		);

		std::string pem;
		ASSERT_NO_THROW(
			pem = writer1.GetPem(*rand);
		);

		std::vector<uint8_t> der;
		ASSERT_NO_THROW(
			der = writer1.GetDer(*rand);
		);

		// try to parse
		{
			EXPECT_NO_THROW(
				X509Cert::FromPEM(pem);
			);
		}
		{
			EXPECT_NO_THROW(
				X509Cert::FromDER(CtnFullR(der));
			);
		}
		{
			TestX509CertExt cert = TestX509CertExt::Empty();
			EXPECT_NO_THROW(
				cert.AppendDER(CtnFullR(der));
			);
			EXPECT_EQ(cert.m_extData, testExtData);
		}
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestX509Cert, X509CertConstructionAndMove)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Cert cert1 = X509Cert::FromPEM(
			std::string(
				GetTestX509CertPem().data(),
				GetTestX509CertPem().size()
			)
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		X509Cert cert2 =  X509Cert::FromPEM(
			std::string(
				GetTestX509CertPem().data(),
				GetTestX509CertPem().size()
			)
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		MBEDTLSCPPTEST_SELF_MOVE_TEST(cert1);

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


GTEST_TEST(TestX509Cert, X509CertDERAndPEM)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Cert cert1 = X509Cert::FromPEM(
			std::string(
				GetTestX509CertPem().data(),
				GetTestX509CertPem().size()
			)
		);

		EXPECT_EQ(
			cert1.GetPem(),
			std::string(GetTestX509CertPem().data())
		);


		X509Cert cert2 = X509Cert::FromDER(CtnFullR(cert1.GetDer()));

		EXPECT_EQ(
			cert2.GetPem(),
			std::string(GetTestX509CertPem().data())
		);
	}

	// Finally, all allocation should be cleaned after exit.
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
		X509Cert cert1 = X509Cert::FromPEM(
			std::string(
				GetTestX509CertPem().data(),
				GetTestX509CertPem().size()
			)
		);

		const auto& kCert1 = cert1;

		// Borrow Public key
		EXPECT_EQ(
			cert1.BorrowPublicKey().GetPublicDer(),
			kCert1.BorrowPublicKey().GetPublicDer()
		);

		// Get a copy of public key
		auto ecPubKey = cert1.GetPublicKey<EcPublicKey<EcType::SECP256R1> >();
		EXPECT_EQ(
			ecPubKey.GetPublicDer(),
			kCert1.BorrowPublicKey().GetPublicDer()
		);

		// Signature hash type
		EXPECT_EQ(cert1.GetSignHashType(), HashType::SHA256);

		// Common Name
		EXPECT_EQ(cert1.GetCommonName(), "mbed TLS Server 1");
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestX509Cert, X509CertV3Extensions)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Cert cert1 = X509Cert::FromPEM(
			std::string(
				GetTestX509CertPem().data(),
				GetTestX509CertPem().size()
			)
		);

		bool isCritical = false;
		std::string extData;

		auto testProc1 = [&](){
			std::tie(isCritical, extData) = cert1.FindV3Extension<std::string>(
				CtnFullR(std::string("1.2.3.4.5.6.7.1"))
			);
		};
		EXPECT_NO_THROW(testProc1());
		EXPECT_EQ(isCritical, false);
		EXPECT_EQ(extData, "TestData1");

		auto testProc2 = [&](){
			std::tie(isCritical, extData) = cert1.FindV3Extension<std::string>(
				CtnFullR(std::string("1.2.3.4.5.6.7.2"))
			);
		};
		EXPECT_NO_THROW(testProc2());
		EXPECT_EQ(isCritical, false);
		EXPECT_EQ(extData, "TestData2");

		auto testProc3 = [&](){
			std::tie(isCritical, extData) = cert1.FindV3Extension<std::string>(
				CtnFullR(std::string("9.9.9.9.9.9.9.9"))
			);
		};
		EXPECT_THROW(testProc3(), RuntimeException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestX509Cert, X509CertVerifySignature)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Cert cert1 = X509Cert::FromPEM(
			std::string(
				GetTestX509CertPem().data(),
				GetTestX509CertPem().size()
			)
		);

		cert1.VerifySignature();
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestX509CertWrt, X509CertChain)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	auto testCaKey  = EcKeyPair<EcType::SECP256R1>::Generate(*rand);
	auto testSubKey = EcKeyPair<EcType::SECP256R1>::Generate(*rand);

	std::string largeExtData =
		std::string(GetTestRsaPubKeyPem().data()) +
		std::string(GetTestRsaPubKeyPem().data());
	largeExtData += largeExtData + largeExtData;
	largeExtData += largeExtData + largeExtData;

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	std::string          caPem;
	std::vector<uint8_t> caDer;
	{
		X509CertWriter writerCa = X509CertWriter::SelfSign(
			HashType::SHA256,
			testCaKey,
			"C=UK,O=ARM,CN=mbed TLS Server 1"
		);
		writerCa.SetBasicConstraints(
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
		).SetV3Extension(
			"1.2.3.4.5.6.7.1", false, CtnFullR(std::string("TestData1"))
		).SetV3Extension(
			"1.2.3.4.5.6.7.2", false, CtnFullR(std::string("TestData2"))
		).SetV3Extension(
			"1.2.3.4.5.6.7.3", false, CtnFullR(largeExtData)
		).SetValidationTime(
			"20210101000000", "29991231235959"
		);

		caPem = writerCa.GetPem(*rand);
		caDer = writerCa.GetDer(*rand);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	std::string          subPem;
	std::vector<uint8_t> subDer;
	{
		X509Cert certCa = X509Cert::FromDER(CtnFullR(caDer));

		X509CertWriter writerSub = X509CertWriter::CaSign(
			HashType::SHA256,
			certCa,
			testCaKey,
			testSubKey,
			"C=UK,O=ARM,CN=mbed TLS Client 1"
		);

		writerSub.SetBasicConstraints(
			false, 0
		).SetKeyUsage(
			MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
			MBEDTLS_X509_KU_NON_REPUDIATION   |
			MBEDTLS_X509_KU_KEY_ENCIPHERMENT  |
			MBEDTLS_X509_KU_DATA_ENCIPHERMENT |
			MBEDTLS_X509_KU_KEY_AGREEMENT
		).SetNsType(
			MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT |
			MBEDTLS_X509_NS_CERT_TYPE_EMAIL      |
			MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING
		).SetSerialNum(
			BigNumber<>(12345)
		).SetV3Extension(
			"1.2.3.4.5.6.7.1", false, CtnFullR(std::string("TestData1"))
		).SetV3Extension(
			"1.2.3.4.5.6.7.2", false, CtnFullR(std::string("TestData2"))
		).SetValidationTime(
			"20210101000000", "29991231235959"
		);

		subPem = writerSub.GetPem(*rand);
		subDer = writerSub.GetDer(*rand);

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
		EXPECT_NO_THROW(certCa.VerifySignature(
			certCa.GetPublicKey<EcPublicKey<EcType::SECP256R1> >()
		););
		EXPECT_NO_THROW(certCa.VerifySignature(testCaKey););

		EXPECT_THROW(certCa.VerifySignature(testSubKey);, mbedTLSRuntimeError);
		EXPECT_NO_THROW(certSub.VerifySignature(certCa.BorrowPublicKey()););
		EXPECT_NO_THROW(
			certSub.VerifySignature(
				certCa.GetPublicKey<EcPublicKey<EcType::SECP256R1> >()
			);
		);
		EXPECT_NO_THROW(certSub.VerifySignature(testCaKey););
		EXPECT_THROW(certSub.VerifySignature(testSubKey);, mbedTLSRuntimeError);

		uint32_t flag = 0;
		EXPECT_NO_THROW(
			certSub.VerifyChainWithCa(
				certCa,
				nullptr,
				"mbed TLS Client 1",
				flag,
				mbedtls_x509_crt_profile_default,
				[](void *, mbedtls_x509_crt *, int, uint32_t *){
					return 0;
				},
				nullptr
			);
		);
		EXPECT_EQ(flag, 0U);
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
