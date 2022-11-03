// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <gtest/gtest.h>

#include <mbedTLScpp/DefaultRbg.hpp>
#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/Tls.hpp>
#include <mbedTLScpp/TlsSessTktMgr.hpp>
#include <mbedTLScpp/X509Cert.hpp>

#include "MemoryTest.hpp"


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

GTEST_TEST(TestTlsIntf, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

class TestConn
{
public:

	static std::vector<uint8_t> s_testBufC2S;
	static std::vector<uint8_t> s_testBufS2C;

	static int SendOn(
		std::vector<uint8_t>& ch,
		const void* buf,
		size_t len
	)
	{
		const uint8_t* begin = static_cast<const uint8_t*>(buf);
		ch.insert(ch.end(), begin, begin + len);
		return static_cast<int>(len);
	}

	static int RecvOn(
		std::vector<uint8_t>& ch,
		void* buf,
		size_t len
	)
	{
		if (ch.empty())
		{
			return MBEDTLS_ERR_SSL_WANT_READ;
		}
		size_t byteRecv = len <= ch.size() ? len : ch.size();
		std::memcpy(buf, ch.data(), byteRecv);
		ch.erase(ch.begin(), ch.begin() + byteRecv);
		return static_cast<int>(byteRecv);
	}

public:
	TestConn(bool isThisClt) :
		m_isThisClt(isThisClt)
	{}

	virtual ~TestConn()
	{}

	virtual int Send(const void* buf, size_t len)
	{
		if (m_isThisClt)
		{
			return SendOn(s_testBufC2S, buf, len);
		}
		else
		{
			return SendOn(s_testBufS2C, buf, len);
		}
	}

	virtual int Recv(void* buf, size_t len)
	{
		if (m_isThisClt)
		{
			return RecvOn(s_testBufS2C, buf, len);
		}
		else
		{
			return RecvOn(s_testBufC2S, buf, len);
		}
	}

	virtual int RecvTimeout(void* buf, size_t len, uint32_t t)
	{
		throw mbedTLSRuntimeError(
			MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE,
			"TestTls does not support RecvTimeout"
		);
	}

private:

	bool m_isThisClt;

}; // class TestConn

std::vector<uint8_t> TestConn::s_testBufC2S;
std::vector<uint8_t> TestConn::s_testBufS2C;

class TestTls : public Tls<TestConn>
{
public: // Static members:

	using _Base       = Tls;

public:

	TestTls(
		std::shared_ptr<const TlsConfig> tlsConfig,
		std::shared_ptr<const TlsSession> session,
		std::unique_ptr<TestConn> conn
	) :
		_Base::Tls(tlsConfig, session, nullptr)
	{
		_Base::GetConnPtr() = std::move(conn);
	}

	/**
	 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
	 *
	 * @exception None No exception thrown
	 * @param rhs The other TestTls instance.
	 */
	TestTls(TestTls&& rhs) noexcept :
		_Base::Tls(std::forward<_Base>(rhs)) //noexcept
	{}

	TestTls(const TestTls& rhs) = delete;

	virtual ~TestTls()
	{}

	/**
	 * @brief Move assignment. The `rhs` will be empty/null afterwards.
	 *
	 * @exception None No exception thrown
	 * @param rhs The other TestTls instance.
	 * @return TestTls& A reference to this instance.
	 */
	TestTls& operator=(TestTls&& rhs) noexcept
	{
		_Base::operator=(std::forward<_Base>(rhs)); //noexcept

		return *this;
	}

	TestTls& operator=(const TestTls& other) = delete;

	using _Base::NullCheck;
	using _Base::Get;
	using _Base::NonVirtualGet;
	using _Base::Swap;

private:

	std::unique_ptr<TestConn> m_conn;
};

GTEST_TEST(TestTlsIntf, TlsClass)
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
		std::make_shared<X509Cert>(X509Cert::FromDER(CtnFullR(testCertDer)));

	std::shared_ptr<TestingTktMgtType> testTktMgr =
		std::make_shared<TestingTktMgtType>(Internal::make_unique<DefaultRbg>());

	std::shared_ptr<TlsConfig> testConfig =
		std::make_shared<TlsConfig>(
			true, true, false,
			MBEDTLS_SSL_PRESET_SUITEB,
			testCert,
			nullptr,
			testCert,
			testPrvKey,
			testTktMgr,
			Internal::make_unique<DefaultRbg>()
		);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		TestTls tls1(
			testConfig,
			nullptr,
			Internal::make_unique<TestConn>(true)
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		TestTls tls2(
			testConfig,
			nullptr,
			Internal::make_unique<TestConn>(false)
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tls1 = std::move(tls1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tls1 = std::move(tls2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		TestTls tls3(std::move(tls1));

		// This should success.
		tls3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(tls1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(tls2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


template <typename _TlsType>
static void TlsHandshakeTillNoInMsg(_TlsType& tls)
{
	while(!tls.HasHandshakeOver())
	{
		try
		{
			tls.HandshakeStep();
		}
		catch(const mbedTLSRuntimeError& e)
		{
			if (
				e.GetErrorCode() == MBEDTLS_ERR_SSL_WANT_READ ||
				e.GetErrorCode() == MBEDTLS_ERR_SSL_WANT_WRITE
			)
			{
				return;
			}
			else
			{
				throw;
			}
		}
	}
}


GTEST_TEST(TestTlsIntf, TlsCom)
{
	using TestingTktMgtType =
		TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM, 86400>;

	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	std::shared_ptr<EcKeyPair<EcType::SECP256R1> > caPrvKey =
		std::make_shared<EcKeyPair<EcType::SECP256R1> >(
			EcKeyPair<EcType::SECP256R1>::Generate(*rand)
		);
	std::shared_ptr<EcKeyPair<EcType::SECP256R1> > svrPrvKey =
		std::make_shared<EcKeyPair<EcType::SECP256R1> >(
			EcKeyPair<EcType::SECP256R1>::Generate(*rand)
		);
	std::shared_ptr<EcKeyPair<EcType::SECP256R1> > cltPrvKey =
		std::make_shared<EcKeyPair<EcType::SECP256R1> >(
			EcKeyPair<EcType::SECP256R1>::Generate(*rand)
		);


	auto caCertDer = X509CertWriter::SelfSign(
		HashType::SHA256,
		*caPrvKey,
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
	std::shared_ptr<X509Cert> caCert =
		std::make_shared<X509Cert>(X509Cert::FromDER(CtnFullR(caCertDer)));

	auto svrCertDer = X509CertWriter::CaSign(
		HashType::SHA256,
		*caCert,
		*caPrvKey,
		*svrPrvKey,
		"C=US,CN=Test Server"
	).SetBasicConstraints(
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
	).SetValidationTime(
		"20210101000000", "29991231235959"
	).GetDer(*rand);
	std::shared_ptr<X509Cert> svrCert =
		std::make_shared<X509Cert>(X509Cert::FromDER(CtnFullR(svrCertDer)));

	auto cltCertDer = X509CertWriter::CaSign(
		HashType::SHA256,
		*caCert,
		*caPrvKey,
		*cltPrvKey,
		"C=US,CN=Test Client"
	).
	SetBasicConstraints(
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
	).SetValidationTime(
		"20210101000000", "29991231235959"
	).GetDer(*rand);
	std::shared_ptr<X509Cert> cltCert =
		std::make_shared<X509Cert>(X509Cert::FromDER(CtnFullR(cltCertDer)));

	std::shared_ptr<TlsConfig> svrConfig =
		std::make_shared<TlsConfig>(
			true, true, true,
			MBEDTLS_SSL_PRESET_SUITEB,
			caCert,
			nullptr,
			svrCert,
			svrPrvKey,
			nullptr,
			Internal::make_unique<DefaultRbg>()
		);

	std::shared_ptr<TlsConfig> cltConfig =
		std::make_shared<TlsConfig>(
			true, false, true,
			MBEDTLS_SSL_PRESET_SUITEB,
			caCert,
			nullptr,
			cltCert,
			cltPrvKey,
			nullptr,
			Internal::make_unique<DefaultRbg>()
		);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		std::unique_ptr<TestTls> svrTlsPre = Internal::make_unique<TestTls>(
			svrConfig,
			nullptr,
			Internal::make_unique<TestConn>(false)
		);
		std::unique_ptr<TestTls> svrTls = Internal::make_unique<TestTls>(
			std::move(*svrTlsPre)
		);
		svrTlsPre.reset();
		EXPECT_EQ(svrTlsPre.get(), nullptr);

		std::unique_ptr<TestTls> cltTlsPre = Internal::make_unique<TestTls>(
			cltConfig,
			nullptr,
			Internal::make_unique<TestConn>(true)
		);
		std::unique_ptr<TestTls> cltTls = Internal::make_unique<TestTls>(
			svrConfig,
			nullptr,
			Internal::make_unique<TestConn>(true)
		);
		*cltTls = std::move(*cltTlsPre);
		cltTlsPre.reset();
		EXPECT_EQ(cltTlsPre.get(), nullptr);

		int cltState = 0;
		int svrState = 0;

		while (
			!cltTls->HasHandshakeOver() ||
			!svrTls->HasHandshakeOver()
		)
		{
			if(!cltTls->HasHandshakeOver())
			{
				TlsHandshakeTillNoInMsg(*cltTls);
				cltState = cltTls->Get()->MBEDTLS_PRIVATE(state);
			}
			if(!svrTls->HasHandshakeOver())
			{
				TlsHandshakeTillNoInMsg(*svrTls);
				svrState = svrTls->Get()->MBEDTLS_PRIVATE(state);
			}
		}

		uint32_t secretDataSent = 80127368UL;
		uint32_t secretDataRecv = 0;

		// clt => svr
		cltTls->SendData(&secretDataSent, sizeof(secretDataSent));
		svrTls->RecvData(&secretDataRecv, sizeof(secretDataRecv));
		EXPECT_EQ(secretDataSent, secretDataRecv);

		secretDataSent = 0;

		// svr => clt
		svrTls->SendData(&secretDataSent, sizeof(secretDataSent));
		cltTls->RecvData(&secretDataRecv, sizeof(secretDataRecv));
		EXPECT_EQ(secretDataSent, secretDataRecv);

		// Getters
		EXPECT_NO_THROW(cltTls->GetSession().NullCheck(););

		EXPECT_EQ(cltTls->BorrowPeerCert().GetDer(), svrCert->GetDer());
		EXPECT_EQ(cltTls->GetPeerCert().GetDer(), svrCert->GetDer());

		EXPECT_EQ(svrTls->BorrowPeerCert().GetDer(), cltCert->GetDer());
		EXPECT_EQ(svrTls->GetPeerCert().GetDer(), cltCert->GetDer());
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
