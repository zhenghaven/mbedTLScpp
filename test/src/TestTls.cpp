#include <gtest/gtest.h>

#include <mbedTLScpp/Tls.hpp>

#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/X509Cert.hpp>
#include <mbedTLScpp/TlsSessTktMgr.hpp>

#include "MemoryTest.hpp"

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

GTEST_TEST(TestTlsIntf, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

class TestTls : public Tls
{
public: // Static members:

	using _Base       = Tls;

	static std::vector<uint8_t> s_testTlsBuf;

public:

	TestTls(std::shared_ptr<const TlsConfig> tlsConfig, std::shared_ptr<const TlsSession> session, bool deferHandshake) :
		_Base::Tls(tlsConfig, session, deferHandshake)
	{}

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

protected:

	virtual int Send(const void* buf, size_t len)
	{
		const uint8_t* begin = static_cast<const uint8_t*>(buf);
		s_testTlsBuf.insert(s_testTlsBuf.end(), begin, begin + len);
		return static_cast<int>(len);
	}

	virtual int Recv(void* buf, size_t len)
	{
		size_t byteRecv = len <= s_testTlsBuf.size() ? len : s_testTlsBuf.size();
		std::memcpy(buf, s_testTlsBuf.data(), byteRecv);
		s_testTlsBuf.erase(s_testTlsBuf.begin(), s_testTlsBuf.begin() + byteRecv);
		return static_cast<int>(byteRecv);
	}

	virtual int RecvTimeout(void* buf, size_t len, uint32_t t)
	{
		throw mbedTLSRuntimeError(MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE, "TestTls does not support RecvTimeout");
	}

private:

};

std::vector<uint8_t> TestTls::s_testTlsBuf;

GTEST_TEST(TestTlsIntf, TlsClass)
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

	std::shared_ptr<TlsConfig> testConfig =
		std::make_shared<TlsConfig>(true, true, false,
			MBEDTLS_SSL_PRESET_SUITEB, testCert, nullptr, testCert, testPrvKey, testTktMgr);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		TestTls tls1(testConfig, nullptr, true);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		TestTls tls2(testConfig, nullptr, true);

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

GTEST_TEST(TestTlsIntf, TlsCom)
{
	std::shared_ptr<EcKeyPair<EcType::SECP256R1> > caPrvKey =
	std::make_shared<EcKeyPair<EcType::SECP256R1> >(EcKeyPair<EcType::SECP256R1>::Generate());
	std::shared_ptr<EcKeyPair<EcType::SECP256R1> > svrPrvKey =
	std::make_shared<EcKeyPair<EcType::SECP256R1> >(EcKeyPair<EcType::SECP256R1>::Generate());
	std::shared_ptr<EcKeyPair<EcType::SECP256R1> > cltPrvKey =
	std::make_shared<EcKeyPair<EcType::SECP256R1> >(EcKeyPair<EcType::SECP256R1>::Generate());

	std::shared_ptr<X509Cert> caCert =
	std::make_shared<X509Cert>(
		X509Cert::FromDER(CtnFullR(
			X509CertWriter::SelfSign(HashType::SHA256, *caPrvKey, "C=US,CN=Test CA").
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

	std::shared_ptr<X509Cert> svrCert =
	std::make_shared<X509Cert>(
		X509Cert::FromDER(CtnFullR(
			X509CertWriter::CaSign(HashType::SHA256, *caCert, *caPrvKey, *svrPrvKey, "C=US,CN=Test Server").
				SetBasicConstraints(false, -1).
				SetKeyUsage(MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
					MBEDTLS_X509_KU_NON_REPUDIATION   |
					MBEDTLS_X509_KU_KEY_ENCIPHERMENT  |
					MBEDTLS_X509_KU_DATA_ENCIPHERMENT |
					MBEDTLS_X509_KU_KEY_AGREEMENT).
				SetNsType(MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT |
					MBEDTLS_X509_NS_CERT_TYPE_EMAIL      |
					MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING).
				SetSerialNum(BigNumber<>(12345)).
				SetValidationTime("20210101000000", "20211231235959").GetDer()
		))
	);

	std::shared_ptr<X509Cert> cltCert =
	std::make_shared<X509Cert>(
		X509Cert::FromDER(CtnFullR(
			X509CertWriter::CaSign(HashType::SHA256, *caCert, *caPrvKey, *cltPrvKey, "C=US,CN=Test Client").
				SetBasicConstraints(false, -1).
				SetKeyUsage(MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
					MBEDTLS_X509_KU_NON_REPUDIATION   |
					MBEDTLS_X509_KU_KEY_ENCIPHERMENT  |
					MBEDTLS_X509_KU_DATA_ENCIPHERMENT |
					MBEDTLS_X509_KU_KEY_AGREEMENT).
				SetNsType(MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT |
					MBEDTLS_X509_NS_CERT_TYPE_EMAIL      |
					MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING).
				SetSerialNum(BigNumber<>(12345)).
				SetValidationTime("20210101000000", "20211231235959").GetDer()
		))
	);

	std::shared_ptr<TlsConfig> svrConfig =
		std::make_shared<TlsConfig>(true, true, true,
			MBEDTLS_SSL_PRESET_SUITEB,
			caCert, nullptr, svrCert, svrPrvKey, nullptr);

	std::shared_ptr<TlsConfig> cltConfig =
		std::make_shared<TlsConfig>(true, false, true,
			MBEDTLS_SSL_PRESET_SUITEB,
			caCert, nullptr, cltCert, cltPrvKey, nullptr);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		std::unique_ptr<TestTls> svrTlsPre = Internal::make_unique<TestTls>(
			svrConfig, nullptr, true
		);
		std::unique_ptr<TestTls> svrTls = Internal::make_unique<TestTls>(
			std::move(*svrTlsPre)
		);
		svrTlsPre.reset();
		EXPECT_EQ(svrTlsPre.get(), nullptr);

		std::unique_ptr<TestTls> cltTlsPre = Internal::make_unique<TestTls>(
			cltConfig, nullptr, true
		);
		std::unique_ptr<TestTls> cltTls = Internal::make_unique<TestTls>(
			svrConfig, nullptr, true
		);
		*cltTls = std::move(*cltTlsPre);
		cltTlsPre.reset();
		EXPECT_EQ(cltTlsPre.get(), nullptr);

		// while (
		// 	!cltTls->HasHandshakeOver() &&
		// 	!svrTls->HasHandshakeOver())
		// {
		// 	int cltState = cltTls->Get()->state;
		// 	int svrState = svrTls->Get()->state;
		// 	if(!cltTls->HasHandshakeOver())
		// 	{
		// 		cltTls->HandshakeStep();
		// 	}
		// 	cltState = cltTls->Get()->state;
		// 	if(!svrTls->HasHandshakeOver())
		// 	{
		// 		svrTls->HandshakeStep();
		// 	}
		// 	svrState = svrTls->Get()->state;
		// }

		int cltState = cltTls->Get()->state; // HELLO_REQUEST
		int svrState = svrTls->Get()->state; // HELLO_REQUEST
		EXPECT_EQ(cltState, MBEDTLS_SSL_HELLO_REQUEST);
		EXPECT_EQ(svrState, MBEDTLS_SSL_HELLO_REQUEST);

		cltTls->HandshakeStep(); // Self
		cltState = cltTls->Get()->state; // CLIENT_HELLO
		EXPECT_EQ(cltState, MBEDTLS_SSL_CLIENT_HELLO);

		svrTls->HandshakeStep(); // Self
		svrState = svrTls->Get()->state; // CLIENT_HELLO
		EXPECT_EQ(cltState, MBEDTLS_SSL_CLIENT_HELLO);


		cltTls->HandshakeStep(); // Clt => Svr
		cltState = cltTls->Get()->state; // SERVER_HELLO
		EXPECT_EQ(cltState, MBEDTLS_SSL_SERVER_HELLO);
		svrTls->HandshakeStep(); // Svr <= Clt
		svrState = svrTls->Get()->state; // SERVER_HELLO
		EXPECT_EQ(svrState, MBEDTLS_SSL_SERVER_HELLO);

		svrTls->HandshakeStep(); // Svr => Clt
		svrState = svrTls->Get()->state; // SERVER_CERTIFICATE
		EXPECT_EQ(svrState, MBEDTLS_SSL_SERVER_CERTIFICATE);
		cltTls->HandshakeStep(); // Clt <= Svr
		cltState = cltTls->Get()->state; // SERVER_CERTIFICATE
		EXPECT_EQ(cltState, MBEDTLS_SSL_SERVER_CERTIFICATE);

		svrTls->HandshakeStep(); // Svr => Clt
		svrState = svrTls->Get()->state; // SERVER_KEY_EXCHANGE
		EXPECT_EQ(svrState, MBEDTLS_SSL_SERVER_KEY_EXCHANGE);
		cltTls->HandshakeStep(); // Clt <= Svr
		cltState = cltTls->Get()->state; // SERVER_KEY_EXCHANGE
		EXPECT_EQ(cltState, MBEDTLS_SSL_SERVER_KEY_EXCHANGE);

		svrTls->HandshakeStep(); // Svr => Clt
		svrState = svrTls->Get()->state; // CERTIFICATE_REQUEST
		EXPECT_EQ(svrState, MBEDTLS_SSL_CERTIFICATE_REQUEST);
		cltTls->HandshakeStep(); // Clt <= Svr
		cltState = cltTls->Get()->state; // CERTIFICATE_REQUEST
		EXPECT_EQ(cltState, MBEDTLS_SSL_CERTIFICATE_REQUEST);

		svrTls->HandshakeStep(); // Svr => Clt
		svrState = svrTls->Get()->state; // SERVER_HELLO_DONE
		EXPECT_EQ(svrState, MBEDTLS_SSL_SERVER_HELLO_DONE);
		cltTls->HandshakeStep(); // Clt <= Svr
		cltState = cltTls->Get()->state; // SERVER_HELLO_DONE
		EXPECT_EQ(cltState, MBEDTLS_SSL_SERVER_HELLO_DONE);

		svrTls->HandshakeStep(); // Svr => Clt
		svrState = svrTls->Get()->state; // CLIENT_CERTIFICATE
		EXPECT_EQ(svrState, MBEDTLS_SSL_CLIENT_CERTIFICATE);
		cltTls->HandshakeStep(); // Clt <= Svr
		cltState = cltTls->Get()->state; // CLIENT_CERTIFICATE
		EXPECT_EQ(cltState, MBEDTLS_SSL_CLIENT_CERTIFICATE);

		cltTls->HandshakeStep(); // Clt => Svr
		cltState = cltTls->Get()->state; // CLIENT_KEY_EXCHANGE
		EXPECT_EQ(cltState, MBEDTLS_SSL_CLIENT_KEY_EXCHANGE);
		svrTls->HandshakeStep(); // Svr <= Clt
		svrState = svrTls->Get()->state; // CLIENT_KEY_EXCHANGE
		EXPECT_EQ(svrState, MBEDTLS_SSL_CLIENT_KEY_EXCHANGE);

		cltTls->HandshakeStep(); // Clt => Svr
		cltState = cltTls->Get()->state; // CERTIFICATE_VERIFY
		EXPECT_EQ(cltState, MBEDTLS_SSL_CERTIFICATE_VERIFY);
		svrTls->HandshakeStep(); // Svr <= Clt
		svrState = svrTls->Get()->state; // CERTIFICATE_VERIFY
		EXPECT_EQ(svrState, MBEDTLS_SSL_CERTIFICATE_VERIFY);

		cltTls->HandshakeStep(); // Clt => Svr
		cltState = cltTls->Get()->state; // CLIENT_CHANGE_CIPHER_SPEC
		EXPECT_EQ(cltState, MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC);
		svrTls->HandshakeStep(); // Svr <= Clt
		svrState = svrTls->Get()->state; // CLIENT_CHANGE_CIPHER_SPEC
		EXPECT_EQ(svrState, MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC);

		cltTls->HandshakeStep(); // Clt => Svr
		cltState = cltTls->Get()->state; // CLIENT_FINISHED
		EXPECT_EQ(cltState, MBEDTLS_SSL_CLIENT_FINISHED);
		svrTls->HandshakeStep(); // Svr <= Clt
		svrState = svrTls->Get()->state; // CLIENT_FINISHED
		EXPECT_EQ(svrState, MBEDTLS_SSL_CLIENT_FINISHED);

		cltTls->HandshakeStep(); // Clt => Svr
		cltState = cltTls->Get()->state; // SERVER_CHANGE_CIPHER_SPEC
		EXPECT_EQ(cltState, MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC);
		svrTls->HandshakeStep(); // Svr <= Clt
		svrState = svrTls->Get()->state; // SERVER_CHANGE_CIPHER_SPEC
		EXPECT_EQ(svrState, MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC);

		svrTls->HandshakeStep(); // Svr => Clt
		svrState = svrTls->Get()->state; // SERVER_FINISHED
		EXPECT_EQ(svrState, MBEDTLS_SSL_SERVER_FINISHED);
		cltTls->HandshakeStep(); // Clt <= Svr
		cltState = cltTls->Get()->state; // SERVER_FINISHED
		EXPECT_EQ(cltState, MBEDTLS_SSL_SERVER_FINISHED);

		svrTls->HandshakeStep(); // Svr => Clt
		svrState = svrTls->Get()->state; // FLUSH_BUFFERS
		EXPECT_EQ(svrState, MBEDTLS_SSL_FLUSH_BUFFERS);
		cltTls->HandshakeStep(); // Clt <= Svr
		cltState = cltTls->Get()->state; // FLUSH_BUFFERS
		EXPECT_EQ(cltState, MBEDTLS_SSL_FLUSH_BUFFERS);

		svrTls->HandshakeStep(); // Self
		svrState = svrTls->Get()->state; // HANDSHAKE_WRAPUP
		EXPECT_EQ(svrState, MBEDTLS_SSL_HANDSHAKE_WRAPUP);
		cltTls->HandshakeStep(); // Self
		cltState = cltTls->Get()->state; // HANDSHAKE_WRAPUP
		EXPECT_EQ(cltState, MBEDTLS_SSL_HANDSHAKE_WRAPUP);

		svrTls->HandshakeStep(); // Self
		svrState = svrTls->Get()->state; // HANDSHAKE_OVER
		EXPECT_EQ(svrState, MBEDTLS_SSL_HANDSHAKE_OVER);
		cltTls->HandshakeStep(); // Self
		cltState = cltTls->Get()->state; // HANDSHAKE_OVER
		EXPECT_EQ(cltState, MBEDTLS_SSL_HANDSHAKE_OVER);

		uint32_t secretDataSent = 80127368UL;
		uint32_t secretDataRecv = 0;

		cltTls->SendData(&secretDataSent, sizeof(secretDataSent));
		svrTls->RecvData(&secretDataRecv, sizeof(secretDataRecv));
		EXPECT_EQ(secretDataSent, secretDataRecv);

		secretDataRecv = 0;

		svrTls->SendData(&secretDataSent, sizeof(secretDataSent));
		cltTls->RecvData(&secretDataRecv, sizeof(secretDataRecv));
		EXPECT_EQ(secretDataSent, secretDataRecv);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
