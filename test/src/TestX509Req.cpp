#include <gtest/gtest.h>

#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/X509Req.hpp>

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

using namespace mbedTLScpp_Test;


GTEST_TEST(TestX509ReqWrt, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}


GTEST_TEST(TestX509ReqWrt, X509ReqWrtConstructAndMove)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	EcKeyPair<EcType::SECP256R1> testKey =
		EcKeyPair<EcType::SECP256R1>::Generate(*rand);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509ReqWriter writer1(
			HashType::SHA256,
			testKey,
			"C=UK,O=ARM,CN=mbed TLS Server 1"
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		X509ReqWriter writer2(
			HashType::SHA256,
			testKey,
			"C=UK,O=ARM,CN=mbed TLS Server 2"
		);

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
		X509ReqWriter writer3(std::move(writer1));

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


GTEST_TEST(TestX509ReqWrt, X509ReqWrtGetDerAndPem)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	EcKeyPair<EcType::SECP256R1> testKey =
		EcKeyPair<EcType::SECP256R1>::Generate(*rand);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509ReqWriter writer(
			HashType::SHA256,
			testKey,
			"C=UK,O=ARM,CN=mbed TLS Server 1"
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		EXPECT_NO_THROW(
			writer.GetDer(*rand);
			writer.GetPem(*rand);
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestX509Req, X509ReqConstructAndMove)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	auto testKey = EcKeyPair<EcType::SECP256R1>::Generate(*rand);

	X509ReqWriter writer(
		HashType::SHA256,
		testKey,
		"C=UK,O=ARM,CN=mbed TLS Server 1"
	);
	auto csrDer = writer.GetDer(*rand);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Req req1 = X509Req::FromDER(CtnFullR(csrDer));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		X509Req req2 = X509Req::FromDER(CtnFullR(csrDer));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		req1 = std::move(req1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		req1 = std::move(req2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		X509Req req3(std::move(req1));

		// This should success.
		req3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(req1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(req2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestX509Req, X509ReqParseCheckAndVerify_PEM)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	auto testKey = EcKeyPair<EcType::SECP256R1>::Generate(*rand);

	X509ReqWriter writer(
		HashType::SHA256,
		testKey,
		"C=UK,O=ARM,CN=mbed TLS Server 1"
	);
	auto csrPem = writer.GetPem(*rand);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Req req1 = X509Req::FromPEM(csrPem);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Check public keys are match
		EXPECT_NO_THROW(
			EXPECT_EQ(
				req1.BorrowPublicKey().GetPublicDer(),
				testKey.GetPublicDer()
			);
		);

		auto pubKey = req1.GetPublicKey<EcPublicKey<EcType::SECP256R1> >();
		EXPECT_NO_THROW(
			EXPECT_EQ(
				pubKey.GetPublicDer(),
				testKey.GetPublicDer()
			);
		);

		// Check hash type
		EXPECT_EQ(req1.GetSignHashType(), HashType::SHA256);

		// verify signature
		EXPECT_NO_THROW(
			req1.VerifySignature();
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestX509Req, X509ReqParseCheckAndVerify_DER)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	auto testKey = EcKeyPair<EcType::SECP256R1>::Generate(*rand);

	X509ReqWriter writer(
		HashType::SHA256,
		testKey,
		"C=UK,O=ARM,CN=mbed TLS Server 1"
	);
	auto csrDer = writer.GetDer(*rand);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Req req1 = X509Req::FromDER(CtnFullR(csrDer));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Check public keys are match
		EXPECT_NO_THROW(
			EXPECT_EQ(
				req1.BorrowPublicKey().GetPublicDer(),
				testKey.GetPublicDer()
			);
		);

		auto pubKey = req1.GetPublicKey<EcPublicKey<EcType::SECP256R1> >();
		EXPECT_NO_THROW(
			EXPECT_EQ(
				pubKey.GetPublicDer(),
				testKey.GetPublicDer()
			);
		);

		// Check hash type
		EXPECT_EQ(req1.GetSignHashType(), HashType::SHA256);

		// verify signature
		EXPECT_NO_THROW(
			req1.VerifySignature();
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
