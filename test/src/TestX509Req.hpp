#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/X509Req.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestX509ReqWrt, X509ReqWrtClass)
{
	EcKeyPair<EcType::SECP256R1> testKey = EcKeyPair<EcType::SECP256R1>::Generate();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509ReqWriter writer1 = X509ReqWriter(HashType::SHA256, testKey, "C=UK,O=ARM,CN=mbed TLS Server 1");

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		X509ReqWriter writer2 = X509ReqWriter(HashType::SHA256, testKey, "C=UK,O=ARM,CN=mbed TLS Server 2");

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

GTEST_TEST(TestX509Req, X509ReqClass)
{
	EcKeyPair<EcType::SECP256R1> testKey = EcKeyPair<EcType::SECP256R1>::Generate();
	X509ReqWriter writer = X509ReqWriter(HashType::SHA256, testKey, "C=UK,O=ARM,CN=mbed TLS Server 1");

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Req req1 = X509Req::FromDER(CtnFullR(writer.GetDer()));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		X509Req req2 = X509Req::FromDER(CtnFullR(writer.GetDer()));

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

GTEST_TEST(TestX509ReqWrt, X509ReqWrtExport)
{
	EcKeyPair<EcType::SECP256R1> testKey = EcKeyPair<EcType::SECP256R1>::Generate();
	X509ReqWriter writer = X509ReqWriter(HashType::SHA256, testKey, "C=UK,O=ARM,CN=mbed TLS Server 1");

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Req req1 = X509Req::FromDER(CtnFullR(writer.GetDer()));
		X509Req req2 = X509Req::FromPEM(writer.GetPem());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestX509Req, X509ReqExport)
{
	EcKeyPair<EcType::SECP256R1> testKey = EcKeyPair<EcType::SECP256R1>::Generate();
	X509ReqWriter writer = X509ReqWriter(HashType::SHA256, testKey, "C=UK,O=ARM,CN=mbed TLS Server 1");
	X509Req req = X509Req::FromDER(CtnFullR(writer.GetDer()));

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Req req1 = X509Req::FromDER(CtnFullR(req.GetDer()));
		X509Req req2 = X509Req::FromPEM(req.GetPem());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestX509Req, X509ReqGetKey)
{
	EcKeyPair<EcType::SECP256R1> testKey = EcKeyPair<EcType::SECP256R1>::Generate();
	X509ReqWriter writer = X509ReqWriter(HashType::SHA256, testKey, "C=UK,O=ARM,CN=mbed TLS Server 1");
	X509Req req = X509Req::FromDER(CtnFullR(writer.GetDer()));

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EXPECT_NO_THROW(auto pkey = req.GetPublicKey<EcPublicKey<EcType::SECP256R1> >(););
		EXPECT_NO_THROW(auto pkey = req.GetPublicKey<EcPublicKeyBase<> >(););
		EXPECT_NO_THROW(auto pkey = req.GetPublicKey<PKeyBase<> >(););
		//EXPECT_NO_THROW(auto pkey = req.GetPublicKey<X509Req>(););

		EXPECT_ANY_THROW(auto pkey = req.GetPublicKey<EcPublicKey<EcType::SECP256K1> >(););
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestX509Req, X509ReqGetters)
{
	EcKeyPair<EcType::SECP256R1> testKey = EcKeyPair<EcType::SECP256R1>::Generate();
	X509ReqWriter writer = X509ReqWriter(HashType::SHA256, testKey, "C=UK,O=ARM,CN=mbed TLS Server 1");
	X509Req req = X509Req::FromDER(CtnFullR(writer.GetDer()));

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EXPECT_NO_THROW(auto borrowKey = req.BorrowPublicKey(););
		EXPECT_NO_THROW(std::vector<uint8_t> borrowKeyDer = req.BorrowPublicKey().GetPublicDer(););

		EXPECT_EQ(req.GetHashType(), HashType::SHA256);
		EXPECT_NO_THROW(req.VerifySignature());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
