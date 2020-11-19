#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/PKey.hpp>

#include "SharedVars.hpp"
#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestPKey, PKeyBaseClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrvPem1 = SecretString(gsk_testRsaPrvKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> rsaPrvPem2 = SecretString(gsk_testRsaPrvKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		rsaPrvPem1 = std::move(rsaPrvPem1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		rsaPrvPem1 = std::move(rsaPrvPem2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		PKeyBase<> rsaPrvPem3(std::move(rsaPrvPem1));

		// This should success.
		rsaPrvPem3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(rsaPrvPem1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(rsaPrvPem2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestPKey, PemParse)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrvPem1 = SecretString(gsk_testRsaPrvKeyPem);

		EXPECT_EQ(rsaPrvPem1.GetAlgmCat(), PKeyAlgmCat::RSA);
		EXPECT_EQ(rsaPrvPem1.GetKeyType(), PKeyType::Private);
		EXPECT_TRUE(rsaPrvPem1.HasPrvKey());
		EXPECT_TRUE(rsaPrvPem1.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> rsaPubPem1 = std::string(gsk_testRsaPubKeyPem);

		EXPECT_EQ(rsaPubPem1.GetAlgmCat(), PKeyAlgmCat::RSA);
		EXPECT_EQ(rsaPubPem1.GetKeyType(), PKeyType::Public);
		EXPECT_FALSE(rsaPubPem1.HasPrvKey());
		EXPECT_TRUE(rsaPubPem1.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPrvPem1 = SecretString(gsk_testEcPrvKeyPem);

		EXPECT_EQ(ecPrvPem1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ecPrvPem1.GetKeyType(), PKeyType::Private);
		EXPECT_TRUE(ecPrvPem1.HasPrvKey());
		EXPECT_TRUE(ecPrvPem1.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 3);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPubPem1 = std::string(gsk_testEcPubKeyPem);

		EXPECT_EQ(ecPubPem1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ecPubPem1.GetKeyType(), PKeyType::Public);
		EXPECT_FALSE(ecPubPem1.HasPrvKey());
		EXPECT_TRUE(ecPubPem1.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestPKey, DerGeneration)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrv1 = SecretString(gsk_testRsaPrvKeyPem);
		PKeyBase<> rsaPrv2 = CtnFullR(rsaPrv1.GetPrivateDer());

		EXPECT_EQ(rsaPrv1.GetAlgmCat(), rsaPrv2.GetAlgmCat());
		EXPECT_EQ(rsaPrv1.GetKeyType(), rsaPrv2.GetKeyType());
		EXPECT_EQ(rsaPrv1.HasPrvKey(),  rsaPrv2.HasPrvKey());
		EXPECT_EQ(rsaPrv1.HasPubKey(),  rsaPrv2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> rsaPub1 = std::string(gsk_testRsaPubKeyPem);
		PKeyBase<> rsaPub2 = CtnFullR(rsaPub1.GetPublicDer());
		EXPECT_THROW(rsaPub1.GetPrivateDer();, mbedTLSRuntimeError);

		EXPECT_EQ(rsaPub1.GetAlgmCat(), rsaPub2.GetAlgmCat());
		EXPECT_EQ(rsaPub1.GetKeyType(), rsaPub2.GetKeyType());
		EXPECT_EQ(rsaPub1.HasPrvKey(),  rsaPub2.HasPrvKey());
		EXPECT_EQ(rsaPub1.HasPubKey(),  rsaPub2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPrv1 = SecretString(gsk_testEcPrvKeyPem);
		PKeyBase<> ecPrv2 = CtnFullR(ecPrv1.GetPrivateDer());

		EXPECT_EQ(ecPrv1.GetAlgmCat(), ecPrv2.GetAlgmCat());
		EXPECT_EQ(ecPrv1.GetKeyType(), ecPrv2.GetKeyType());
		EXPECT_EQ(ecPrv1.HasPrvKey(),  ecPrv2.HasPrvKey());
		EXPECT_EQ(ecPrv1.HasPubKey(),  ecPrv2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 6);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPub1 = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> ecPub2 = CtnFullR(ecPub1.GetPublicDer());
		EXPECT_THROW(ecPub1.GetPrivateDer();, mbedTLSRuntimeError);

		EXPECT_EQ(ecPub1.GetAlgmCat(), ecPub2.GetAlgmCat());
		EXPECT_EQ(ecPub1.GetKeyType(), ecPub2.GetKeyType());
		EXPECT_EQ(ecPub1.HasPrvKey(),  ecPub2.HasPrvKey());
		EXPECT_EQ(ecPub1.HasPubKey(),  ecPub2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 8);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestPKey, PemGeneration)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrv1 = SecretString(gsk_testRsaPrvKeyPem);
		PKeyBase<> rsaPrv2 = rsaPrv1.GetPrivatePem();

		EXPECT_EQ(rsaPrv1.GetAlgmCat(), rsaPrv2.GetAlgmCat());
		EXPECT_EQ(rsaPrv1.GetKeyType(), rsaPrv2.GetKeyType());
		EXPECT_EQ(rsaPrv1.HasPrvKey(),  rsaPrv2.HasPrvKey());
		EXPECT_EQ(rsaPrv1.HasPubKey(),  rsaPrv2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> rsaPub1 = std::string(gsk_testRsaPubKeyPem);
		PKeyBase<> rsaPub2 = rsaPub1.GetPublicPem();
		EXPECT_THROW(rsaPub1.GetPrivatePem();, mbedTLSRuntimeError);

		EXPECT_EQ(rsaPub1.GetAlgmCat(), rsaPub2.GetAlgmCat());
		EXPECT_EQ(rsaPub1.GetKeyType(), rsaPub2.GetKeyType());
		EXPECT_EQ(rsaPub1.HasPrvKey(),  rsaPub2.HasPrvKey());
		EXPECT_EQ(rsaPub1.HasPubKey(),  rsaPub2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPrv1 = SecretString(gsk_testEcPrvKeyPem);
		PKeyBase<> ecPrv2 = ecPrv1.GetPrivatePem();

		EXPECT_EQ(ecPrv1.GetAlgmCat(), ecPrv2.GetAlgmCat());
		EXPECT_EQ(ecPrv1.GetKeyType(), ecPrv2.GetKeyType());
		EXPECT_EQ(ecPrv1.HasPrvKey(),  ecPrv2.HasPrvKey());
		EXPECT_EQ(ecPrv1.HasPubKey(),  ecPrv2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 6);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPub1 = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> ecPub2 = ecPub1.GetPublicPem();
		EXPECT_THROW(ecPub1.GetPrivatePem();, mbedTLSRuntimeError);

		EXPECT_EQ(ecPub1.GetAlgmCat(), ecPub2.GetAlgmCat());
		EXPECT_EQ(ecPub1.GetKeyType(), ecPub2.GetKeyType());
		EXPECT_EQ(ecPub1.HasPrvKey(),  ecPub2.HasPrvKey());
		EXPECT_EQ(ecPub1.HasPubKey(),  ecPub2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 8);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestPKey, SignAndVerifySign)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;

	Hash<HashType::SHA256> testHash = Hasher<HashType::SHA256>().Calc(CtnFullR("TestString"));

	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrv1 = SecretString(gsk_testRsaPrvKeyPem);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		auto rsaSign1 = rsaPrv1.DerSign<HashType::SHA256>(testHash);
		auto rsaSign2 = rsaPrv1.DerSign(HashType::SHA256, CtnFullR(testHash));
		rsaPrv1.VerifyDerSign<HashType::SHA256>(testHash, CtnFullR(rsaSign1));
		rsaPrv1.VerifyDerSign(HashType::SHA256, CtnFullR(testHash), CtnFullR(rsaSign2));

		PKeyBase<> rsaPub1 = std::string(gsk_testRsaPubKeyPem);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_THROW(rsaPub1.DerSign<HashType::SHA256>(testHash);, mbedTLSRuntimeError);
		EXPECT_THROW(rsaPub1.DerSign(HashType::SHA256, CtnFullR(testHash));, mbedTLSRuntimeError);
		rsaPub1.VerifyDerSign<HashType::SHA256>(testHash, CtnFullR(rsaSign1));
		rsaPub1.VerifyDerSign(HashType::SHA256, CtnFullR(testHash), CtnFullR(rsaSign2));

		PKeyBase<> ecPrv1 = SecretString(gsk_testEcPrvKeyPem);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 3);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		auto ecSign1 = ecPrv1.DerSign<HashType::SHA256>(testHash);
		auto ecSign2 = ecPrv1.DerSign(HashType::SHA256, CtnFullR(testHash));
		ecPrv1.VerifyDerSign<HashType::SHA256>(testHash, CtnFullR(ecSign1));
		ecPrv1.VerifyDerSign(HashType::SHA256, CtnFullR(testHash), CtnFullR(ecSign2));

		PKeyBase<> ecPub1 = std::string(gsk_testEcPubKeyPem);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_THROW(ecPub1.DerSign<HashType::SHA256>(testHash);, mbedTLSRuntimeError);
		EXPECT_THROW(ecPub1.DerSign(HashType::SHA256, CtnFullR(testHash));, mbedTLSRuntimeError);
		ecPub1.VerifyDerSign<HashType::SHA256>(testHash, CtnFullR(ecSign1));
		ecPub1.VerifyDerSign(HashType::SHA256, CtnFullR(testHash), CtnFullR(ecSign2));
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
