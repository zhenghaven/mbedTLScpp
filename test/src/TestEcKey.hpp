#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/EcKey.hpp>

#include "SharedVars.hpp"
#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestEcKey, EcGroupClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcGroup<> ecGrp1(EcType::SECP256R1);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EcGroup<> ecGrp2(EcType::CURVE25519);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ecGrp1 = std::move(ecGrp1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ecGrp1 = std::move(ecGrp2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		EcGroup<> ecGrp3(std::move(ecGrp1));

		// This should success.
		ecGrp3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(ecGrp1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(ecGrp2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicBaseClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcPublicKeyBase<> ec1 = EcPublicKeyBase<>::FromPEM(gsk_testEcPubKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EcPublicKeyBase<> ec2 = EcPublicKeyBase<>::FromPEM(gsk_testEcPubKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ec1 = std::move(ec1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ec1 = std::move(ec2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		EcPublicKeyBase<> ec3(std::move(ec1));

		// This should success.
		ec3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(ec1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(ec2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicBaseConstructor)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	std::vector<uint8_t> testEcDer;
	std::vector<uint8_t> testRsaDer;

	{
		PKeyBase<> ecPubPem1  = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> rsaPubPem1 = std::string(gsk_testRsaPubKeyPem);

		testEcDer  = ecPubPem1.GetPublicDer();
		testRsaDer = rsaPubPem1.GetPublicDer();
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);

	{
		BigNum xBN;
		BigNum yBN;
		BigNum zBN;
		std::vector<uint8_t> xVec;
		std::vector<uint8_t> yVec;
		std::array<uint8_t, 32> x;
		std::array<uint8_t, 32> y;

		// PEM, success & fail
		EcPublicKeyBase<> ec1 = EcPublicKeyBase<>::FromPEM(gsk_testEcPubKeyPem);
		EXPECT_EQ(ec1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec1.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcPublicKeyBase<>::FromPEM(gsk_testRsaPubKeyPem);, InvalidArgumentException);

		// DER, success & fail
		EcPublicKeyBase<> ec2 = EcPublicKeyBase<>::FromDER(CtnFullR(testEcDer));
		EXPECT_EQ(ec2.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec2.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcPublicKeyBase<>::FromDER(CtnFullR(testRsaDer));, InvalidArgumentException);

		xBN = BigNum(ec2.GetEcContext().Q.X);
		yBN = BigNum(ec2.GetEcContext().Q.Y);
		zBN = BigNum(ec2.GetEcContext().Q.Z);
		EXPECT_EQ(zBN, 1);

		xVec = xBN.Bytes();
		yVec = yBN.Bytes();
		std::copy(xVec.begin(), xVec.end(), x.begin());
		std::copy(yVec.begin(), yVec.end(), y.begin());

		// x,y,z BigNum
		EcPublicKeyBase<> ec3(EcType::SECP256R1, xBN, yBN);
		EXPECT_EQ(ec3.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec3.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec3.GetEcType() , EcType::SECP256R1);

		EcPublicKeyBase<> ec4(EcType::SECP256R1, std::move(xBN), std::move(yBN));
		EXPECT_EQ(ec4.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec4.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec4.GetEcType() , EcType::SECP256R1);

		EXPECT_TRUE(xBN.IsNull());
		EXPECT_TRUE(yBN.IsNull());

		// x,y,z Bytes
		EcPublicKeyBase<> ec5(EcType::SECP256R1, ConstBigNumber(CtnFullR(x)), ConstBigNumber(CtnFullR(y)));
		EXPECT_EQ(ec5.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec5.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec5.GetEcType() , EcType::SECP256R1);

		// From PKeyBase
		PKeyBase<> ecPubPem1  = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> rsaPubPem1 = std::string(gsk_testRsaPubKeyPem);

		EcPublicKeyBase<> ec6 = EcPublicKeyBase<>::Convert(std::move(ecPubPem1));
		EXPECT_TRUE(ecPubPem1.IsNull());

		EXPECT_THROW(EcPublicKeyBase<> ecErr = EcPublicKeyBase<>::Convert(std::move(rsaPubPem1));, InvalidArgumentException);
		EXPECT_FALSE(rsaPubPem1.IsNull());

		// Borrow
		EcPublicKeyBase<BorrowedPKeyTrait> ec7 = ec6.Get();
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec7.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec6.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec7.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec6.GetEcContext().Q.Y));

		EXPECT_THROW(EcPublicKeyBase<BorrowedPKeyTrait> ecErr(rsaPubPem1.Get());, InvalidArgumentException);

		// Copy
		EcPublicKeyBase<> ec8 = ec6;
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec8.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec6.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec8.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec6.GetEcContext().Q.Y));

		EcPublicKeyBase<> ec9 = ec7;
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec7.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec7.GetEcContext().Q.Y));

		// Copy Assignment
		const void* tmpPtr = nullptr;

		tmpPtr = ec9.Get();
		ec9 = ec1;

		tmpPtr = ec9.Get();
		ec9 = ec7;

		//ec7 = ec7;
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicBaseExports)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		EcPublicKeyBase<> ec1 = EcPublicKeyBase<>::FromPEM(gsk_testEcPubKeyPem);

		EXPECT_NO_THROW(ec1.GetPublicDer(););
		EXPECT_NO_THROW(ec1.GetPublicPem(););
		//EXPECT_ANY_THROW(ec1.GetPrivateDer(););
		//EXPECT_ANY_THROW(ec1.GetPrivatePem(););
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPrivateBaseClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPairBase<> ec1 = EcKeyPairBase<>::FromPEM(gsk_testEcPrvKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EcKeyPairBase<> ec2 = EcKeyPairBase<>::FromPEM(gsk_testEcPrvKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ec1 = std::move(ec1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ec1 = std::move(ec2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		EcKeyPairBase<> ec3(std::move(ec1));

		// This should success.
		ec3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(ec1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(ec2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestEcKey, EcPrivateBaseConstructor)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	SecretVector<uint8_t> testEcDer;
	SecretVector<uint8_t> testEcPubDer;
	SecretVector<uint8_t> testRsaDer;

	{
		PKeyBase<> ecPrvPem1  = SecretString(gsk_testEcPrvKeyPem);
		PKeyBase<> rsaPrvPem1 = SecretString(gsk_testRsaPrvKeyPem);

		testEcDer     = ecPrvPem1.GetPrivateDer();
		auto tmpVec   = ecPrvPem1.GetPublicDer();
		testRsaDer    = rsaPrvPem1.GetPrivateDer();

		testEcPubDer.assign(tmpVec.begin(), tmpVec.end());
	}

	{
		BigNum rBN;
		BigNum xBN;
		BigNum yBN;
		BigNum zBN;
		SecretVector<uint8_t> rVec;
		std::vector<uint8_t> xVec;
		std::vector<uint8_t> yVec;
		SecretArray<uint8_t, 32> r;
		std::array<uint8_t, 32> x;
		std::array<uint8_t, 32> y;

		// Generate
		EcKeyPairBase<> ec1 = EcKeyPairBase<>::Generate(EcType::SECP256R1);
		EXPECT_EQ(ec1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec1.GetEcType() , EcType::SECP256R1);

		// PEM, success & fail
		EcKeyPairBase<> ec2 = EcKeyPairBase<>::FromPEM(gsk_testEcPrvKeyPem);
		EXPECT_EQ(ec2.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec2.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcKeyPairBase<>::FromPEM(gsk_testEcPubKeyPem);, mbedTLSRuntimeError);
		EXPECT_THROW(EcKeyPairBase<>::FromPEM(gsk_testRsaPrvKeyPem);, InvalidArgumentException);

		// DER, success & fail
		EcKeyPairBase<> ec3 = EcKeyPairBase<>::FromDER(CtnFullR(testEcDer));
		EXPECT_EQ(ec3.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec3.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec3.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcKeyPairBase<>::FromDER(CtnFullR(testEcPubDer));, mbedTLSRuntimeError);
		EXPECT_THROW(EcKeyPairBase<>::FromDER(CtnFullR(testRsaDer));, InvalidArgumentException);

		rBN = BigNum(ec2.GetEcContext().d);
		xBN = BigNum(ec2.GetEcContext().Q.X);
		yBN = BigNum(ec2.GetEcContext().Q.Y);
		zBN = BigNum(ec2.GetEcContext().Q.Z);
		EXPECT_EQ(zBN, 1);

		rVec = rBN.SecretBytes();
		xVec = xBN.Bytes();
		yVec = yBN.Bytes();
		std::copy(rVec.begin(), rVec.end(), r.Get().begin());
		std::copy(xVec.begin(), xVec.end(), x.begin());
		std::copy(yVec.begin(), yVec.end(), y.begin());

		// r BigNum
		EcKeyPairBase<> ec4(EcType::SECP256R1, rBN);
		EXPECT_EQ(ec4.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec4.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec4.GetEcType() , EcType::SECP256R1);

		// r Bytes
		EcKeyPairBase<> ec5(EcType::SECP256R1, ConstBigNumber(CtnFullR(r)));
		EXPECT_EQ(ec5.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec5.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec5.GetEcType() , EcType::SECP256R1);

		// r, x,y,z BigNum
		EcKeyPairBase<> ec6(EcType::SECP256R1, rBN, xBN, yBN);
		EXPECT_EQ(ec6.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec6.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec6.GetEcType() , EcType::SECP256R1);

		EcKeyPairBase<> ec7(EcType::SECP256R1, std::move(rBN), std::move(xBN), std::move(yBN));
		EXPECT_EQ(ec7.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec7.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec7.GetEcType() , EcType::SECP256R1);
		EXPECT_TRUE(rBN.IsNull());
		EXPECT_TRUE(xBN.IsNull());
		EXPECT_TRUE(yBN.IsNull());

		// r, x,y,z Bytes
		EcKeyPairBase<> ec8(EcType::SECP256R1, ConstBigNumber(CtnFullR(r)), ConstBigNumber(CtnFullR(x)), ConstBigNumber(CtnFullR(y)));
		EXPECT_EQ(ec8.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec8.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec8.GetEcType() , EcType::SECP256R1);

		// From PKeyBase
		PKeyBase<> ecPubPem1  = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> ecPrvPem1  = SecretString(gsk_testEcPrvKeyPem);
		PKeyBase<> rsaPrvPem1 = SecretString(gsk_testRsaPrvKeyPem);

		EcKeyPairBase<> ec9 = EcKeyPairBase<>::Convert(std::move(ecPrvPem1));
		EXPECT_TRUE(ecPrvPem1.IsNull());
		EXPECT_EQ(ec9.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec9.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec9.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcKeyPairBase<> ecErr = EcKeyPairBase<>::Convert(std::move(ecPubPem1));, InvalidArgumentException);
		EXPECT_FALSE(ecPubPem1.IsNull());
		EXPECT_THROW(EcKeyPairBase<> ecErr = EcKeyPairBase<>::Convert(std::move(rsaPrvPem1));, InvalidArgumentException);
		EXPECT_FALSE(rsaPrvPem1.IsNull());

		// Borrow
		EcKeyPairBase<BorrowedPKeyTrait> ec10 = ec9.Get();
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().d), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().d));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.Y));

		EXPECT_THROW(EcKeyPairBase<BorrowedPKeyTrait> ecErr(ecPubPem1.Get());, InvalidArgumentException);
		EXPECT_THROW(EcKeyPairBase<BorrowedPKeyTrait> ecErr(rsaPrvPem1.Get());, InvalidArgumentException);

		// Copy
		EcKeyPairBase<> ec11 = ec9;
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec11.GetEcContext().d), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().d));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec11.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec11.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.Y));

		EcKeyPairBase<> ec12 = ec10;
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec12.GetEcContext().d), BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().d));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec12.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec12.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().Q.Y));

		// Copy Assignment
		const void* tmpPtr = nullptr;

		tmpPtr = ec12.Get();
		ec12 = ec1;

		tmpPtr = ec12.Get();
		ec12 = ec10;

		//ec10 = ec10;
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPrivateBaseExports)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		EcKeyPairBase<> ec1 = EcKeyPairBase<>::FromPEM(gsk_testEcPrvKeyPem);

		EXPECT_NO_THROW(ec1.GetPublicDer(););
		EXPECT_NO_THROW(ec1.GetPublicPem(););
		EXPECT_NO_THROW(ec1.GetPrivateDer(););
		EXPECT_NO_THROW(ec1.GetPrivatePem(););
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPrivateBaseDeriveShared)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		EcKeyPairBase<> ec1 = EcKeyPairBase<>::Generate(EcType::SECP256R1);
		EcKeyPairBase<> ec2 = EcKeyPairBase<>::Generate(EcType::SECP256R1);
		EcPublicKeyBase<> ec3 = EcPublicKeyBase<>::FromPEM(gsk_testEcPubKeyPem);

		// BigNum
		BigNum skBN;
		EXPECT_NO_THROW(skBN = ec1.DeriveSharedKeyInBigNum(ec2););
		EXPECT_TRUE(0UL < skBN.GetSize() && skBN.GetSize() <= 32UL);
		EXPECT_NO_THROW(skBN = ec1.DeriveSharedKeyInBigNum(ec3););
		EXPECT_TRUE(0UL < skBN.GetSize() && skBN.GetSize() <= 32UL);

		// Bytes
		SecretVector<uint8_t> sk;
		EXPECT_NO_THROW(sk = ec1.DeriveSharedKey(ec2););
		EXPECT_TRUE(0UL < sk.size() && sk.size() <= 32UL);
		EXPECT_NO_THROW(sk = ec1.DeriveSharedKey(ec3););
		EXPECT_TRUE(0UL < sk.size() && sk.size() <= 32UL);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPrivateBaseSign)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	Hash<HashType::SHA256> testHash = Hasher<HashType::SHA256>().Calc(CtnFullR("TestString"));

	{
		EcKeyPairBase<> ec1 = EcKeyPairBase<>::Generate(EcType::SECP256R1);
		// BigNum
		BigNum rBN;
		BigNum sBN;
		EXPECT_TRUE(rBN.GetSize() <= 0UL);
		EXPECT_TRUE(sBN.GetSize() <= 0UL);
		std::tie(rBN, sBN) = ec1.SignInBigNum(HashType::SHA256, CtnFullR(testHash));
		EXPECT_TRUE(0UL < rBN.GetSize() && rBN.GetSize() <= 32UL);
		EXPECT_TRUE(0UL < sBN.GetSize() && sBN.GetSize() <= 32UL);

		// Bytes
		std::vector<uint8_t> rVec;
		std::vector<uint8_t> sVec;
		EXPECT_TRUE(rVec.size() <= 0UL);
		EXPECT_TRUE(sVec.size() <= 0UL);
		std::tie(rVec, sVec) = ec1.Sign(HashType::SHA256, CtnFullR(testHash));
		EXPECT_TRUE(0UL < rVec.size() && rVec.size() <= 32UL);
		EXPECT_TRUE(0UL < sVec.size() && sVec.size() <= 32UL);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicBaseVerifySign)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	Hash<HashType::SHA256> testHash = Hasher<HashType::SHA256>().Calc(CtnFullR("TestString"));

	{
		EcKeyPairBase<> ecPrv   = EcKeyPairBase<>::FromPEM(gsk_testEcPrvKeyPem);
		EcPublicKeyBase<> ecPub = EcPublicKeyBase<>::FromPEM(gsk_testEcPubKeyPem);

		// BigNum
		BigNum rBN;
		BigNum sBN;
		std::tie(rBN, sBN) = ecPrv.SignInBigNum(HashType::SHA256, CtnFullR(testHash));

		// Bytes
		std::vector<uint8_t> rVec;
		std::vector<uint8_t> sVec;
		std::tie(rVec, sVec) = ecPrv.Sign(HashType::SHA256, CtnFullR(testHash));

		EXPECT_NO_THROW(ecPub.VerifySign(CtnFullR(testHash), rBN, sBN));
		EXPECT_NO_THROW(ecPub.VerifySign(CtnFullR(testHash), CtnFullR(rVec), CtnFullR(sVec)));
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcPublicKey<EcType::SECP256R1> ec1 = EcPublicKey<EcType::SECP256R1>::FromPEM(gsk_testEcPubKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EcPublicKey<EcType::SECP256R1> ec2 = EcPublicKey<EcType::SECP256R1>::FromPEM(gsk_testEcPubKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ec1 = std::move(ec1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ec1 = std::move(ec2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		EcPublicKey<EcType::SECP256R1> ec3(std::move(ec1));

		// This should success.
		ec3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(ec1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(ec2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicConstructor)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	std::vector<uint8_t> testEcDer;
	std::vector<uint8_t> testRsaDer;

	{
		PKeyBase<> ecPubPem1  = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> rsaPubPem1 = std::string(gsk_testRsaPubKeyPem);

		testEcDer  = ecPubPem1.GetPublicDer();
		testRsaDer = rsaPubPem1.GetPublicDer();
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);

	{
		BigNum xBN;
		BigNum yBN;
		BigNum zBN;
		std::vector<uint8_t> xVec;
		std::vector<uint8_t> yVec;
		std::array<uint8_t, 32> xArr;
		std::array<uint8_t, 32> yArr;
		uint8_t x[32];
		uint8_t y[32];

		// PEM, success & fail
		EcPublicKey<EcType::SECP256R1> ec1 = EcPublicKey<EcType::SECP256R1>::FromPEM(gsk_testEcPubKeyPem);
		EXPECT_EQ(ec1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec1.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW({EcPublicKey<EcType::SECP256R1>::FromPEM(gsk_testRsaPubKeyPem);}, InvalidArgumentException);
		EXPECT_THROW({EcPublicKey<EcType::SECP521R1>::FromPEM(gsk_testEcPubKeyPem); }, InvalidArgumentException);

		// DER, success & fail
		EcPublicKey<EcType::SECP256R1> ec2 = EcPublicKey<EcType::SECP256R1>::FromDER(CtnFullR(testEcDer));
		EXPECT_EQ(ec2.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec2.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW({EcPublicKey<EcType::SECP256R1>::FromDER(CtnFullR(testRsaDer));}, InvalidArgumentException);
		EXPECT_THROW({EcPublicKey<EcType::SECP521R1>::FromDER(CtnFullR(testEcDer)); }, InvalidArgumentException);

		xBN = BigNum(ec2.GetEcContext().Q.X);
		yBN = BigNum(ec2.GetEcContext().Q.Y);
		zBN = BigNum(ec2.GetEcContext().Q.Z);
		EXPECT_EQ(zBN, 1);

		xVec = xBN.Bytes();
		yVec = yBN.Bytes();
		std::copy(xVec.begin(), xVec.end(), xArr.begin());
		std::copy(yVec.begin(), yVec.end(), yArr.begin());
		std::copy(xVec.begin(), xVec.end(), std::begin(x));
		std::copy(yVec.begin(), yVec.end(), std::begin(y));

		// x,y,z BigNum
		EcPublicKey<EcType::SECP256R1> ec3 = EcPublicKey<EcType::SECP256R1>::FromBigNums(xBN, yBN);
		EXPECT_EQ(ec3.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec3.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec3.GetEcType() , EcType::SECP256R1);

		EcPublicKey<EcType::SECP256R1> ec4 = EcPublicKey<EcType::SECP256R1>::FromBigNums(std::move(xBN), std::move(yBN));
		EXPECT_EQ(ec4.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec4.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec4.GetEcType() , EcType::SECP256R1);

		EXPECT_TRUE(xBN.IsNull());
		EXPECT_TRUE(yBN.IsNull());

		// x,y,z Bytes
		EcPublicKey<EcType::SECP256R1> ec5 = EcPublicKey<EcType::SECP256R1>::FromBigNums(ConstBigNumber(CtnFullR(xArr)), ConstBigNumber(CtnFullR(yArr)));
		EXPECT_EQ(ec5.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec5.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec5.GetEcType() , EcType::SECP256R1);

		EcPublicKey<EcType::SECP256R1> ec105 = EcPublicKey<EcType::SECP256R1>::FromBytes(CtnFullR(xVec), CtnFullR(yVec));
		EXPECT_EQ(ec105.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec105.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec105.GetEcType() , EcType::SECP256R1);

		EcPublicKey<EcType::SECP256R1> ec106 = EcPublicKey<EcType::SECP256R1>::FromBytes(xArr, yArr);
		EXPECT_EQ(ec106.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec106.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec106.GetEcType() , EcType::SECP256R1);

		EcPublicKey<EcType::SECP256R1> ec107 = EcPublicKey<EcType::SECP256R1>::FromBytes(x, y);
		EXPECT_EQ(ec106.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec106.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec106.GetEcType() , EcType::SECP256R1);

		// From PKeyBase
		PKeyBase<> ecPubPem1  = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> rsaPubPem1 = std::string(gsk_testRsaPubKeyPem);

		EXPECT_THROW({EcPublicKey<EcType::SECP256R1> ecErr = EcPublicKey<EcType::SECP256R1>::Convert(std::move(rsaPubPem1));}, InvalidArgumentException);
		EXPECT_FALSE(rsaPubPem1.IsNull());

		EXPECT_THROW({EcPublicKey<EcType::SECP521R1> ecErr = EcPublicKey<EcType::SECP521R1>::Convert(std::move(ecPubPem1)); }, InvalidArgumentException);
		EXPECT_FALSE(rsaPubPem1.IsNull());

		EcPublicKey<EcType::SECP256R1> ec6 = EcPublicKey<EcType::SECP256R1>::Convert(std::move(ecPubPem1));
		EXPECT_TRUE(ecPubPem1.IsNull());

		// Borrow
		EcPublicKey<EcType::SECP256R1, BorrowedPKeyTrait> ec7 = ec6.Get();
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec7.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec6.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec7.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec6.GetEcContext().Q.Y));

		EXPECT_THROW((EcPublicKey<EcType::SECP256R1, BorrowedPKeyTrait>(rsaPubPem1.Get())), InvalidArgumentException);
		EXPECT_THROW((EcPublicKey<EcType::SECP521R1, BorrowedPKeyTrait>(ecPubPem1.Get()) ), InvalidArgumentException);

		// Copy
		EcPublicKey<EcType::SECP256R1> ec8 = ec6;
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec8.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec6.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec8.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec6.GetEcContext().Q.Y));

		EcPublicKey<EcType::SECP256R1> ec9 = ec7;
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec7.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec7.GetEcContext().Q.Y));

		// Copy Assignment
		const void* tmpPtr = nullptr;

		tmpPtr = ec9.Get();
		ec9 = ec1;

		tmpPtr = ec9.Get();
		ec9 = ec7;

		//ec7 = ec7;
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPrivateClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPair<EcType::SECP256R1> ec1 = EcKeyPair<EcType::SECP256R1>::FromPEM(gsk_testEcPrvKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EcKeyPair<EcType::SECP256R1> ec2 = EcKeyPair<EcType::SECP256R1>::FromPEM(gsk_testEcPrvKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ec1 = std::move(ec1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		ec1 = std::move(ec2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		EcKeyPair<EcType::SECP256R1> ec3(std::move(ec1));

		// This should success.
		ec3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(ec1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(ec2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicAPI)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	std::array<uint8_t, 32> r;
	std::array<uint8_t, 32> s;
	std::vector<uint8_t> rVec;
	std::vector<uint8_t> sVec;

	Hash<HashType::SHA256> testHash = Hasher<HashType::SHA256>().Calc(CtnFullR("TestString"));

	{
		EcKeyPairBase<> ec1 = EcKeyPairBase<>::FromPEM(gsk_testEcPrvKeyPem);

		std::tie(rVec, sVec) = ec1.Sign(HashType::SHA256, CtnFullR(testHash));
		std::copy(rVec.begin(), rVec.end(), r.begin());
		std::copy(sVec.begin(), sVec.end(), s.begin());
	}

	{
		EcPublicKey<EcType::SECP256R1> ec1 = EcPublicKey<EcType::SECP256R1>::FromPEM(gsk_testEcPubKeyPem);

		EXPECT_NO_THROW(ec1.GetPublicPem());
		EXPECT_NO_THROW(ec1.GetPublicDer());
		EXPECT_NO_THROW(ec1.VerifySign(testHash, CtnFullR(r), CtnFullR(s)));
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPrivateConstructor)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	SecretVector<uint8_t> testEcDer;
	SecretVector<uint8_t> testEcPubDer;
	SecretVector<uint8_t> testRsaDer;

	{
		PKeyBase<> ecPrvPem1  = SecretString(gsk_testEcPrvKeyPem);
		PKeyBase<> rsaPrvPem1 = SecretString(gsk_testRsaPrvKeyPem);

		testEcDer     = ecPrvPem1.GetPrivateDer();
		auto tmpVec   = ecPrvPem1.GetPublicDer();
		testRsaDer    = rsaPrvPem1.GetPrivateDer();

		testEcPubDer.assign(tmpVec.begin(), tmpVec.end());
	}

	{
		BigNum rBN;
		BigNum xBN;
		BigNum yBN;
		BigNum zBN;
		SecretVector<uint8_t> rVec;
		std::vector<uint8_t> xVec;
		std::vector<uint8_t> yVec;
		SecretArray<uint8_t, 32> rArr;
		std::array<uint8_t, 32> xArr;
		std::array<uint8_t, 32> yArr;

		// Generate
		EcKeyPair<EcType::SECP256R1> ec1 = EcKeyPair<EcType::SECP256R1>::Generate();
		EXPECT_EQ(ec1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec1.GetEcType() , EcType::SECP256R1);

		// PEM, success & fail
		EcKeyPair<EcType::SECP256R1> ec2 = EcKeyPair<EcType::SECP256R1>::FromPEM(gsk_testEcPrvKeyPem);
		EXPECT_EQ(ec2.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec2.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcKeyPair<EcType::SECP256R1>::FromPEM(gsk_testEcPubKeyPem);, mbedTLSRuntimeError);
		EXPECT_THROW(EcKeyPair<EcType::SECP521R1>::FromPEM(gsk_testEcPrvKeyPem); , InvalidArgumentException);
		EXPECT_THROW(EcKeyPair<EcType::SECP256R1>::FromPEM(gsk_testRsaPrvKeyPem);, InvalidArgumentException);

		// DER, success & fail
		EcKeyPair<EcType::SECP256R1> ec3 = EcKeyPair<EcType::SECP256R1>::FromDER(CtnFullR(testEcDer));
		EXPECT_EQ(ec3.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec3.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec3.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcKeyPair<EcType::SECP256R1>::FromDER(CtnFullR(testEcPubDer));, mbedTLSRuntimeError);
		EXPECT_THROW(EcKeyPair<EcType::SECP521R1>::FromDER(CtnFullR(testEcDer)); , InvalidArgumentException);
		EXPECT_THROW(EcKeyPair<EcType::SECP256R1>::FromDER(CtnFullR(testRsaDer));, InvalidArgumentException);

		rBN = BigNum(ec2.GetEcContext().d);
		xBN = BigNum(ec2.GetEcContext().Q.X);
		yBN = BigNum(ec2.GetEcContext().Q.Y);
		zBN = BigNum(ec2.GetEcContext().Q.Z);
		EXPECT_EQ(zBN, 1);

		rVec = rBN.SecretBytes();
		xVec = xBN.Bytes();
		yVec = yBN.Bytes();
		std::copy(rVec.begin(), rVec.end(), rArr.Get().begin());
		std::copy(xVec.begin(), xVec.end(), xArr.begin());
		std::copy(yVec.begin(), yVec.end(), yArr.begin());

		// r BigNum
		EcKeyPair<EcType::SECP256R1> ec4 = EcKeyPair<EcType::SECP256R1>::FromBigNums(rBN);
		EXPECT_EQ(ec4.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec4.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec4.GetEcType() , EcType::SECP256R1);

		// r Bytes
		EcKeyPair<EcType::SECP256R1> ec5 = EcKeyPair<EcType::SECP256R1>::FromBigNums(ConstBigNumber(CtnFullR(rArr)));
		EXPECT_EQ(ec5.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec5.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec5.GetEcType() , EcType::SECP256R1);

		EcKeyPair<EcType::SECP256R1> ec101 = EcKeyPair<EcType::SECP256R1>::FromBytes(CtnFullR(rArr));
		EXPECT_EQ(ec101.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec101.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec101.GetEcType() , EcType::SECP256R1);

		EcKeyPair<EcType::SECP256R1> ec102 = EcKeyPair<EcType::SECP256R1>::FromBytes(rArr);
		EXPECT_EQ(ec102.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec102.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec102.GetEcType() , EcType::SECP256R1);

		// r, x,y,z BigNum
		EcKeyPair<EcType::SECP256R1> ec6 = EcKeyPair<EcType::SECP256R1>::FromBigNums(rBN, xBN, yBN);
		EXPECT_EQ(ec6.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec6.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec6.GetEcType() , EcType::SECP256R1);

		EcKeyPair<EcType::SECP256R1> ec7 = EcKeyPair<EcType::SECP256R1>::FromBigNums(std::move(rBN), std::move(xBN), std::move(yBN));
		EXPECT_EQ(ec7.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec7.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec7.GetEcType() , EcType::SECP256R1);
		EXPECT_TRUE(rBN.IsNull());
		EXPECT_TRUE(xBN.IsNull());
		EXPECT_TRUE(yBN.IsNull());

		// r, x,y,z Bytes
		EcKeyPair<EcType::SECP256R1> ec8 = EcKeyPair<EcType::SECP256R1>::FromBigNums(ConstBigNumber(CtnFullR(rArr)), ConstBigNumber(CtnFullR(xArr)), ConstBigNumber(CtnFullR(yArr)));
		EXPECT_EQ(ec8.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec8.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec8.GetEcType() , EcType::SECP256R1);

		EcKeyPair<EcType::SECP256R1> ec103 = EcKeyPair<EcType::SECP256R1>::FromBytes(CtnFullR(rArr), CtnFullR(xArr), CtnFullR(yArr));
		EXPECT_EQ(ec103.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec103.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec103.GetEcType() , EcType::SECP256R1);

		EcKeyPair<EcType::SECP256R1> ec104 = EcKeyPair<EcType::SECP256R1>::FromBytes(rArr, xArr, yArr);
		EXPECT_EQ(ec104.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec104.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec104.GetEcType() , EcType::SECP256R1);

		// From PKeyBase
		PKeyBase<> ecPubPem1  = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> ecPrvPem1  = SecretString(gsk_testEcPrvKeyPem);
		PKeyBase<> rsaPrvPem1 = SecretString(gsk_testRsaPrvKeyPem);

		EXPECT_THROW(EcKeyPair<EcType::SECP521R1> ecErr = EcKeyPair<EcType::SECP521R1>::Convert(std::move(ecPrvPem1));, InvalidArgumentException);
		EXPECT_FALSE(ecPrvPem1.IsNull());

		EcKeyPair<EcType::SECP256R1> ec9 = EcKeyPair<EcType::SECP256R1>::Convert(std::move(ecPrvPem1));
		EXPECT_TRUE(ecPrvPem1.IsNull());
		EXPECT_EQ(ec9.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec9.GetKeyType(), PKeyType::Private);
		EXPECT_EQ(ec9.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcKeyPair<EcType::SECP256R1> ecErr = EcKeyPair<EcType::SECP256R1>::Convert(std::move(ecPubPem1));, InvalidArgumentException);
		EXPECT_FALSE(ecPubPem1.IsNull());
		EXPECT_THROW(EcKeyPair<EcType::SECP256R1> ecErr = EcKeyPair<EcType::SECP256R1>::Convert(std::move(rsaPrvPem1));, InvalidArgumentException);
		EXPECT_FALSE(rsaPrvPem1.IsNull());

		// Borrow
		ecPrvPem1  = SecretString(gsk_testEcPrvKeyPem);

		EcKeyPair<EcType::SECP256R1, BorrowedPKeyTrait> ec10 = ec9.Get();
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().d), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().d));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.Y));

		EXPECT_THROW((EcKeyPair<EcType::SECP256R1, BorrowedPKeyTrait>(ecPubPem1.Get()) );, InvalidArgumentException);
		EXPECT_THROW((EcKeyPair<EcType::SECP521R1, BorrowedPKeyTrait>(ecPrvPem1.Get()) );, InvalidArgumentException);
		EXPECT_THROW((EcKeyPair<EcType::SECP256R1, BorrowedPKeyTrait>(rsaPrvPem1.Get()));, InvalidArgumentException);

		// Copy
		EcKeyPair<EcType::SECP256R1> ec11 = ec9;
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec11.GetEcContext().d), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().d));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec11.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec11.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec9.GetEcContext().Q.Y));

		EcKeyPair<EcType::SECP256R1> ec12 = ec10;
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec12.GetEcContext().d), BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().d));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec12.GetEcContext().Q.X), BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().Q.X));
		EXPECT_EQ(BigNumber<BorrowerBigNumTrait>(&ec12.GetEcContext().Q.Y), BigNumber<BorrowerBigNumTrait>(&ec10.GetEcContext().Q.Y));

		// Copy Assignment
		const void* tmpPtr = nullptr;

		tmpPtr = ec12.Get();
		ec12 = ec1;

		tmpPtr = ec12.Get();
		ec12 = ec10;

		//ec10 = ec10;
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}
