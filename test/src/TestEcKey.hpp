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
		EcPublicKeyBase<> ec1(gsk_testEcPubKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EcPublicKeyBase<> ec2(gsk_testEcPubKeyPem);

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
		EcPublicKeyBase<> ec1(gsk_testEcPubKeyPem);
		EXPECT_EQ(ec1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec1.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcPublicKeyBase<> ecErr(gsk_testRsaPubKeyPem);, InvalidArgumentException);

		// DER, success & fail
		EcPublicKeyBase<> ec2(CtnFullR(testEcDer));
		EXPECT_EQ(ec1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetKeyType(), PKeyType::Public);
		EXPECT_EQ(ec1.GetEcType() , EcType::SECP256R1);

		EXPECT_THROW(EcPublicKeyBase<> ecErr(CtnFullR(testRsaDer));, InvalidArgumentException);

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
		EcPublicKeyBase<> ec4(EcType::SECP256R1, std::move(xBN), std::move(yBN));
		EXPECT_TRUE(xBN.IsNull());
		EXPECT_TRUE(yBN.IsNull());

		// x,y,z Bytes
		EcPublicKeyBase<> ec5(EcType::SECP256R1, ConstBigNumber(CtnFullR(x)), ConstBigNumber(CtnFullR(y)));

		// From PKeyBase
		PKeyBase<> ecPubPem1  = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> rsaPubPem1 = std::string(gsk_testRsaPubKeyPem);

		EcPublicKeyBase<> ec6(std::move(ecPubPem1));
		EXPECT_TRUE(ecPubPem1.IsNull());

		EXPECT_THROW(EcPublicKeyBase<> ecErr(std::move(rsaPubPem1));, InvalidArgumentException);
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

GTEST_TEST(TestEcKey, EcPrivateBaseClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPairBase<> ec1(gsk_testEcPrvKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EcKeyPairBase<> ec2(gsk_testEcPrvKeyPem);

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

	{
		// Generate

		// PEM, success & fail

		// DER, success & fail

		// r BigNum

		// r Bytes

		// r, x,y,z BigNum

		// r, x,y,z Bytes

		// From PKeyBase

		// Copy

		// Borrow
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPrivateBaseDeriveShared)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		// BigNum
		// Bytes
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPrivateBaseSign)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		// BigNum
		// Bytes
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicBaseVerifySign)
{
	int64_t initCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		// BigNum
		// Bytes
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}
