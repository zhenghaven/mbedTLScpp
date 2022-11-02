#include <gtest/gtest.h>

#include <mbedTLScpp/EcKey.hpp>

#include "SharedVars.hpp"
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


GTEST_TEST(TestEcKey, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestEcKey, EcGroupConstructAndMove)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcGroup<> ecGrp1(EcType::SECP256R1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		const mbedtls_ecp_group* grp1Ptr = ecGrp1.Get();
		EXPECT_EQ(ecGrp1.Get()->id, MBEDTLS_ECP_DP_SECP256R1);


		// Move
		EcGroup<> ecGrp2(std::move(ecGrp1));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ecGrp1.Get(), nullptr);
		EXPECT_EQ(ecGrp2.Get(), grp1Ptr);
		EXPECT_EQ(ecGrp2.Get()->id, MBEDTLS_ECP_DP_SECP256R1);


		// Copy
		EcGroup<> ecGrp3 = EcGroup<>::FromDeepCopy(ecGrp2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ecGrp2.Get(), grp1Ptr);
		EXPECT_NE(ecGrp3.Get(), nullptr);
		EXPECT_NE(ecGrp3.Get(), grp1Ptr);
		EXPECT_EQ(ecGrp3.Get()->id, MBEDTLS_ECP_DP_SECP256R1);


		// Move assignment
		ecGrp1 = std::move(ecGrp2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ecGrp2.Get(), nullptr);
		EXPECT_EQ(ecGrp1.Get(), grp1Ptr);
		EXPECT_EQ(ecGrp1.Get()->id, MBEDTLS_ECP_DP_SECP256R1);

	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestEcKey, EcGroupLoad)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcGroup<> grp1(EcType::SECP256R1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		const mbedtls_ecp_group* grp1Ptr = grp1.Get();
		EXPECT_EQ(grp1.Get()->id, MBEDTLS_ECP_DP_SECP256R1);

		grp1.Load(EcType::CURVE25519);
		EXPECT_EQ(grp1.Get(), grp1Ptr);
		EXPECT_EQ(grp1.Get()->id, MBEDTLS_ECP_DP_CURVE25519);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicKeyBaseConstructAndMove)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcPublicKeyBase<> ec1(EcType::SECP256R1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		const mbedtls_pk_context* ec1Ptr = ec1.Get();
		EXPECT_NE(ec1.Get(), nullptr);
		EXPECT_EQ(ec1.GetAlgorithmCat(), PKeyAlgmCat::EC);


		// Move
		EcPublicKeyBase<> ec2(std::move(ec1));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec1.Get(), nullptr);
		EXPECT_EQ(ec2.Get(), ec1Ptr);
		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);


		// Move Assignment
		ec1 = std::move(ec2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.Get(), nullptr);
		EXPECT_EQ(ec1.Get(), ec1Ptr);
		EXPECT_EQ(ec1.GetAlgorithmCat(), PKeyAlgmCat::EC);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestEcKey, EcPublicKeyBasePEMAndDER)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// EC Public Key
	{
		EcPublicKeyBase<> ec = EcPublicKeyBase<>::FromPEM(
			std::string(
				GetTestEcPubKeyPem().data(), GetTestEcPubKeyPem().size()
			)
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec.GetKeyType(),      PKeyType::Public);
		EXPECT_EQ(ec.GetEcType(),       EcType::SECP256R1);

		EXPECT_NO_THROW(
			auto pem = ec.GetPublicPem();
			std::string oriPem(GetTestEcPubKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);

		auto der = ec.GetPublicDer();

		EcPublicKeyBase<> ec2 = EcPublicKeyBase<>::FromDER(CtnFullR(der));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(),      PKeyType::Public);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);

		EXPECT_NO_THROW(
			auto pem = ec2.GetPublicPem();
			std::string oriPem(GetTestEcPubKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);
	}

	// Failed - RSA
	{
		using _TestType = EcPublicKeyBase<>;

		EXPECT_THROW(
			_TestType::FromPEM(
				std::string(
					GetTestRsaPubKeyPem().data(), GetTestRsaPubKeyPem().size()
				)
			);,
			InvalidArgumentException
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcPublicKeyBaseCopy)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcPublicKeyBase<> ec = EcPublicKeyBase<>::FromPEM(
			std::string(
				GetTestEcPubKeyPem().data(), GetTestEcPubKeyPem().size()
			)
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		EcPublicKeyBase<> ec2 = EcPublicKeyBase<>::FromDeepCopy(ec);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_NO_THROW(
			EXPECT_EQ(ec.GetPublicDer(), ec2.GetPublicDer());
		);


		// Copy Empty Obj
		ec = std::move(ec2);
		EcPublicKeyBase<> ec3 = EcPublicKeyBase<>::FromDeepCopy(ec2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec3.Get(), nullptr);
		EXPECT_EQ(ec2.Get(), nullptr);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// Copy Empty PK
	{
		EcPublicKeyBase<> ec;

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EcPublicKeyBase<> ec2 = EcPublicKeyBase<>::FromDeepCopy(ec);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(mbedtls_pk_ec(*(ec.Get())), nullptr);
		EXPECT_EQ(mbedtls_pk_ec(*(ec2.Get())), nullptr);
	}


	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcPublicKeyBaseBorrow)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcPublicKeyBase<> ec = EcPublicKeyBase<>::FromPEM(
			std::string(
				GetTestEcPubKeyPem().data(), GetTestEcPubKeyPem().size()
			)
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		auto ec2 = EcPublicKeyBase<BorrowedPKeyTrait>::Borrow(ec.Get());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(),      PKeyType::Public);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);

		EXPECT_EQ(ec2.Get(), ec.Get());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairBaseConstructAndMove)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPairBase<> ec1(EcType::SECP256R1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		const mbedtls_pk_context* ec1Ptr = ec1.Get();
		EXPECT_NE(ec1.Get(), nullptr);
		EXPECT_EQ(ec1.GetAlgorithmCat(), PKeyAlgmCat::EC);


		// Move
		EcKeyPairBase<> ec2(std::move(ec1));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec1.Get(), nullptr);
		EXPECT_EQ(ec2.Get(), ec1Ptr);
		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);


		// Move Assignment
		ec1 = std::move(ec2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.Get(), nullptr);
		EXPECT_EQ(ec1.Get(), ec1Ptr);
		EXPECT_EQ(ec1.GetAlgorithmCat(), PKeyAlgmCat::EC);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairBasePEMAndDER)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// EC Public Key
	{
		EcKeyPairBase<> ec = EcKeyPairBase<>::FromPEM(
			SecretString(
				GetTestEcPrivKeyPem().data(), GetTestEcPrivKeyPem().size()
			),
			*rand
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec.GetKeyType(),      PKeyType::Private);
		EXPECT_EQ(ec.GetEcType(),       EcType::SECP256R1);

		EXPECT_NO_THROW(
			auto pem = ec.GetPrivatePem();
			std::string oriPem(GetTestEcPrivKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);

		auto der = ec.GetPrivateDer();

		EcKeyPairBase<> ec2 = EcKeyPairBase<>::FromDER(CtnFullR(der), *rand);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, der.capacity());

		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(),      PKeyType::Private);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);

		EXPECT_NO_THROW(
			auto pem = ec2.GetPrivatePem();
			std::string oriPem(GetTestEcPrivKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// Failed - EC Public Key
	{
		using _TestType = EcKeyPairBase<>;

		EXPECT_THROW(
			_TestType::FromPEM(
				SecretString(
					GetTestEcPubKeyPem().data(), GetTestEcPubKeyPem().size()
				),
				*rand
			);,
			mbedTLSRuntimeError
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairBaseCopy)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPairBase<> ec = EcKeyPairBase<>::FromPEM(
			SecretString(
				GetTestEcPrivKeyPem().data(), GetTestEcPrivKeyPem().size()
			),
			*rand
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		EcKeyPairBase<> ec2 = EcKeyPairBase<>::FromDeepCopy(ec);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_NO_THROW(
			EXPECT_EQ(ec.GetPublicDer(), ec2.GetPublicDer());
		);


		// Copy Empty Obj
		ec = std::move(ec2);
		EcKeyPairBase<> ec3 = EcKeyPairBase<>::FromDeepCopy(ec2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec3.Get(), nullptr);
		EXPECT_EQ(ec2.Get(), nullptr);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// Copy Empty PK
	{
		EcKeyPairBase<> ec;

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EcKeyPairBase<> ec2 = EcKeyPairBase<>::FromDeepCopy(ec);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(mbedtls_pk_ec(*(ec.Get())), nullptr);
		EXPECT_EQ(mbedtls_pk_ec(*(ec2.Get())), nullptr);
	}


	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairBaseBorrow)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPairBase<> ec = EcKeyPairBase<>::FromPEM(
			SecretString(
				GetTestEcPrivKeyPem().data(), GetTestEcPrivKeyPem().size()
			),
			*rand
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		auto ec2 = EcKeyPairBase<BorrowedPKeyTrait>::Borrow(ec.Get());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(),      PKeyType::Private);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);

		EXPECT_EQ(ec2.Get(), ec.Get());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairBaseGenerate)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPairBase<> ec =
			EcKeyPairBase<>::Generate(EcType::SECP256R1, *rand);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec.GetKeyType(),      PKeyType::Private);
		EXPECT_EQ(ec.GetEcType(),       EcType::SECP256R1);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairBaseSignAndVerify)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;

	Hash<HashType::SHA256> testHash1 =
		Hasher<HashType::SHA256>().Calc(CtnFullR("TestString"));
	Hash<HashType::SHA256> testHash2 =
		Hasher<HashType::SHA256>().Calc(CtnFullR("XTestStringX"));

	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPairBase<> priv = EcKeyPairBase<>::Generate(
			EcType::SECP256R1, *rand
		);
		EcPublicKeyBase<> pub = EcPublicKeyBase<>::FromDER(
			CtnFullR(priv.GetPublicDer())
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		// Sign
		BigNum r;
		BigNum s;
		std::tie(r, s) = priv.SignInBigNum(testHash1, *rand);

		// Verify
		EXPECT_NO_THROW(
			pub.VerifySign(CtnFullR(testHash1), r, s);
		);
		EXPECT_THROW(
			pub.VerifySign(CtnFullR(testHash2), r, s);,
			mbedTLSRuntimeError
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairBaseDeriveSharedKey)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;

	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPairBase<> priv1 = EcKeyPairBase<>::Generate(
			EcType::SECP256R1, *rand
		);
		EcKeyPairBase<> priv2 = EcKeyPairBase<>::Generate(
			EcType::SECP256R1, *rand
		);
		EcKeyPairBase<> priv3 = EcKeyPairBase<>::Generate(
			EcType::SECP256R1, *rand
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 3);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		BigNum s1 = priv1.DeriveSharedKeyInBigNum(priv2, *rand);
		BigNum s2 = priv2.DeriveSharedKeyInBigNum(priv1, *rand);
		BigNum s3 = priv1.DeriveSharedKeyInBigNum(priv3, *rand);

		EXPECT_EQ(s1, s2);
		EXPECT_NE(s1, s3);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcPublicKeyConstructAndMove)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcPublicKey<EcType::SECP256R1> ec1(EcType::SECP256R1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		const mbedtls_pk_context* ec1Ptr = ec1.Get();
		EXPECT_NE(ec1.Get(), nullptr);
		EXPECT_EQ(ec1.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetEcType(),       EcType::SECP256R1);


		// Move
		EcPublicKey<EcType::SECP256R1> ec2(std::move(ec1));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec1.Get(), nullptr);
		EXPECT_EQ(ec2.Get(), ec1Ptr);
		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);


		// Move Assignment
		ec1 = std::move(ec2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.Get(), nullptr);
		EXPECT_EQ(ec1.Get(), ec1Ptr);
		EXPECT_EQ(ec1.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetEcType(),       EcType::SECP256R1);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcPublicKeyPEMAndDER)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// EC Public Key
	{
		auto ec = EcPublicKey<EcType::SECP256R1>::FromPEM(
			std::string(
				GetTestEcPubKeyPem().data(), GetTestEcPubKeyPem().size()
			)
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec.GetKeyType(),      PKeyType::Public);
		EXPECT_EQ(ec.GetEcType(),       EcType::SECP256R1);

		EXPECT_NO_THROW(
			auto pem = ec.GetPublicPem();
			std::string oriPem(GetTestEcPubKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);

		auto der = ec.GetPublicDer();

		auto ec2 = EcPublicKey<EcType::SECP256R1>::FromDER(CtnFullR(der));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(),      PKeyType::Public);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);

		EXPECT_NO_THROW(
			auto pem = ec2.GetPublicPem();
			std::string oriPem(GetTestEcPubKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcPublicKeyCopy)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		auto ec = EcPublicKey<EcType::SECP256R1>::FromPEM(
			std::string(
				GetTestEcPubKeyPem().data(), GetTestEcPubKeyPem().size()
			)
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		auto ec2 = EcPublicKey<EcType::SECP256R1>::FromDeepCopy(ec);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_NO_THROW(
			EXPECT_EQ(ec.GetPublicDer(), ec2.GetPublicDer());
		);


		// Copy Empty Obj
		ec = std::move(ec2);
		auto ec3 = EcPublicKey<EcType::SECP256R1>::FromDeepCopy(ec2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec3.Get(), nullptr);
		EXPECT_EQ(ec2.Get(), nullptr);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcPublicKeyBorrow)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		auto ec = EcPublicKey<EcType::SECP256R1>::FromPEM(
			std::string(
				GetTestEcPubKeyPem().data(), GetTestEcPubKeyPem().size()
			)
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		auto ec2 =
			EcPublicKey<EcType::SECP256R1, BorrowedPKeyTrait>::Borrow(ec.Get());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(),      PKeyType::Public);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);

		EXPECT_EQ(ec2.Get(), ec.Get());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairConstructAndMove)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EcKeyPair<EcType::SECP256R1> ec1(EcType::SECP256R1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		const mbedtls_pk_context* ec1Ptr = ec1.Get();
		EXPECT_NE(ec1.Get(), nullptr);
		EXPECT_EQ(ec1.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetEcType(),       EcType::SECP256R1);


		// Move
		EcKeyPair<EcType::SECP256R1> ec2(std::move(ec1));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec1.Get(), nullptr);
		EXPECT_EQ(ec2.Get(), ec1Ptr);
		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);


		// Move Assignment
		ec1 = std::move(ec2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.Get(), nullptr);
		EXPECT_EQ(ec1.Get(), ec1Ptr);
		EXPECT_EQ(ec1.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec1.GetEcType(),       EcType::SECP256R1);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairPEMAndDER)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// EC Public Key
	{
		auto ec = EcKeyPair<EcType::SECP256R1>::FromPEM(
			SecretString(
				GetTestEcPrivKeyPem().data(), GetTestEcPrivKeyPem().size()
			),
			*rand
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec.GetKeyType(),      PKeyType::Private);
		EXPECT_EQ(ec.GetEcType(),       EcType::SECP256R1);

		EXPECT_NO_THROW(
			auto pem = ec.GetPrivatePem();
			std::string oriPem(GetTestEcPrivKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);

		auto der = ec.GetPrivateDer();

		auto ec2 = EcKeyPair<EcType::SECP256R1>::FromDER(CtnFullR(der), *rand);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, der.capacity());

		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(),      PKeyType::Private);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);

		EXPECT_NO_THROW(
			auto pem = ec2.GetPrivatePem();
			std::string oriPem(GetTestEcPrivKeyPem().data());
			std::string generatedPem(pem.data(), pem.size());
			EXPECT_EQ(generatedPem, oriPem);
		);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// Failed - Other Curve Type
	{
		using _TestType = EcKeyPair<EcType::SECP256R1>;

		EXPECT_THROW(
			_TestType::FromPEM(
				SecretString(
					GetTestEc521PrivKeyPem().data(),
					GetTestEc521PrivKeyPem().size()
				),
				*rand
			);,
			InvalidArgumentException
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairCopy)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		auto ec = EcKeyPair<EcType::SECP256R1>::FromPEM(
			SecretString(
				GetTestEcPrivKeyPem().data(), GetTestEcPrivKeyPem().size()
			),
			*rand
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		auto ec2 = EcKeyPair<EcType::SECP256R1>::FromDeepCopy(ec);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_NO_THROW(
			EXPECT_EQ(ec.GetPublicDer(), ec2.GetPublicDer());
		);


		// Copy Empty Obj
		ec = std::move(ec2);
		auto ec3 = EcKeyPair<EcType::SECP256R1>::FromDeepCopy(ec2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec3.Get(), nullptr);
		EXPECT_EQ(ec2.Get(), nullptr);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairBorrow)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		auto ec = EcKeyPair<EcType::SECP256R1>::FromPEM(
			SecretString(
				GetTestEcPrivKeyPem().data(), GetTestEcPrivKeyPem().size()
			),
			*rand
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		auto ec2 =
			EcKeyPair<EcType::SECP256R1, BorrowedPKeyTrait>::Borrow(ec.Get());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec2.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec2.GetKeyType(),      PKeyType::Private);
		EXPECT_EQ(ec2.GetEcType(),       EcType::SECP256R1);

		EXPECT_EQ(ec2.Get(), ec.Get());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairGenerate)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		auto ec = EcKeyPair<EcType::SECP256R1>::Generate(*rand);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_EQ(ec.GetAlgorithmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ec.GetKeyType(),      PKeyType::Private);
		EXPECT_EQ(ec.GetEcType(),       EcType::SECP256R1);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairSignAndVerify)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;

	Hash<HashType::SHA256> testHash1 =
		Hasher<HashType::SHA256>().Calc(CtnFullR("TestString"));
	Hash<HashType::SHA256> testHash2 =
		Hasher<HashType::SHA256>().Calc(CtnFullR("XTestStringX"));

	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		auto priv = EcKeyPair<EcType::SECP256R1>::Generate(*rand);
		auto pub = EcPublicKey<EcType::SECP256R1>::FromDER(
			CtnFullR(priv.GetPublicDer())
		);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);


		// Sign
		BigNum r;
		BigNum s;
		std::tie(r, s) = priv.SignInBigNum(testHash1, *rand);

		// Verify
		EXPECT_NO_THROW(
			pub.VerifySign(CtnFullR(testHash1), r, s);
		);
		EXPECT_THROW(
			pub.VerifySign(CtnFullR(testHash2), r, s);,
			mbedTLSRuntimeError
		);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}


GTEST_TEST(TestEcKey, EcKeyPairDeriveSharedKey)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	int64_t initSecCount = 0;

	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		auto priv1 = EcKeyPair<EcType::SECP256R1>::Generate(*rand);
		auto priv2 = EcKeyPair<EcType::SECP256R1>::Generate(*rand);
		auto priv3 = EcKeyPair<EcType::SECP256R1>::Generate(*rand);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 3);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		BigNum s1 = priv1.DeriveSharedKeyInBigNum(priv2, *rand);
		BigNum s2 = priv2.DeriveSharedKeyInBigNum(priv1, *rand);
		BigNum s3 = priv1.DeriveSharedKeyInBigNum(priv3, *rand);

		EXPECT_EQ(s1, s2);
		EXPECT_NE(s1, s3);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

