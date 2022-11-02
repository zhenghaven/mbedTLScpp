// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <gtest/gtest.h>


#include <mbedTLScpp/Internal/PKeyHelper.hpp>
#include <mbedTLScpp/DefaultRbg.hpp>

#include "SharedVars.hpp"


namespace mbedTLScpp_Test
{
	extern size_t g_numOfTestFile;
}


#ifdef MBEDTLSCPPTEST_TEST_STD_NS
using namespace std;
#endif // MBEDTLSCPPTEST_TEST_STD_NS

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif // !MBEDTLSCPP_CUSTOMIZED_NAMESPACE

using namespace mbedTLScpp_Test;


GTEST_TEST(TestInternalPKeyHelper, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestInternalPKeyHelper, pk_write_rsa_key_est_size)
{
	// RSA 1024 bits
	{
		std::unique_ptr<RbgInterface> rand =
			Internal::make_unique<DefaultRbg>();

		mbedtls_rsa_context rsa;
		mbedtls_rsa_init(&rsa);

		mbedtls_rsa_gen_key(
			&rsa,
			RbgInterface::CallBack,
			rand.get(),
			1024,
			65537
		);

		// ===== Public Key =====
		size_t estPubSize = Internal::pk_write_rsa_pubkey_asn1_est_size(rsa);

		static constexpr size_t expPubSize =
			4 + 1 + 1 + // asn1_write_mpi(e)
			128 + 2 + 1 + // asn1_write_mpi(n)
			2 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_GE(estPubSize, expPubSize);


		// ===== Private Key =====
		size_t estPrivSize = Internal::pk_write_rsa_prvkey_der_est_size(rsa);

		static constexpr size_t expPrivSize =
			64 + 1 + 1 + // asn1_write_mpi(QP)
			64 + 1 + 1 + // asn1_write_mpi(DQ)
			64 + 1 + 1 + // asn1_write_mpi(DP)
			64 + 1 + 1 + // asn1_write_mpi(Q)
			64 + 1 + 1 + // asn1_write_mpi(P)
			128 + 2 + 1 + // asn1_write_mpi(D)
			4 + 1 + 1 + // asn1_write_mpi(E)
			128 + 2 + 1 + // asn1_write_mpi(N)
			1 + 1 + 1 + // asn1_write_int(0)
			3 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_GE(estPrivSize, expPrivSize);

		// ===== Clean Up =====
		mbedtls_rsa_free(&rsa);
	}

	// RSA 2048 bits
	{
		std::unique_ptr<RbgInterface> rand =
			Internal::make_unique<DefaultRbg>();

		mbedtls_rsa_context rsa;
		mbedtls_rsa_init(&rsa);

		mbedtls_rsa_gen_key(
			&rsa,
			RbgInterface::CallBack,
			rand.get(),
			2048,
			65537
		);

		// ===== Public Key =====
		size_t estPubSize = Internal::pk_write_rsa_pubkey_asn1_est_size(rsa);

		static constexpr size_t expPubSize =
			4 + 1 + 1 + // asn1_write_mpi(e)
			256 + 3 + 1 + // asn1_write_mpi(n)
			3 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_GE(estPubSize, expPubSize);


		// ===== Private Key =====
		size_t actPrivSize = Internal::pk_write_rsa_prvkey_der_est_size(rsa);

		static constexpr size_t expPrivSize =
			128 + 2 + 1 + // asn1_write_mpi(QP)
			128 + 2 + 1 + // asn1_write_mpi(DQ)
			128 + 2 + 1 + // asn1_write_mpi(DP)
			128 + 2 + 1 + // asn1_write_mpi(Q)
			128 + 2 + 1 + // asn1_write_mpi(P)
			256 + 3 + 1 + // asn1_write_mpi(D)
			4 + 1 + 1 + // asn1_write_mpi(E)
			256 + 3 + 1 + // asn1_write_mpi(N)
			1 + 1 + 1 + // asn1_write_int(0)
			3 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_GE(actPrivSize, expPrivSize);

		// ===== Clean Up =====
		mbedtls_rsa_free(&rsa);
	}
}

GTEST_TEST(TestInternalPKeyHelper, pk_write_ec_key_est_size)
{
	// secp256r1
	{
		std::unique_ptr<RbgInterface> rand =
			Internal::make_unique<DefaultRbg>();

		mbedtls_ecp_keypair ecKey;
		mbedtls_ecp_keypair_init(&ecKey);
		mbedtls_ecp_gen_key(
			MBEDTLS_ECP_DP_SECP256K1,
			&ecKey,
			RbgInterface::CallBack,
			rand.get()
		);

		// ===== Public Key =====
		size_t estPubSize = Internal::pk_write_ec_pubkey_asn1_est_size(ecKey);

		static constexpr size_t expPubSize = (2 * 32) + 1;

		EXPECT_EQ(estPubSize, expPubSize);


		// ===== Private Key =====
		size_t estPrivSize = Internal::pk_write_ec_prvkey_der_est_size(ecKey);

		static constexpr size_t expPubLen =
			expPubSize +
			1 + // +1
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			1 + 1; // asn1_write_len() + asn1_write_tag()
		static constexpr size_t expParamLen =
			sizeof(MBEDTLS_OID_EC_GRP_SECP256K1) - 1
			+ 1 + 1 + // pk_write_ec_param
			+ 1 + 1; // asn1_write_len() + asn1_write_tag()
		static constexpr size_t expPrivSize =
			expPubLen + expParamLen +
			32 + 1 + 1 + 1 + // asn1_write_mpi_est_size_given_mpi_size
			sizeof(int) + 1 + 1 + 1 + // asn1_write_int_est_size
			1 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_EQ(estPrivSize, expPrivSize);

		// ===== Clean Up =====
		mbedtls_ecp_keypair_free(&ecKey);
	}

	// secp512k1
	{
		std::unique_ptr<RbgInterface> rand =
			Internal::make_unique<DefaultRbg>();

		mbedtls_ecp_keypair ecKey;
		mbedtls_ecp_keypair_init(&ecKey);
		mbedtls_ecp_gen_key(
			MBEDTLS_ECP_DP_SECP521R1,
			&ecKey,
			RbgInterface::CallBack,
			rand.get()
		);

		// ===== Public Key =====
		size_t estPubSize = Internal::pk_write_ec_pubkey_asn1_est_size(ecKey);

		static constexpr size_t expPubSize = (2 * 66) + 1;

		EXPECT_EQ(estPubSize, expPubSize);


		// ===== Private Key =====
		size_t estPrivSize = Internal::pk_write_ec_prvkey_der_est_size(ecKey);

		static constexpr size_t expPubLen =
			expPubSize +
			1 + // +1
			2 + 1 + // asn1_write_len() + asn1_write_tag()
			2 + 1; // asn1_write_len() + asn1_write_tag()
		static constexpr size_t expParamLen =
			sizeof(MBEDTLS_OID_EC_GRP_SECP521R1) - 1
			+ 1 + 1 + // pk_write_ec_param
			+ 1 + 1; // asn1_write_len() + asn1_write_tag()
		static constexpr size_t expPrivSize =
			expPubLen + expParamLen +
			66 + 1 + 1 + 1 + // asn1_write_mpi_est_size_given_mpi_size
			sizeof(int) + 1 + 1 + 1 + // asn1_write_int_est_size
			2 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_EQ(estPrivSize, expPrivSize);


		// ===== Clean Up =====
		mbedtls_ecp_keypair_free(&ecKey);
	}
}

GTEST_TEST(TestInternalPKeyHelper, ec_signature_to_asn1_est_size)
{
	{
		size_t res = Internal::ec_signature_to_asn1_est_size(32, 32);
		EXPECT_EQ(
			res,
			2 * (32 + 1 + 1 + 1) + // asn1_write_mpi_est_size_given_mpi_size
			1 + 1
		);
	}

	{
		size_t res = Internal::ec_signature_to_asn1_est_size(66, 66);
		EXPECT_EQ(
			res,
			2 * (66 + 1 + 1 + 1) + // asn1_write_mpi_est_size_given_mpi_size
			2 + 1
		);
	}
}

GTEST_TEST(TestInternalPKeyHelper, pk_write_key_der_est_size)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	// RSA
	{
		std::vector<uint8_t> buf;
		mbedtls_pk_context pk;
		mbedtls_pk_init(&pk);
		mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
		mbedtls_rsa_context& rsa = *mbedtls_pk_rsa(pk);

		mbedtls_rsa_gen_key(
			&rsa,
			RbgInterface::CallBack,
			rand.get(),
			1024,
			65537
		);

		// ===== Public Key =====
		size_t estPubSize = Internal::pk_write_pubkey_der_est_size(pk);
		buf.resize(estPubSize);

		auto mbedtlsPubSize =
			mbedtls_pk_write_pubkey_der(&pk, buf.data(), buf.size());
		EXPECT_GT(mbedtlsPubSize, 0);

		EXPECT_LE(mbedtlsPubSize, estPubSize);


		// ===== Private Key =====
		size_t estPrivSize = Internal::pk_write_prvkey_der_est_size(pk);
		buf.resize(estPrivSize);

		auto mbedtlsPrivSize =
			mbedtls_pk_write_key_der(&pk, buf.data(), buf.size());
		EXPECT_GT(mbedtlsPrivSize, 0);

		EXPECT_LE(mbedtlsPrivSize, estPrivSize);


		// ===== Clean Up =====
		mbedtls_pk_free(&pk);
	}

	// EC
	{
		std::vector<uint8_t> buf;
		mbedtls_pk_context pk;
		mbedtls_pk_init(&pk);
		mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
		mbedtls_ecp_keypair& ec = *mbedtls_pk_ec(pk);

		mbedtls_ecp_gen_key(
			MBEDTLS_ECP_DP_SECP384R1,
			&ec,
			RbgInterface::CallBack,
			rand.get()
		);

		// ===== Public Key =====
		size_t estPubSize = Internal::pk_write_pubkey_der_est_size(pk);
		buf.resize(estPubSize);

		auto mbedtlsPubSize =
			mbedtls_pk_write_pubkey_der(&pk, buf.data(), buf.size());
		EXPECT_GT(mbedtlsPubSize, 0);

		EXPECT_LE(mbedtlsPubSize, estPubSize);


		// ===== Private Key =====
		size_t estPrivSize = Internal::pk_write_prvkey_der_est_size(pk);
		buf.resize(estPrivSize);

		auto mbedtlsPrivSize =
			mbedtls_pk_write_key_der(&pk, buf.data(), buf.size());
		EXPECT_GT(mbedtlsPrivSize, 0);

		EXPECT_LE(mbedtlsPrivSize, estPrivSize);


		// clean up
		mbedtls_pk_free(&pk);
	}

}

GTEST_TEST(TestInternalPKeyHelper, pk_write_sign_der_est_size)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	// RSA
	{
		std::vector<uint8_t> buf;
		mbedtls_pk_context pk;
		mbedtls_pk_init(&pk);
		mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
		mbedtls_rsa_context& rsa = *mbedtls_pk_rsa(pk);

		mbedtls_rsa_gen_key(
			&rsa,
			RbgInterface::CallBack,
			rand.get(),
			1024,
			65537
		);

		size_t estSize = Internal::pk_write_sign_der_est_size(pk, 256 / 8);
		static constexpr size_t expSize = 1024 / 8;

		EXPECT_EQ(estSize, expSize);

		// ===== Clean Up =====
		mbedtls_pk_free(&pk);
	}

	// EC
	{
		std::vector<uint8_t> buf;
		mbedtls_pk_context pk;
		mbedtls_pk_init(&pk);
		mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
		mbedtls_ecp_keypair& ec = *mbedtls_pk_ec(pk);

		mbedtls_ecp_gen_key(
			MBEDTLS_ECP_DP_SECP384R1,
			&ec,
			RbgInterface::CallBack,
			rand.get()
		);

		size_t estSize = Internal::pk_write_sign_der_est_size(pk, 256 / 8);
		static constexpr size_t expSize =
			48 + 1 + 1 + // as1_write_mpi(s)
			48 + 1 + 1 + // as1_write_mpi(r)
			1 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_GE(estSize, expSize);

		// clean up
		mbedtls_pk_free(&pk);
	}

}

GTEST_TEST(TestInternalPKeyHelper, GetKeyType_RSAPrivate)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();
	{
		// Key
		mbedtls_pk_context pk;
		mbedtls_pk_init(&pk);

		int mbedtlsRet = mbedtls_pk_parse_key(
			&pk,
			reinterpret_cast<const unsigned char*>(
				GetTestRsaPrivKeyPem().data()
			),
			GetTestRsaPrivKeyPem().size(),
			nullptr,
			0,
			RbgInterface::CallBack,
			rand.get()
		);
		EXPECT_EQ(mbedtlsRet, 0);

		// ===== Test =====
		EXPECT_NO_THROW(
			EXPECT_EQ(GetAlgmCat(pk), PKeyAlgmCat::RSA)
		);
		EXPECT_NO_THROW(
			EXPECT_EQ(Internal::GetKeyType(pk), PKeyType::Private)
		);

		// clean up
		mbedtls_pk_free(&pk);
	}
}

GTEST_TEST(TestInternalPKeyHelper, GetKeyType_RSAPublic)
{
	{
		// Key
		mbedtls_pk_context pk;
		mbedtls_pk_init(&pk);

		int mbedtlsRet = mbedtls_pk_parse_public_key(
			&pk,
			reinterpret_cast<const unsigned char*>(
				GetTestRsaPubKeyPem().data()
			),
			GetTestRsaPubKeyPem().size()
		);
		EXPECT_EQ(mbedtlsRet, 0);

		// ===== Test =====
		EXPECT_NO_THROW(
			EXPECT_EQ(GetAlgmCat(pk), PKeyAlgmCat::RSA)
		);
		EXPECT_NO_THROW(
			EXPECT_EQ(Internal::GetKeyType(pk), PKeyType::Public)
		);

		// clean up
		mbedtls_pk_free(&pk);
	}
}

GTEST_TEST(TestInternalPKeyHelper, GetKeyType_EcPrivate)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();
	{
		// Key
		mbedtls_pk_context pk;
		mbedtls_pk_init(&pk);

		int mbedtlsRet = mbedtls_pk_parse_key(
			&pk,
			reinterpret_cast<const unsigned char*>(
				GetTestEcPrivKeyPem().data()
			),
			GetTestEcPrivKeyPem().size(),
			nullptr,
			0,
			RbgInterface::CallBack,
			rand.get()
		);
		EXPECT_EQ(mbedtlsRet, 0);

		// ===== Test =====
		EXPECT_NO_THROW(
			EXPECT_EQ(GetAlgmCat(pk), PKeyAlgmCat::EC)
		);
		EXPECT_NO_THROW(
			EXPECT_EQ(Internal::GetKeyType(pk), PKeyType::Private)
		);

		// clean up
		mbedtls_pk_free(&pk);
	}
}

GTEST_TEST(TestInternalPKeyHelper, GetKeyType_EcPublic)
{
	{
		// Key
		mbedtls_pk_context pk;
		mbedtls_pk_init(&pk);

		int mbedtlsRet = mbedtls_pk_parse_public_key(
			&pk,
			reinterpret_cast<const unsigned char*>(
				GetTestEcPubKeyPem().data()
			),
			GetTestEcPubKeyPem().size()
		);
		EXPECT_EQ(mbedtlsRet, 0);

		// ===== Test =====
		EXPECT_NO_THROW(
			EXPECT_EQ(GetAlgmCat(pk), PKeyAlgmCat::EC)
		);
		EXPECT_NO_THROW(
			EXPECT_EQ(Internal::GetKeyType(pk), PKeyType::Public)
		);

		// clean up
		mbedtls_pk_free(&pk);
	}
}
