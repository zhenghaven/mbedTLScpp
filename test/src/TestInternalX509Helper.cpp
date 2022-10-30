// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <gtest/gtest.h>

#include <mbedTLScpp/Internal/X509Helper.hpp>
#include <mbedTLScpp/DefaultRbg.hpp>

#include "SharedVars.hpp"


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

using namespace mbedTLScpp_Test;

GTEST_TEST(TestInternalX509Helper, CountTestFile)
{
	++g_numOfTestFile;
}

GTEST_TEST(TestInternalX509Helper, x509_write_extension_est_size)
{
	// Basic Constraints
	{
		mbedtls_asn1_named_data ext;
		ext.next = nullptr;

		static_assert(
			sizeof(MBEDTLS_OID_BASIC_CONSTRAINTS) - 1 == 3,
			"OID length error."
		);
		ext.oid.p = static_cast<unsigned char*>(mbedtls_calloc(1, 3));
		ext.oid.len = 3;
		std::memcpy(ext.oid.p, MBEDTLS_OID_BASIC_CONSTRAINTS, 3);

		ext.val.p = static_cast<unsigned char*>(mbedtls_calloc(1, 9));
		ext.val.len = 9;
		ext.val.p[0] = 0;
		std::memcpy(ext.val.p + 1, "Test Val", 8);

		size_t estSize = Internal::x509_write_extension_est_size(ext);

		static constexpr size_t expSize =
			// val
			8 + // asn1_write_raw_buffer
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// critical
			0 +
			// oid
			3 + // asn1_write_raw_buffer
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// ext
			1 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_EQ(estSize, expSize);

		// clean up
		mbedtls_asn1_free_named_data(&ext);
	}
}

GTEST_TEST(TestInternalX509Helper, x509_write_extensions_est_size)
{
	// Basic Constraints
	{
		mbedtls_asn1_named_data ext;
		ext.next = nullptr;

		static_assert(
			sizeof(MBEDTLS_OID_BASIC_CONSTRAINTS) - 1 == 3,
			"OID length error."
		);
		ext.oid.p = static_cast<unsigned char*>(mbedtls_calloc(1, 3));
		ext.oid.len = 3;
		std::memcpy(ext.oid.p, MBEDTLS_OID_BASIC_CONSTRAINTS, 3);

		ext.val.p = static_cast<unsigned char*>(mbedtls_calloc(1, 9));
		ext.val.len = 9;
		ext.val.p[0] = 0;
		std::memcpy(ext.val.p + 1, "Test Val", 8);

		size_t estSize = Internal::x509_write_extensions_est_size(&ext);

		static constexpr size_t expSize =
			// val
			8 + // asn1_write_raw_buffer
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// critical
			0 +
			// oid
			3 + // asn1_write_raw_buffer
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// ext
			1 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_EQ(estSize, expSize);

		// clean up
		mbedtls_asn1_free_named_data(&ext);
	}
}

GTEST_TEST(TestInternalX509Helper, x509_write_name_est_size)
{
	{
		static constexpr char const testOid[] = "1.1.1.1.1";
		static constexpr char const testVal[] = "Test Val";
		mbedtls_asn1_named_data ext;
		ext.next = nullptr;

		ext.oid.p = static_cast<unsigned char*>(
			mbedtls_calloc(1, sizeof(testOid) - 1)
		);
		ext.oid.len = sizeof(testOid) - 1;
		std::memcpy(ext.oid.p, testOid, sizeof(testOid) - 1);

		ext.val.p = static_cast<unsigned char*>(
			mbedtls_calloc(1, sizeof(testVal) - 1)
		);
		ext.val.len = sizeof(testVal) - 1;
		std::memcpy(ext.val.p, testVal, sizeof(testVal) - 1);


		size_t estSize = Internal::x509_write_name_est_size(ext);

		static constexpr size_t expSize =
			// tagged string
			8 + // asn1_write_raw_buffer
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// oid
			9 + // asn1_write_raw_buffer
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// seq
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// set
			1 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_EQ(estSize, expSize);


		// clean up
		mbedtls_asn1_free_named_data(&ext);
	}
}

GTEST_TEST(TestInternalX509Helper, x509_write_names_est_size)
{
	{
		static constexpr char const testOid[] = "1.1.1.1.1";
		static constexpr char const testVal[] = "Test Val";
		mbedtls_asn1_named_data ext;
		ext.next = nullptr;

		ext.oid.p = static_cast<unsigned char*>(
			mbedtls_calloc(1, sizeof(testOid) - 1)
		);
		ext.oid.len = sizeof(testOid) - 1;
		std::memcpy(ext.oid.p, testOid, sizeof(testOid) - 1);

		ext.val.p = static_cast<unsigned char*>(
			mbedtls_calloc(1, sizeof(testVal) - 1)
		);
		ext.val.len = sizeof(testVal) - 1;
		std::memcpy(ext.val.p, testVal, sizeof(testVal) - 1);


		size_t estSize = Internal::x509_write_names_est_size(&ext);

		static constexpr size_t expSize =
			// tagged string
			8 + // asn1_write_raw_buffer
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// oid
			9 + // asn1_write_raw_buffer
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// seq
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// set
			1 + 1 + // asn1_write_len() + asn1_write_tag()
			// total
			1 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_EQ(estSize, expSize);


		// clean up
		mbedtls_asn1_free_named_data(&ext);
	}
}

GTEST_TEST(TestInternalX509Helper, x509_write_sig_est_size)
{
	{
		static constexpr char const testOid[] = "1.1.1.1.1";

		size_t estSize = Internal::x509_write_sig_est_size(
			testOid,
			sizeof(testOid) - 1,
			512
		);

		static constexpr size_t expSize =
			// sig
			512 + 1 + // sig
			3 + 1 + // asn1_write_len() + asn1_write_tag()
			// algorithm_identifier
			1 + 1 + // asn1_write_null()
			9 + 1 + 1 + // asn1_write_oid()
			1 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_EQ(estSize, expSize);
	}
}

GTEST_TEST(TestInternalX509Helper, x509_write_time_est_size)
{
	{
		static constexpr char const testTime[] = "20220101000000Z";

		size_t estSize = Internal::x509_write_time_est_size(
			testTime,
			sizeof(testTime) - 1
		);

		static constexpr size_t expSize =
			// time
			13 + // time
			1 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_EQ(estSize, expSize);
	}

	{
		static constexpr char const testTime[] = "20500101000000Z";

		size_t estSize = Internal::x509_write_time_est_size(
			testTime,
			sizeof(testTime) - 1
		);

		static constexpr size_t expSize =
			// time
			15 + // time
			1 + 1; // asn1_write_len() + asn1_write_tag()

		EXPECT_EQ(estSize, expSize);
	}

}

GTEST_TEST(TestInternalX509Helper, x509write_csr_der_est_size)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();
	std::vector<uint8_t> buf;

	// Key
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	mbedtls_pk_parse_key(
		&pk,
		reinterpret_cast<const unsigned char*>(GetTestEcPrivKeyPem().data()),
		GetTestEcPrivKeyPem().size(),
		nullptr,
		0,
		RbgInterface::CallBack,
		rand.get()
	);


	// Req
	mbedtls_x509write_csr req;
	mbedtls_x509write_csr_init(&req);

	mbedtls_x509write_csr_set_key(&req, &pk);
	mbedtls_x509write_csr_set_subject_name(&req, "CN=Test");
	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
	mbedtls_x509write_csr_set_key_usage(&req, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);


	// Estimate size
	size_t estSize = Internal::x509write_csr_der_est_size(req);
	buf.resize(estSize);

	// Actual size
	auto actSize = mbedtls_x509write_csr_der(
		&req,
		buf.data(),
		buf.size(),
		RbgInterface::CallBack,
		rand.get()
	);


	// Compare
	EXPECT_GT(actSize, 0);
	EXPECT_LE(actSize, estSize);


	// clean up
	mbedtls_pk_free(&pk);
	mbedtls_x509write_csr_free(&req);
}

GTEST_TEST(TestInternalX509Helper, x509write_crt_der_est_size)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();
	std::vector<uint8_t> buf;

	// Key
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	mbedtls_pk_parse_key(
		&pk,
		reinterpret_cast<const unsigned char*>(GetTestEcPrivKeyPem().data()),
		GetTestEcPrivKeyPem().size(),
		nullptr,
		0,
		RbgInterface::CallBack,
		rand.get()
	);


	// Cert
	mbedtls_x509write_cert crt;
	mbedtls_x509write_crt_init(&crt);

	mbedtls_x509write_crt_set_subject_key(&crt, &pk);
	mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
	mbedtls_x509write_crt_set_subject_name(&crt, "CN=Test");
	mbedtls_x509write_crt_set_issuer_name(&crt, "CN=Test");
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
	mbedtls_x509write_crt_set_validity(&crt, "20220101000000", "20500101000000");
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);


	// Estimate size
	size_t estSize = Internal::x509write_crt_der_est_size(crt);
	buf.resize(estSize);

	// Actual size
	auto actSize = mbedtls_x509write_crt_der(
		&crt,
		buf.data(),
		buf.size(),
		RbgInterface::CallBack,
		rand.get()
	);


	// Compare
	EXPECT_GT(actSize, 0);
	EXPECT_LE(actSize, estSize);


	// clean up
	mbedtls_pk_free(&pk);
	mbedtls_x509write_crt_free(&crt);
}
