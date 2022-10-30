// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <gtest/gtest.h>

#include <mbedtls/oid.h>
#include <mbedtls/x509.h>

#include <mbedTLScpp/Internal/Asn1Helper.hpp>


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

GTEST_TEST(TestInternalAsn1Helper, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

//==============================================================================
// ASN.1 DeepCopy functions
//==============================================================================

GTEST_TEST(TestInternalAsn1Helper, Asn1DeepCopyBuf)
{
	// copy null to non-null
	{
		mbedtls_asn1_buf src;
		src.p = nullptr;
		src.len = 0;
		src.tag = 0;

		mbedtls_asn1_buf dst;
		dst.p = static_cast<unsigned char *>(mbedtls_calloc(1, 1));
		dst.len = 1;
		dst.tag = 1;

		Internal::Asn1DeepCopy(dst, src);

		EXPECT_EQ(dst.p, nullptr);
		EXPECT_EQ(dst.len, 0);
		EXPECT_EQ(dst.tag, 0);

		// clean up
		// nothing to clean up
	}

	// copy some data to null
	{
		static constexpr const char srcData[] = "Hello World!";
		mbedtls_asn1_buf src;
		src.p = static_cast<unsigned char *>(
			mbedtls_calloc(sizeof(srcData), 1)
		);
		src.len = sizeof(srcData);
		src.tag = 1;
		std::memcpy(src.p, srcData, sizeof(srcData));


		mbedtls_asn1_buf dst;
		dst.p = nullptr;
		dst.len = 0;
		dst.tag = 0;


		Internal::Asn1DeepCopy(dst, src);


		EXPECT_NE(dst.p, nullptr);
		EXPECT_EQ(dst.len, sizeof(srcData));
		EXPECT_EQ(dst.tag, 1);
		EXPECT_EQ(std::memcmp(dst.p, srcData, sizeof(srcData)), 0);


		// clean up
		mbedtls_free(src.p);
		mbedtls_free(dst.p);
	}
}


GTEST_TEST(TestInternalAsn1Helper, Asn1DeepCopyNamedDataList)
{
	// copy null to non-null
	{
		mbedtls_asn1_named_data* src = nullptr;
		mbedtls_asn1_named_data* dst = nullptr;

		auto res = mbedtls_x509_string_to_names(
			&dst,
			"CN=www.example.com,OU=IT,O=Example"
		);
		ASSERT_EQ(res, 0);

		Internal::Asn1DeepCopy(dst, src);

		EXPECT_EQ(dst, nullptr);
	}

	// copy some data to null
	{
		mbedtls_asn1_named_data* src = nullptr;
		mbedtls_asn1_named_data* dst = nullptr;

		auto res = mbedtls_x509_string_to_names(
			&src,
			"CN=www.example.com,OU=IT,O=Example"
		);
		ASSERT_EQ(res, 0);


		Internal::Asn1DeepCopy(dst, src);


		size_t numOfNames = 0;
		const mbedtls_asn1_named_data* srcCur = src;
		const mbedtls_asn1_named_data* dstCur = dst;
		while (srcCur != nullptr && dstCur != nullptr)
		{
			EXPECT_EQ(srcCur->oid.len, dstCur->oid.len);
			EXPECT_EQ(srcCur->oid.tag, dstCur->oid.tag);
			EXPECT_EQ(
				std::memcmp(srcCur->oid.p, dstCur->oid.p, srcCur->oid.len),
				0
			);

			EXPECT_EQ(srcCur->val.len, dstCur->val.len);
			EXPECT_EQ(srcCur->val.tag, dstCur->val.tag);
			EXPECT_EQ(
				std::memcmp(srcCur->val.p, dstCur->val.p, srcCur->val.len),
				0
			);

			srcCur = srcCur->next;
			dstCur = dstCur->next;
			++numOfNames;
		}
		EXPECT_EQ(numOfNames, 3);


		// clean up
		mbedtls_asn1_free_named_data_list(&src);
		mbedtls_asn1_free_named_data_list(&dst);
	}
}

//==============================================================================
// ASN.1 Write size estimation functions
//==============================================================================

GTEST_TEST(TestInternalAsn1Helper, asn1_write_len_est_size)
{
	EXPECT_EQ(Internal::asn1_write_len_est_size(      0x00U), 1);
	EXPECT_EQ(Internal::asn1_write_len_est_size(      0xFFU), 2);
	EXPECT_EQ(Internal::asn1_write_len_est_size(    0xFFFFU), 3);
	EXPECT_EQ(Internal::asn1_write_len_est_size(  0xFFFFFFU), 4);
	EXPECT_EQ(Internal::asn1_write_len_est_size(0xFFFFFFFFU), 5);
#if SIZE_MAX > 0xFFFFFFFFU
	EXPECT_THROW(
		Internal::asn1_write_len_est_size(0x100000000U),
		InvalidArgumentException
	);
#endif
}

GTEST_TEST(TestInternalAsn1Helper, asn1_write_tag_est_size)
{
	EXPECT_EQ(Internal::asn1_write_tag_est_size(MBEDTLS_ASN1_UTF8_STRING), 1);
	EXPECT_EQ(Internal::asn1_write_tag_est_size(MBEDTLS_ASN1_BIT_STRING), 1);
}

GTEST_TEST(TestInternalAsn1Helper, asn1_write_null_est_size)
{
	EXPECT_EQ(Internal::asn1_write_null_est_size(), 2);
}

GTEST_TEST(TestInternalAsn1Helper, asn1_write_bool_est_size)
{
	EXPECT_EQ(Internal::asn1_write_bool_est_size(0), 3);
	EXPECT_EQ(Internal::asn1_write_bool_est_size(1), 3);
	EXPECT_EQ(Internal::asn1_write_bool_est_size(128), 3);
}

GTEST_TEST(TestInternalAsn1Helper, asn1_write_int_est_size)
{
	static constexpr size_t sizeOfInt = sizeof(int);

	EXPECT_EQ(Internal::asn1_write_int_est_size_est_val_len(0), sizeOfInt + 1);
	EXPECT_EQ(Internal::asn1_write_int_est_size_est_val_len(1), sizeOfInt + 1);

	EXPECT_EQ(
		Internal::asn1_write_int_est_size(0xFFFFF),
		sizeOfInt + 1 +
		1 + // <==> Internal::asn1_write_len_est_size(sizeOfInt + 1) +
		1   // <==> Internal::asn1_write_tag_est_size(MBEDTLS_ASN1_INTEGER)
	);
}

GTEST_TEST(TestInternalAsn1Helper, asn1_write_oid_est_size)
{
	const std::string testOid = MBEDTLS_OID_AT_CN;

	EXPECT_EQ(
		Internal::asn1_write_oid_est_size(testOid.data(), testOid.size()),
		testOid.size() +
		1 + // <==> Internal::asn1_write_len_est_size(testOid.size() + 1) +
		1   // <==> Internal::asn1_write_tag_est_size(MBEDTLS_ASN1_OID)
	);
}

GTEST_TEST(TestInternalAsn1Helper, asn1_write_mpi_est_size)
{
	EXPECT_EQ(
		Internal::asn1_write_mpi_est_size_given_mpi_size(16), // 16 bytes BigNum
		16 + 1 +
		1 + // <==> Internal::asn1_write_len_est_size(16 + 1) +
		1   // <==> Internal::asn1_write_tag_est_size(MBEDTLS_ASN1_INTEGER)
	);

	mbedtls_mpi mpi;
	mbedtls_mpi_init(&mpi);
	mbedtls_mpi_read_string(&mpi, 16, "1234567890ABCDEF");

	EXPECT_EQ(
		Internal::asn1_write_mpi_est_size(mpi),
		8 + 1 +
		1 + // <==> Internal::asn1_write_len_est_size(8 + 1) +
		1   // <==> Internal::asn1_write_tag_est_size(MBEDTLS_ASN1_INTEGER)
	);

	// clean up
	mbedtls_mpi_free(&mpi);
}

GTEST_TEST(TestInternalAsn1Helper, asn1_write_algorithm_identifier_est_size)
{
	const std::string testOid = MBEDTLS_OID_PKCS1_RSA;

	static constexpr size_t sizeOfParam = 100;
	EXPECT_EQ(
		Internal::asn1_write_algorithm_identifier_est_size(
			testOid.data(),
			testOid.size(),
			sizeOfParam
		),
		sizeOfParam +
		(testOid.size() + 1 + 1) +
			// <==> Internal::asn1_write_oid_est_size(
			//		testOid.data(), testOid.size()) +
		1 + // <==> Internal::asn1_write_len_est_size(...) +
		1   // <==> Internal::asn1_write_tag_est_size(...)
	);


	EXPECT_EQ(
		Internal::asn1_write_algorithm_identifier_est_size(
			testOid.data(),
			testOid.size(),
			0
		),
		2 + // <==> Internal::asn1_write_null_est_size() +
		(testOid.size() + 1 + 1) +
			// <==> Internal::asn1_write_oid_est_size(
			//		testOid.data(), testOid.size()) +
		1 + // <==> Internal::asn1_write_len_est_size(...) +
		1   // <==> Internal::asn1_write_tag_est_size(...)
	);
}

GTEST_TEST(TestInternalAsn1Helper, asn1_write_tagged_string_est_size)
{
	const std::string testString = "test string";

	EXPECT_EQ(
		Internal::asn1_write_tagged_string_est_size(
			MBEDTLS_ASN1_UTF8_STRING,
			testString.data(),
			testString.size()
		),
		testString.size() +
		1 + // <==> Internal::asn1_write_len_est_size(testString.size()) +
		1   // <==> Internal::asn1_write_tag_est_size(MBEDTLS_ASN1_UTF8_STRING)
	);
}
