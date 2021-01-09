#pragma once

#include <mbedtls/oid.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>

#include "Asn1Helper.hpp"
#include "PKeyHelper.hpp"

#include "../Exceptions.hpp"


/** ============================================================================
 *   PEM header and footer
 *  ============================================================================
 */



#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	namespace Internal
	{
		static constexpr char const PEM_BEGIN_CSR[] = "-----BEGIN CERTIFICATE REQUEST-----\n";
		static constexpr char const PEM_END_CSR[]   = "-----END CERTIFICATE REQUEST-----\n";

		static constexpr size_t PEM_CSR_HEADER_SIZE = sizeof(PEM_BEGIN_CSR) - 1;
		static constexpr size_t PEM_CSR_FOOTER_SIZE = sizeof(PEM_END_CSR) - 1;

		static constexpr char const PEM_BEGIN_CRL[] = "-----BEGIN X509 CRL-----\n";
		static constexpr char const PEM_END_CRL[]   = "-----END X509 CRL-----\n";

		static constexpr size_t PEM_CRL_HEADER_SIZE = sizeof(PEM_BEGIN_CRL) - 1;
		static constexpr size_t PEM_CRL_FOOTER_SIZE = sizeof(PEM_END_CRL) - 1;

		static constexpr char const PEM_BEGIN_CRT[] = "-----BEGIN CERTIFICATE-----\n";
		static constexpr char const PEM_END_CRT[]   = "-----END CERTIFICATE-----\n";

		static constexpr size_t PEM_CRT_HEADER_SIZE = sizeof(PEM_BEGIN_CRT) - 1;
		static constexpr size_t PEM_CRT_FOOTER_SIZE = sizeof(PEM_END_CRT) - 1;
	}
}





/** ============================================================================
 *   General part
 *  ============================================================================
 */



#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	namespace Internal
	{
		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t x509_write_extension_est_size_p1(const mbedtls_asn1_named_data& ext)
		{
			return asn1_write_raw_buffer_est_size(ext.val.p + 1, ext.val.len - 1) +
				asn1_write_len_est_size(ext.val.len - 1) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_OCTET_STRING) +

				((ext.val.p[0] != 0) ? asn1_write_bool_est_size(1) : 0) +

				asn1_write_raw_buffer_est_size(ext.oid.p, ext.oid.len) +
				asn1_write_len_est_size(ext.oid.len) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_OID);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t x509_write_extension_est_size(const mbedtls_asn1_named_data& ext)
		{
			return x509_write_extension_est_size_p1(ext) +
				asn1_write_len_est_size(x509_write_extension_est_size_p1(ext)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline size_t x509_write_extensions_est_size(const mbedtls_asn1_named_data* first)
		{
			size_t len = 0;
			const mbedtls_asn1_named_data *cur_ext = first;

			while (cur_ext != NULL)
			{
				len += x509_write_extension_est_size(*cur_ext);
				cur_ext = cur_ext->next;
			}

			return len;
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t x509_write_name_est_size_p1(const mbedtls_asn1_named_data& cur_name)
		{
			//const char *oid = (const char*)cur_name.oid.p;
			//size_t oid_len = cur_name.oid.len;
			//const unsigned char *name = cur_name.val.p;
			//size_t name_len = cur_name.val.len;

			// Write correct string tag and value
			return asn1_write_tagged_string_est_size(cur_name.val.tag, cur_name.val.p, cur_name.val.len) +
			// Write OID
			//
			asn1_write_oid_est_size(cur_name.oid.p, cur_name.oid.len);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t x509_write_name_est_size_p2(const mbedtls_asn1_named_data& cur_name)
		{
			return x509_write_name_est_size_p1(cur_name) +

			asn1_write_len_est_size(x509_write_name_est_size_p1(cur_name)) +
			asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t x509_write_name_est_size(const mbedtls_asn1_named_data& cur_name)
		{
			return x509_write_name_est_size_p2(cur_name) +

			asn1_write_len_est_size(x509_write_name_est_size_p2(cur_name)) +
			asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline size_t x509_write_names_est_size(const mbedtls_asn1_named_data* first)
		{
			size_t len = 0;
			const mbedtls_asn1_named_data *cur = first;

			while (cur != NULL)
			{
				len += x509_write_name_est_size(*cur);
				cur = cur->next;
			}

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			return len;
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t x509_write_sig_est_size(const char *oid, size_t oid_len, size_t sig_len)
		{
			return (sig_len + 1) +
				asn1_write_len_est_size((sig_len + 1)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_BIT_STRING) +
				asn1_write_algorithm_identifier_est_size(oid, oid_len, 0);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t x509_write_time_est_size(const char *t, size_t size)
		{
			return
				/*
				 * write MBEDTLS_ASN1_UTC_TIME if year < 2050 (2 bytes shorter)
				 */
				(t[0] == '2' && t[1] == '0' && t[2] < '5') ?
					(
						asn1_write_raw_buffer_est_size(t + 2, size - 2) +
						asn1_write_len_est_size(asn1_write_raw_buffer_est_size(t + 2, size - 2)) +
						asn1_write_tag_est_size(MBEDTLS_ASN1_UTC_TIME)
					) :
					(
						asn1_write_raw_buffer_est_size(t, size) +
						asn1_write_len_est_size(asn1_write_raw_buffer_est_size(t, size)) +
						asn1_write_tag_est_size(MBEDTLS_ASN1_GENERALIZED_TIME)
					);
		}
	}
}





/** ============================================================================
 *   Req part
 *  ============================================================================
 */



#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	namespace Internal
	{
		/**
		 * @brief Estimate the memory space needed to store DER encoded X509 request.
		 *
		 * @param ctx The context.
		 *
		 * @exception mbedTLSRuntimeError
		 * @exception InvalidArgumentException
		 *
		 * @return A size_t.
		 */
		inline size_t x509write_csr_der_est_size(const mbedtls_x509write_csr& ctx)
		{
			const char *sig_oid;
			size_t sig_oid_len = 0;
			size_t pub_len = 0, sig_and_oid_len = 0;
			size_t len = 0;
			mbedtls_pk_type_t pk_alg;

			if (mbedtls_pk_can_do(ctx.key, MBEDTLS_PK_RSA))
				pk_alg = MBEDTLS_PK_RSA;
			else if (mbedtls_pk_can_do(ctx.key, MBEDTLS_PK_ECDSA))
				pk_alg = MBEDTLS_PK_ECDSA;
			else
				throw InvalidArgumentException("mbedTLScpp::Internal::x509write_csr_der_est_size - The algorithm of mbedtls_x509write_csr object's key is invalid.");

			/*
			* Prepare data to be signed in tmp_buf
			*/

			len += x509_write_extensions_est_size(ctx.extensions);

			if (len)
			{
				len += asn1_write_len_est_size(len);
				len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

				len += asn1_write_len_est_size(len);
				len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);

				len += asn1_write_oid_est_size(MBEDTLS_OID_PKCS9_CSR_EXT_REQ, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS9_CSR_EXT_REQ));

				len += asn1_write_len_est_size(len);
				len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
			}

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);

			len += pk_write_pubkey_der_est_size(*ctx.key);

			/*
			*  Subject  ::=  Name
			*/
			len += x509_write_names_est_size(ctx.subject);

			/*
			*  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
			*/
			len += asn1_write_int_est_size(0);

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			/*
			* Prepare signature
			*/
			const size_t hashLen = mbedtls_md_get_size(mbedtls_md_info_from_type(ctx.md_alg));

			const size_t signLen = pk_write_sign_der_est_max_size(*ctx.key, hashLen);

			MBEDTLSCPP_MAKE_C_FUNC_CALL(mbedTLScpp::Internal::x509write_csr_der_est_size,
				mbedtls_oid_get_oid_by_sig_alg, pk_alg, ctx.md_alg, &sig_oid, &sig_oid_len);

			/*
			* Write data to output buffer
			*/
			sig_and_oid_len += x509_write_sig_est_size(sig_oid, sig_oid_len, signLen);

			len += sig_and_oid_len;
			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			return len;
		}
	}
}





/** ============================================================================
 *   Cert part
 *  ============================================================================
 */



#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	namespace Internal
	{
		/**
		 * @brief Estimate the memory space needed to store DER encoded X509 certificate.
		 *
		 * @param ctx The context.
		 *
		 * @exception mbedTLSRuntimeError
		 * @exception InvalidArgumentException
		 *
		 * @return A size_t.
		 */
		inline size_t x509write_crt_der_est_size(const mbedtls_x509write_cert& ctx)
		{
			const char *sig_oid;
			size_t sig_oid_len = 0;
			size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len = 0;
			size_t len = 0;
			mbedtls_pk_type_t pk_alg;

			/* Signature algorithm needed in TBS, and later for actual signature */

			/* There's no direct way of extracting a signature algorithm
			* (represented as an element of mbedtls_pk_type_t) from a PK instance. */
			if (mbedtls_pk_can_do(ctx.issuer_key, MBEDTLS_PK_RSA))
				pk_alg = MBEDTLS_PK_RSA;
			else if (mbedtls_pk_can_do(ctx.issuer_key, MBEDTLS_PK_ECDSA))
				pk_alg = MBEDTLS_PK_ECDSA;
			else
				throw InvalidArgumentException("mbedTLScpp::Internal::x509write_crt_der_est_size - The algorithm of mbedtls_x509write_cert issuer_key's key is invalid.");

			if (ctx.subject_key == nullptr)
			{
				throw InvalidArgumentException("mbedTLScpp::Internal::x509write_crt_der_est_size - mbedtls_x509write_cert's pointer to subject key is NULL.");
			}

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				x509write_crt_der_est_size,
				mbedtls_oid_get_oid_by_sig_alg, pk_alg, ctx.md_alg, &sig_oid, &sig_oid_len);

			/*
			*  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
			*/

			/* Only for v3 */
			if (ctx.version == MBEDTLS_X509_CRT_VERSION_3)
			{
				len += x509_write_extensions_est_size(ctx.extensions);
				len += asn1_write_len_est_size(len);
				len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
				len += asn1_write_len_est_size(len);
				len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 3);
			}

			/*
			*  SubjectPublicKeyInfo
			*/
			pub_len = pk_write_pubkey_der_est_size(*ctx.subject_key);;
			len += pub_len;

			/*
			*  Subject  ::=  Name
			*/
			len += x509_write_names_est_size(ctx.subject);

			/*
			*  Validity ::= SEQUENCE {
			*       notBefore      Time,
			*       notAfter       Time }
			*/
			sub_len = 0;

			sub_len += x509_write_time_est_size(ctx.not_after, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);

			sub_len += x509_write_time_est_size(ctx.not_before, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);

			len += sub_len;
			len += asn1_write_len_est_size(sub_len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			/*
			*  Issuer  ::=  Name
			*/
			len += x509_write_names_est_size(ctx.issuer);

			/*
			*  Signature   ::=  AlgorithmIdentifier
			*/
			len += asn1_write_algorithm_identifier_est_size(sig_oid, strlen(sig_oid), 0);

			/*
			*  Serial   ::=  INTEGER
			*/
			len += asn1_write_mpi_est_size(ctx.serial);

			/*
			*  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
			*/

			/* Can be omitted for v1 */
			if (ctx.version != MBEDTLS_X509_CRT_VERSION_1)
			{
				sub_len = 0;
				sub_len += asn1_write_int_est_size(ctx.version);
				len += sub_len;
				len += asn1_write_len_est_size(sub_len);
				len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0);
			}

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			/*
			* Make signature
			*/

			/* Compute hash of CRT. */
			sig_len = pk_write_sign_der_est_max_size(*ctx.issuer_key, mbedtls_md_get_size(mbedtls_md_info_from_type(ctx.md_alg)));


			/* Add signature at the end of the buffer,
			* making sure that it doesn't underflow
			* into the CRT buffer. */
			sig_and_oid_len += x509_write_sig_est_size(sig_oid, sig_oid_len, sig_len);

			/*
			* Memory layout after this step:
			*
			* buf       c=buf+len                c2            buf+size
			* [CRT0,...,CRTn, UNUSED, ..., UNUSED, SIG0, ..., SIGm]
			*/

			/* Move raw CRT to just before the signature. */

			len += sig_and_oid_len;
			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			return len;
		}
	}
}
