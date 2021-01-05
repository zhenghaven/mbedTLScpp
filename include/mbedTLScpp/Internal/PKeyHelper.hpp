#pragma once

#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/ecp.h>

#include "Asn1Helper.hpp"

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
		constexpr char const PEM_BEGIN_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n";
		constexpr char const PEM_END_PUBLIC_KEY[]   = "-----END PUBLIC KEY-----\n";

		constexpr size_t PEM_PUBLIC_HEADER_SIZE = sizeof(PEM_BEGIN_PUBLIC_KEY) - 1;
		constexpr size_t PEM_PUBLIC_FOOTER_SIZE = sizeof(PEM_END_PUBLIC_KEY) - 1;

		constexpr char const PEM_BEGIN_PRIVATE_KEY_EC[] = "-----BEGIN EC PRIVATE KEY-----\n";
		constexpr char const PEM_END_PRIVATE_KEY_EC[]   = "-----END EC PRIVATE KEY-----\n";

		constexpr size_t PEM_EC_PRIVATE_HEADER_SIZE = sizeof(PEM_BEGIN_PRIVATE_KEY_EC) - 1;
		constexpr size_t PEM_EC_PRIVATE_FOOTER_SIZE = sizeof(PEM_END_PRIVATE_KEY_EC) - 1;

		constexpr char const PEM_BEGIN_PRIVATE_KEY_RSA[] = "-----BEGIN RSA PRIVATE KEY-----\n";
		constexpr char const PEM_END_PRIVATE_KEY_RSA[]   = "-----END RSA PRIVATE KEY-----\n";

		constexpr size_t PEM_RSA_PRIVATE_HEADER_SIZE = sizeof(PEM_BEGIN_PRIVATE_KEY_RSA) - 1;
		constexpr size_t PEM_RSA_PRIVATE_FOOTER_SIZE = sizeof(PEM_END_PRIVATE_KEY_RSA) - 1;
	}
}


/** ============================================================================
 *   RSA part
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
		inline size_t pk_write_rsa_pubkey_asn1_est_size(const mbedtls_rsa_context& rsa)
		{
			size_t len = 0;

			/* Export E */
			len += asn1_write_mpi_est_size(rsa.E);

			/* Export N */
			len += asn1_write_mpi_est_size(rsa.N);

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
		inline size_t pk_write_rsa_prvkey_der_est_size(const mbedtls_rsa_context& rsa)
		{
			size_t len = 0;
			/*
			 * Export the parameters one after another to avoid simultaneous copies.
			 */

			/* Export QP */
			len += asn1_write_mpi_est_size(rsa.QP);

			/* Export DQ */
			len += asn1_write_mpi_est_size(rsa.DQ);

			/* Export DP */
			len += asn1_write_mpi_est_size(rsa.DP);

			/* Export Q */
			len += asn1_write_mpi_est_size(rsa.Q);

			/* Export P */
			len += asn1_write_mpi_est_size(rsa.P);

			/* Export D */
			len += asn1_write_mpi_est_size(rsa.D);

			/* Export E */
			len += asn1_write_mpi_est_size(rsa.E);

			/* Export N */
			len += asn1_write_mpi_est_size(rsa.N);

			len += asn1_write_int_est_size(0);
			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			return len;
		}
	}
}



/** ============================================================================
 *   ECP part
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
		inline size_t ecp_point_write_binary_est_size(
			const mbedtls_ecp_group& grp, const mbedtls_ecp_point& P, int format)
		{
			/*
			 * Common case: P == 0
			 */
			if (mbedtls_mpi_cmp_int(&P.Z, 0) == 0)
			{
				return 1;
			}

			size_t plen = mbedtls_mpi_size(&grp.P);

			if (format == MBEDTLS_ECP_PF_UNCOMPRESSED)
			{
				return 2 * plen + 1;
			}
			else if (format == MBEDTLS_ECP_PF_COMPRESSED)
			{
				return plen + 1;
			}

			throw InvalidArgumentException("mbedTLScpp::Internal::ecp_point_write_binary_est_size - Invalid ECP format is given.");
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline size_t pk_write_ec_pubkey_asn1_est_size(const mbedtls_ecp_keypair& ec)
		{
			return ecp_point_write_binary_est_size(ec.grp, ec.Q,
				MBEDTLS_ECP_PF_UNCOMPRESSED);
		}

		/**
		 * @brief
		 *
		 * @exception mbedTLSRuntimeError
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline size_t pk_write_ec_param_est_size(const mbedtls_ecp_keypair& ec)
		{
			const char *oid;
			size_t oid_len;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(mbedTLScpp::Internal::pk_write_ec_param_est_size,
				mbedtls_oid_get_oid_by_ec_grp, ec.grp.id, &oid, &oid_len);

			return asn1_write_oid_est_size(oid, oid_len);
		}

		/**
		 * @brief
		 *
		 * @exception mbedTLSRuntimeError
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline size_t pk_write_ec_prvkey_der_est_size(const mbedtls_ecp_keypair& ec)
		{
			size_t len = 0;
			size_t pub_len = 0, par_len = 0;

			/* publicKey */
			pub_len += pk_write_ec_pubkey_asn1_est_size(ec);

			pub_len += 1;

			pub_len += asn1_write_len_est_size(pub_len);
			pub_len += asn1_write_tag_est_size(MBEDTLS_ASN1_BIT_STRING);

			pub_len += asn1_write_len_est_size(pub_len);
			pub_len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1);
			len += pub_len;

			/* parameters */
			par_len += pk_write_ec_param_est_size(ec);

			par_len += asn1_write_len_est_size(par_len);
			par_len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0);
			len += par_len;

			/* privateKey: write as MPI then fix tag */
			len += asn1_write_mpi_est_size(ec.d);

			/* version */
			len += asn1_write_int_est_size(1);

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
		inline constexpr size_t ec_signature_to_asn1_est_max_size(size_t rMaxSize, size_t sMaxSize)
		{
			return
				(asn1_write_mpi_est_max_size(sMaxSize) + asn1_write_mpi_est_max_size(rMaxSize)) +
				asn1_write_len_est_size(asn1_write_mpi_est_max_size(sMaxSize) + asn1_write_mpi_est_max_size(rMaxSize)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		}
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
		 * @param key
		 *
		 * @exception mbedTLSRuntimeError
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline size_t pk_write_pubkey_asn1_est_size(const mbedtls_pk_context& key)
		{
			if (key.pk_ctx == nullptr)
			{
				throw InvalidArgumentException("mbedTLScpp::Internal::pk_write_pubkey_est_size - An empty Pkey context is given.");
			}

#if defined(MBEDTLS_RSA_C)
			if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_RSA)
				return pk_write_rsa_pubkey_asn1_est_size(*mbedtls_pk_rsa(key));
			else
#endif
#if defined(MBEDTLS_ECP_C)
			if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY)
				return pk_write_ec_pubkey_asn1_est_size(*mbedtls_pk_ec(key));
			else
#endif
				throw InvalidArgumentException("mbedTLScpp::Internal::pk_write_pubkey_est_size - Invalid PKey type is given.");
		}

		inline size_t pk_write_pubkey_der_est_size(const mbedtls_pk_context& key)
		{
			size_t len = 0, par_len = 0, oid_len = 0;
			const char *oid;

			len += pk_write_pubkey_asn1_est_size(key);

			/*
			 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
			 *       algorithm            AlgorithmIdentifier,
			 *       subjectPublicKey     BIT STRING }
			 */

			len += 1;

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_BIT_STRING);

			MBEDTLSCPP_MAKE_C_FUNC_CALL(mbedTLScpp::Internal::pk_write_pubkey_der_est_size,
				mbedtls_oid_get_oid_by_pk_alg, mbedtls_pk_get_type(&key), &oid, &oid_len);

#if defined(MBEDTLS_ECP_C)
			if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY)
			{
				par_len += pk_write_ec_param_est_size(*mbedtls_pk_ec(key));
			}
#endif

			len += asn1_write_algorithm_identifier_est_size(oid, oid_len, par_len);

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			return len;
		}

		inline size_t pk_write_prvkey_der_est_size(const mbedtls_pk_context& key)
		{
			size_t len = 0;

			if (key.pk_ctx == nullptr)
			{
				throw InvalidArgumentException("mbedTLScpp::Internal::pk_write_prvkey_der_est_size - An empty Pkey context is given.");
			}

#if defined(MBEDTLS_RSA_C)
			if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_RSA)
			{
				len = pk_write_rsa_prvkey_der_est_size(*mbedtls_pk_rsa(key));
			}
			else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
			if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY)
			{
				len = pk_write_ec_prvkey_der_est_size(*mbedtls_pk_ec(key));
			}
			else
#endif /* MBEDTLS_ECP_C */
			throw InvalidArgumentException("mbedTLScpp::Internal::pk_write_prvkey_der_est_size - Invalid PKey type is given.");

			return len;
		}

		inline size_t pk_write_sign_der_est_max_size(const mbedtls_pk_context& key, size_t hashLenInBytes)
		{
			if (key.pk_ctx == nullptr)
			{
				throw InvalidArgumentException("mbedTLScpp::Internal::pk_write_sign_der_est_size - An empty Pkey context is given.");
			}

			switch (mbedtls_pk_get_type(&key))
			{
			case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY:
			case mbedtls_pk_type_t::MBEDTLS_PK_ECDSA:
			{
				const mbedtls_ecp_keypair& ec = *mbedtls_pk_ec(key);

				size_t nBytes = (ec.grp.nbits + 7) >> 3; // refer to mbedtls_mpi_size

				return ec_signature_to_asn1_est_max_size(nBytes, nBytes);
			}
			case mbedtls_pk_type_t::MBEDTLS_PK_RSA:
			{
				const mbedtls_rsa_context* rsa = static_cast<const mbedtls_rsa_context*>(key.pk_ctx);
				return mbedtls_rsa_get_len(rsa);
			}
			case mbedtls_pk_type_t::MBEDTLS_PK_RSA_ALT:
			{
				const mbedtls_rsa_alt_context* rsa_alt = static_cast<const mbedtls_rsa_alt_context*>(key.pk_ctx);
				return rsa_alt->key_len_func(rsa_alt->key);
			}
			case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY_DH:
			case mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS:
			case mbedtls_pk_type_t::MBEDTLS_PK_NONE:
			default:
				throw InvalidArgumentException("mbedTLScpp::Internal::pk_write_sign_der_est_size - The given key type is not supported.");
			}
		}
	}
}
