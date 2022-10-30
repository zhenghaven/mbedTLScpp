// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
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

// constexpr char const PEM_BEGIN_PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n";
// constexpr char const PEM_END_PUBLIC_KEY[]   = "-----END PUBLIC KEY-----\n";

// constexpr size_t PEM_PUBLIC_HEADER_SIZE = sizeof(PEM_BEGIN_PUBLIC_KEY) - 1;
// constexpr size_t PEM_PUBLIC_FOOTER_SIZE = sizeof(PEM_END_PUBLIC_KEY) - 1;

// constexpr char const PEM_BEGIN_PRIVATE_KEY_EC[] = "-----BEGIN EC PRIVATE KEY-----\n";
// constexpr char const PEM_END_PRIVATE_KEY_EC[]   = "-----END EC PRIVATE KEY-----\n";

// constexpr size_t PEM_EC_PRIVATE_HEADER_SIZE = sizeof(PEM_BEGIN_PRIVATE_KEY_EC) - 1;
// constexpr size_t PEM_EC_PRIVATE_FOOTER_SIZE = sizeof(PEM_END_PRIVATE_KEY_EC) - 1;

// constexpr char const PEM_BEGIN_PRIVATE_KEY_RSA[] = "-----BEGIN RSA PRIVATE KEY-----\n";
// constexpr char const PEM_END_PRIVATE_KEY_RSA[]   = "-----END RSA PRIVATE KEY-----\n";

// constexpr size_t PEM_RSA_PRIVATE_HEADER_SIZE = sizeof(PEM_BEGIN_PRIVATE_KEY_RSA) - 1;
// constexpr size_t PEM_RSA_PRIVATE_FOOTER_SIZE = sizeof(PEM_END_PRIVATE_KEY_RSA) - 1;

} // namespace Internal
} // namespace mbedTLScpp





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

	// The size of each key component can be found at:
	// https://docs.cossacklabs.com/themis/spec/asymmetric-keypairs/rsa/

	size_t modSize = mbedtls_rsa_get_len(&rsa);
	static constexpr size_t pubExpSize = 4;

	/* Export E */
	len += asn1_write_mpi_est_size_given_mpi_size(pubExpSize);

	/* Export N */
	len += asn1_write_mpi_est_size_given_mpi_size(modSize);

	len += asn1_write_len_est_size(len);
	len += asn1_write_tag_est_size(
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE
	);

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

	// The size of each key component can be found at:
	// https://docs.cossacklabs.com/themis/spec/asymmetric-keypairs/rsa/

	size_t modSize = mbedtls_rsa_get_len(&rsa);
	static constexpr size_t pubExpSize = 4;

	/*
	* Export the parameters one after another to avoid simultaneous copies.
	*/

	/* Export QP */
	len += asn1_write_mpi_est_size_given_mpi_size(modSize/ 2);

	/* Export DQ */
	len += asn1_write_mpi_est_size_given_mpi_size(modSize/ 2);

	/* Export DP */
	len += asn1_write_mpi_est_size_given_mpi_size(modSize/ 2);

	/* Export Q */
	len += asn1_write_mpi_est_size_given_mpi_size(modSize/ 2);

	/* Export P */
	len += asn1_write_mpi_est_size_given_mpi_size(modSize/ 2);

	/* Export D */
	len += asn1_write_mpi_est_size_given_mpi_size(modSize);

	/* Export E */
	len += asn1_write_mpi_est_size_given_mpi_size(pubExpSize);

	/* Export N */
	len += asn1_write_mpi_est_size_given_mpi_size(modSize);

	len += asn1_write_int_est_size(0);
	len += asn1_write_len_est_size(len);
	len += asn1_write_tag_est_size(
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE
	);

	return len;
}

} // namespace mbedTLScpp
} // namespace Internal





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
	const mbedtls_ecp_group& grp,
	int format
)
{
	size_t plen = mbedtls_mpi_size(&grp.P);

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
	if(mbedtls_ecp_get_type(&grp) == MBEDTLS_ECP_TYPE_MONTGOMERY)
	{
		(void) format; /* Montgomery curves always use the same point format */
		return plen;
	}
#endif

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
	if(mbedtls_ecp_get_type(&grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS)
	{
		/*
		* Common case: P == 0
		*/
		// P.Z became a private field,
		// and we only need to get a estimate on size
		// if (mbedtls_mpi_cmp_int(&P.Z, 0) == 0)
		// {
		// 	return 1;
		// }

		if (format == MBEDTLS_ECP_PF_UNCOMPRESSED)
		{
			return 2 * plen + 1;
		}
		else if (format == MBEDTLS_ECP_PF_COMPRESSED)
		{
			return plen + 1;
		}
	}
#endif

	throw InvalidArgumentException(
		"mbedTLScpp::Internal::ecp_point_write_binary_est_size"
		" - Invalid ECP format is given."
	);
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
	return ecp_point_write_binary_est_size(
		ec.MBEDTLS_PRIVATE(grp), // we have to access group info via private
		MBEDTLS_ECP_PF_UNCOMPRESSED
	);
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

	// we have to access group info via private
	const mbedtls_ecp_group& grp = ec.MBEDTLS_PRIVATE(grp);

	MBEDTLSCPP_MAKE_C_FUNC_CALL(
		Internal::pk_write_ec_param_est_size,
		mbedtls_oid_get_oid_by_ec_grp,
		grp.id,
		&oid,
		&oid_len
	);

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

	// we have to access group info via private
	const mbedtls_ecp_group& grp = ec.MBEDTLS_PRIVATE(grp);
	size_t plen = mbedtls_mpi_size(&grp.P);

	/* publicKey */
	pub_len += pk_write_ec_pubkey_asn1_est_size(ec);

	pub_len += 1;

	pub_len += asn1_write_len_est_size(pub_len);
	pub_len += asn1_write_tag_est_size(MBEDTLS_ASN1_BIT_STRING);

	pub_len += asn1_write_len_est_size(pub_len);
	pub_len += asn1_write_tag_est_size(
		MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1
	);
	len += pub_len;

	/* parameters */
	par_len += pk_write_ec_param_est_size(ec);

	par_len += asn1_write_len_est_size(par_len);
	par_len += asn1_write_tag_est_size(
		MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0
	);
	len += par_len;

	/* privateKey: write as MPI then fix tag */
	len += asn1_write_mpi_est_size_given_mpi_size(plen);

	/* version */
	len += asn1_write_int_est_size(1);

	len += asn1_write_len_est_size(len);
	len += asn1_write_tag_est_size(
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE
	);

	return len;
}


/**
 * @brief
 *
 * @exception InvalidArgumentException
 *
 * @return size_t
 */
inline constexpr size_t ec_signature_to_asn1_est_size(
	size_t rSize,
	size_t sSize
)
{
	return
		(
			asn1_write_mpi_est_size_given_mpi_size(sSize) +
			asn1_write_mpi_est_size_given_mpi_size(rSize)
		) +
		asn1_write_len_est_size(
			asn1_write_mpi_est_size_given_mpi_size(sSize) +
			asn1_write_mpi_est_size_given_mpi_size(rSize)
		) +
		asn1_write_tag_est_size(
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE
		);
}

} // namespace mbedTLScpp
} // namespace Internal





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
		throw InvalidArgumentException(
			"mbedTLScpp::Internal::pk_write_pubkey_est_size"
			" - Invalid PKey type is given."
		);
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

	MBEDTLSCPP_MAKE_C_FUNC_CALL(
		Internal::pk_write_pubkey_der_est_size,
		mbedtls_oid_get_oid_by_pk_alg,
		mbedtls_pk_get_type(&key),
		&oid,
		&oid_len
	);

#if defined(MBEDTLS_ECP_C)
	if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY)
	{
		par_len += pk_write_ec_param_est_size(*mbedtls_pk_ec(key));
	}
#endif

	len += asn1_write_algorithm_identifier_est_size(oid, oid_len, par_len);

	len += asn1_write_len_est_size(len);
	len += asn1_write_tag_est_size(
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE
	);

	return len;
}


inline size_t pk_write_prvkey_der_est_size(const mbedtls_pk_context& key)
{
#if defined(MBEDTLS_RSA_C)
	if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_RSA)
	{
		return pk_write_rsa_prvkey_der_est_size(*mbedtls_pk_rsa(key));
	}
	else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
	if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY)
	{
		return pk_write_ec_prvkey_der_est_size(*mbedtls_pk_ec(key));
	}
	else
#endif /* MBEDTLS_ECP_C */
	throw InvalidArgumentException(
		"mbedTLScpp::Internal::pk_write_prvkey_der_est_size"
		" - Invalid PKey type is given."
	);
}


inline size_t pk_write_sign_der_est_size(
	const mbedtls_pk_context& key,
	size_t /* hashLenInBytes */
)
{
	switch (mbedtls_pk_get_type(&key))
	{
	case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY:
	case mbedtls_pk_type_t::MBEDTLS_PK_ECDSA:
	{
		const mbedtls_ecp_keypair& ec = *mbedtls_pk_ec(key);
		// we have to access group info via private
		const mbedtls_ecp_group& grp = ec.MBEDTLS_PRIVATE(grp);
		size_t plen = mbedtls_mpi_size(&grp.P);

		return ec_signature_to_asn1_est_size(plen, plen);
	}
	case mbedtls_pk_type_t::MBEDTLS_PK_RSA:
	{
		const mbedtls_rsa_context& rsa = *mbedtls_pk_rsa(key);
		return mbedtls_rsa_get_len(&rsa);
	}
	case mbedtls_pk_type_t::MBEDTLS_PK_RSA_ALT:
	case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY_DH:
	case mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS:
	case mbedtls_pk_type_t::MBEDTLS_PK_NONE:
	default:
		throw InvalidArgumentException(
			"mbedTLScpp::Internal::pk_write_sign_der_est_size"
			" - The given key type is not supported."
		);
	}
}

} // namespace Internal
} // namespace mbedTLScpp
