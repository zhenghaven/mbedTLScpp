#pragma once

#include <cstddef>
#include <cstdint>

#include <mbedtls/asn1.h>
#include <mbedtls/bignum.h>

#include "../Exceptions.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	namespace Internal
	{
		inline constexpr size_t asn1_write_len_est_size(size_t len)
		{
			return
				len < 0x80 ?
					1 :
					(len <= 0xFF ?
						2 :
						(len <= 0xFFFF ?
							3 :
							(len <= 0xFFFFFF ?
								4 :
#if SIZE_MAX > 0xFFFFFFFF
								(len <= 0xFFFFFFFF ?
									5 :
									throw InvalidArgumentException("mbedTLScpp::Internal::asn1_write_len_est_size - Invalid length is given.")
								)
#else
								5
#endif
							)
						)
					);
		}

		inline constexpr size_t asn1_write_tag_est_size(unsigned char tag)
		{
			return 1;
		}

		inline constexpr size_t asn1_write_null_est_size()
		{
			return asn1_write_len_est_size(0) + asn1_write_tag_est_size(MBEDTLS_ASN1_NULL);
		}

		inline constexpr size_t asn1_write_bool_est_size(int boolean)
		{
			return static_cast<size_t>(1) +
				asn1_write_len_est_size(static_cast<size_t>(1)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_BOOLEAN);
		}

		inline constexpr size_t asn1_write_int_est_size_part1(int val)
		{
			return 1 +
					((val > 0 && static_cast<unsigned char>(val) & 0x80) ? 1 : 0);
		}

		inline constexpr size_t asn1_write_int_est_size(int val)
		{
			return asn1_write_int_est_size_part1(val) +
					+ asn1_write_len_est_size(asn1_write_int_est_size_part1(val))
					+ asn1_write_tag_est_size(MBEDTLS_ASN1_INTEGER);
		}

		inline constexpr size_t asn1_write_raw_buffer_est_size(const void *buf, size_t size)
		{
			return size;
		}

		inline constexpr size_t asn1_write_oid_est_size_part1(const char *oid, size_t oid_len)
		{
			return asn1_write_raw_buffer_est_size(oid, oid_len);
		}

		inline constexpr size_t asn1_write_oid_est_size(const char *oid, size_t oid_len)
		{
			return asn1_write_oid_est_size_part1(oid, oid_len) +
				asn1_write_len_est_size(asn1_write_oid_est_size_part1(oid, oid_len)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_OID);
		}

		inline constexpr uint8_t mpi_get_byte(const mbedtls_mpi & X, size_t pos)
		{
			return (X.p[( pos ) / sizeof(mbedtls_mpi_uint)] >> ((pos % sizeof(mbedtls_mpi_uint)) * 8)) & 0xff;
		}

		inline size_t asn1_write_mpi_est_size(const mbedtls_mpi & X)
		{
			size_t len = 0;

			len = mbedtls_mpi_size(&X);

			if (len > 0)
			{
				uint8_t firstByte = mpi_get_byte(X, len - 1);

				// DER format assumes 2s complement for numbers, so the leftmost bit
				// should be 0 for positive numbers and 1 for negative numbers.
				if (X.s == 1 && firstByte & 0x80)
				{
					len += 1;
				}
			}

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_INTEGER);

			return len;
		}

		inline constexpr size_t asn1_write_mpi_est_size_part1(size_t xMaxSize)
		{
			return xMaxSize +
					((xMaxSize > 0) ? 1 : 0);
		}

		inline constexpr size_t asn1_write_mpi_est_max_size(size_t xMaxSize)
		{
			return asn1_write_mpi_est_size_part1(xMaxSize) +
				asn1_write_len_est_size(asn1_write_mpi_est_size_part1(xMaxSize)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_INTEGER);
		}

		inline constexpr size_t asn1_write_algorithm_identifier_est_size_part1(const char *oid, size_t oid_len, size_t par_len)
		{
			return ((par_len == 0) ?
				asn1_write_null_est_size() :
				par_len) +
				asn1_write_oid_est_size(oid, oid_len);
		}

		inline constexpr size_t asn1_write_algorithm_identifier_est_size(const char *oid, size_t oid_len, size_t par_len)
		{
			return asn1_write_algorithm_identifier_est_size_part1(oid, oid_len, par_len) +
				asn1_write_len_est_size(asn1_write_algorithm_identifier_est_size_part1(oid, oid_len, par_len)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		}

		inline constexpr size_t asn1_write_tagged_string_est_size(int tag, const char *text, size_t text_len)
		{
			return asn1_write_raw_buffer_est_size(text, text_len) +
				asn1_write_len_est_size(asn1_write_raw_buffer_est_size(text, text_len)) +
				asn1_write_tag_est_size(tag);
		}

		inline size_t x509_write_extension_est_size(const mbedtls_asn1_named_data& ext)
		{
			size_t len = 0;

			len += asn1_write_raw_buffer_est_size(ext.val.p + 1, ext.val.len - 1);
			len += asn1_write_len_est_size(ext.val.len - 1);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_OCTET_STRING);

			if (ext.val.p[0] != 0)
			{
				len += asn1_write_bool_est_size(1);
			}

			len += asn1_write_raw_buffer_est_size(ext.oid.p, ext.oid.len);
			len += asn1_write_len_est_size(ext.oid.len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_OID);

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			return len;
		}

		inline size_t x509_write_extensions_est_size(const mbedtls_asn1_named_data& first)
		{
			size_t len = 0;
			const mbedtls_asn1_named_data *cur_ext = &first;

			while (cur_ext != NULL)
			{
				len += x509_write_extension_est_size(*cur_ext);
				cur_ext = cur_ext->next;
			}

			return len;
		}

		inline size_t x509_write_name_est_size(const mbedtls_asn1_named_data& cur_name)
		{
			size_t len = 0;
			const char *oid = (const char*)cur_name.oid.p;
			size_t oid_len = cur_name.oid.len;
			const unsigned char *name = cur_name.val.p;
			size_t name_len = cur_name.val.len;

			// Write correct string tag and value
			len += asn1_write_tagged_string_est_size(cur_name.val.tag, (const char *)name, name_len);
			// Write OID
			//
			len += asn1_write_oid_est_size(oid, oid_len);

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);

			return len;
		}

		inline size_t x509_write_names_est_size(const mbedtls_asn1_named_data& first)
		{
			size_t len = 0;
			const mbedtls_asn1_named_data *cur = &first;

			while (cur != NULL)
			{
				len += x509_write_name_est_size(*cur);
				cur = cur->next;
			}

			len += asn1_write_len_est_size(len);
			len += asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

			return len;
		}

		inline constexpr size_t x509_write_sig_est_size(const char *oid, size_t oid_len, size_t sig_len)
		{
			return (sig_len + 1) +
				asn1_write_len_est_size((sig_len + 1)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_BIT_STRING) +
				asn1_write_algorithm_identifier_est_size(oid, oid_len, 0);
		}

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
