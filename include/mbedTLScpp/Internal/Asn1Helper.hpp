#pragma once

#include <cstddef>
#include <cstdint>

#include <vector>

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
		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
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

		inline constexpr size_t asn1_write_tag_est_size(unsigned char tag) noexcept
		{
			return 1;
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t asn1_write_null_est_size()
		{
			return asn1_write_len_est_size(0) + asn1_write_tag_est_size(MBEDTLS_ASN1_NULL);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t asn1_write_bool_est_size(int boolean)
		{
			return static_cast<size_t>(1) +
				asn1_write_len_est_size(static_cast<size_t>(1)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_BOOLEAN);
		}

		inline constexpr size_t asn1_write_int_est_size_part1(int val) noexcept
		{
			return 1 +
					((val > 0 && static_cast<unsigned char>(val) & 0x80) ? static_cast<size_t>(1) : static_cast<size_t>(0));
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t asn1_write_int_est_size(int val)
		{
			return asn1_write_int_est_size_part1(val) +
					+ asn1_write_len_est_size(asn1_write_int_est_size_part1(val))
					+ asn1_write_tag_est_size(MBEDTLS_ASN1_INTEGER);
		}

		inline constexpr size_t asn1_write_raw_buffer_est_size(const void *buf, size_t size) noexcept
		{
			return size;
		}

		inline constexpr size_t asn1_write_oid_est_size_part1(const void *oid, size_t oid_len) noexcept
		{
			return asn1_write_raw_buffer_est_size(oid, oid_len);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t asn1_write_oid_est_size(const void *oid, size_t oid_len)
		{
			return asn1_write_oid_est_size_part1(oid, oid_len) +
				asn1_write_len_est_size(asn1_write_oid_est_size_part1(oid, oid_len)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_OID);
		}

		inline constexpr uint8_t mpi_get_byte(const mbedtls_mpi & X, size_t pos) noexcept
		{
			return (X.p[( pos ) / sizeof(mbedtls_mpi_uint)] >> ((pos % sizeof(mbedtls_mpi_uint)) * 8)) & 0xff;
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
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

		inline constexpr size_t asn1_write_mpi_est_size_part1(size_t xMaxSize) noexcept
		{
			return xMaxSize +
					((xMaxSize > 0) ? 1 : 0);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t asn1_write_mpi_est_max_size(size_t xMaxSize)
		{
			return asn1_write_mpi_est_size_part1(xMaxSize) +
				asn1_write_len_est_size(asn1_write_mpi_est_size_part1(xMaxSize)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_INTEGER);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t asn1_write_algorithm_identifier_est_size_part1(const char *oid, size_t oid_len, size_t par_len)
		{
			return ((par_len == 0) ?
				asn1_write_null_est_size() :
				par_len) +
				asn1_write_oid_est_size(oid, oid_len);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t asn1_write_algorithm_identifier_est_size(const char *oid, size_t oid_len, size_t par_len)
		{
			return asn1_write_algorithm_identifier_est_size_part1(oid, oid_len, par_len) +
				asn1_write_len_est_size(asn1_write_algorithm_identifier_est_size_part1(oid, oid_len, par_len)) +
				asn1_write_tag_est_size(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		}

		/**
		 * @brief
		 *
		 * @exception InvalidArgumentException
		 *
		 * @return size_t
		 */
		inline constexpr size_t asn1_write_tagged_string_est_size(int tag, const void *text, size_t text_len)
		{
			return asn1_write_raw_buffer_est_size(text, text_len) +
				asn1_write_len_est_size(asn1_write_raw_buffer_est_size(text, text_len)) +
				asn1_write_tag_est_size(tag);
		}




		/**
		 * @brief
		 *
		 * @param list
		 * @param oid
		 * @exception InvalidArgumentException
		 * @return const mbedtls_asn1_named_data&
		 */
		inline const mbedtls_asn1_named_data& Asn1GetNamedDataFromList(const mbedtls_asn1_named_data* list, const std::string& oid)
		{
			const mbedtls_asn1_named_data* curr = list;
			while (curr != NULL)
			{
				if (curr->oid.len == oid.size() &&
					memcmp(curr->oid.p, oid.data(), oid.size()) == 0)
				{
					return *curr;
				}

				curr = curr->next;
			}

			throw InvalidArgumentException("The given OID is not found in the list.");
		}

		/**
		 * @brief
		 *
		 * @param dest
		 * @param src
		 * @exception std::bad_alloc
		 */
		inline void Asn1DeepCopy(mbedtls_asn1_buf& dest, const mbedtls_asn1_buf& src)
		{
			if (src.p == nullptr)
			{
				dest.p = nullptr;
			}
			else
			{
				dest.p = static_cast<unsigned char *>(mbedtls_calloc(1, src.len));
				if (dest.p == nullptr)
				{
					throw std::bad_alloc();
				}
			}

			dest.len = src.len;
			dest.tag = src.tag;
			std::memcpy(dest.p, src.p, src.len);
		}

		/**
		 * @brief
		 *
		 * @param dest Dest is a pointer holding named data. If there is already
		 *             something stored in dest (not-null), it will be freed.
		 * @param src
		 * @exception std::bad_alloc
		 */
		inline void Asn1DeepCopy(mbedtls_asn1_named_data*& dest, const mbedtls_asn1_named_data* src)
		{
			mbedtls_asn1_free_named_data_list(&dest);

			dest = static_cast<mbedtls_asn1_named_data*>(mbedtls_calloc(1, sizeof(mbedtls_asn1_named_data)));
			if (dest == nullptr)
			{
				throw std::bad_alloc();
			}

			const mbedtls_asn1_named_data* curSrc = src;
			mbedtls_asn1_named_data* curDest = dest;

			while (curSrc != nullptr)
			{
				Asn1DeepCopy(curDest->oid, curSrc->oid);
				Asn1DeepCopy(curDest->val, curSrc->val);
				curDest->next_merged = curSrc->next_merged;

				if (curSrc->next != nullptr)
				{
					curDest->next = static_cast<mbedtls_asn1_named_data*>(mbedtls_calloc(1, sizeof(mbedtls_asn1_named_data)));
					if (curDest->next == nullptr)
					{
						throw std::bad_alloc();
					}
				}

				curSrc = curSrc->next;
				curDest = curDest->next;
			}
		}

		inline void Asn1ReverseNamedDataList(mbedtls_asn1_named_data*& dest)
		{
			std::vector<mbedtls_asn1_named_data*> stack;

			mbedtls_asn1_named_data* cur = dest;
			while(cur != nullptr)
			{
				stack.push_back(cur);
				cur = cur->next;
			}

			if (stack.size() > 0)
			{
				dest = stack.back();
				stack.pop_back();
				dest->next = nullptr;
			}

			cur = dest;

			while(stack.size() > 0 && cur != nullptr)
			{
				cur->next = stack.back();
				stack.pop_back();
				cur = cur->next;
				cur->next = nullptr;
			}
		}
	}
}
