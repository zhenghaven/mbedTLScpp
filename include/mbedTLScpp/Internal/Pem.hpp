#pragma once

#include <cstddef>
#include <cstdint>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	namespace Internal
	{
		/**
		 * @brief Calculate the length of the string that is generated by encoding a byte string.
		 *
		 * @tparam _BinBlockSize The binary block size.
		 * @tparam _EncBlockSize The encoding block size.
		 * @tparam _HasPad       Does it has padding?
		 * @param binarySize     The size of the byte string, in bytes.
		 * @return constexpr size_t The calculation result.
		 */
		template<uint8_t _BinBlockSize, uint8_t _EncBlockSize, bool _HasPad>
		inline constexpr size_t CodecEncodedSize(size_t binarySize) noexcept
		{
			// source: cppcodec
			return _HasPad ?
				(
					(binarySize + (_BinBlockSize - 1)
						- ((binarySize + (_BinBlockSize - 1)) % _BinBlockSize))
					* _EncBlockSize / _BinBlockSize
				) :
				// No padding: only pad to the next multiple of 5 bits, i.e. at most a single extra byte.
				(
					(binarySize * _EncBlockSize / _BinBlockSize)
						+ (((binarySize * _EncBlockSize) % _BinBlockSize) ? 1 : 0)
				);
		}

		/**
		 * @brief Calculate the length of the string that is generated by Base64-encoding a byte string.
		 *
		 * @tparam _HasPad   Does it has padding?
		 * @param binarySize The size of the byte string, in bytes.
		 * @return constexpr size_t The calculation result.
		 */
		template<bool _HasPad>
		inline constexpr size_t Base64EncodedSize(size_t binarySize) noexcept
		{
			return CodecEncodedSize<3, 4, _HasPad>(binarySize);
		}

		/**
		 * @brief Calculate the length of the PEM string based on the size of the DER.
		 *
		 * @param derSize    The size of the DER.
		 * @param headerSize The length of the PEM header.
		 * @param footerSize The length of the PEM footer.
		 * @return constexpr size_t The calculation result.
		 */
		inline constexpr size_t CalcPemBytes(size_t derSize, size_t headerSize, size_t footerSize)
		{
			return headerSize +                        // Header size
				Base64EncodedSize<true>(derSize) +        // Base64 encoded size
				1 +                                    // Required by mbedtls_base64_encode
				(Base64EncodedSize<true>(derSize) / 64) + //'\n' for each line
				footerSize +                           // Footer size
				1;                                     // null terminator
		}
	}
}
