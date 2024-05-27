// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstddef>
#include <cstdint>

// #include <mbedtls/constant_time.h>

// Currently, the declaration of mbedtls_ct_memcmp() is not wrapped in
// an extern "C" block.
extern "C" int mbedtls_ct_memcmp( const void *a, const void *b, size_t n );

namespace mbedTLScpp
{
namespace Internal
{

/**
 * @brief Compare equality of memory content in constant time.
 *
 * @param a
 * @param b
 * @param n
 * @return 1 for equal, 0 for not equal.
 */
inline uint8_t ConstTimeMemEqual( const void *a, const void *b, size_t n ) noexcept
{
	// mbedtls_ct_memcmp should return a int that is at most 32 bits.
	int initRes = mbedtls_ct_memcmp(a, b, n);

	// fold the 32 bits result to 16 bits, by ORing the upper 16 bits with the lower 16 bits.
	uint16_t fold16Res = static_cast<uint16_t>((initRes & 0xffff) | (initRes >> 16));
	// fold again to 8 bits, and store the result in 16 bits variable.
	uint16_t fold8Res = static_cast<uint16_t>((fold16Res & 0xff) | (fold16Res >> 8));

	// The value in fold8Res should be in the range of [0x0000, 0x00ff]
	// By subtracting 1, 0x0000 will be mapped to 0xffff,
	// and [0x0001, 0x00ff] will be mapped to [0x0000, 0x00fe]
	uint16_t minusOne = static_cast<uint16_t>(fold8Res - 1);

	// By shifting right 8 bits, 0xffff will be mapped to 0xff,
	// and [0x0000, 0x00fe] will be mapped to 0x00
	uint8_t upperByte = static_cast<uint8_t>(minusOne >> 8);

	// we only need to return the least significant bit of the upper byte.
	// so 0x00ff will be mapped to 0x01, and 0x0000 will be mapped to 0x00.
	return static_cast<uint8_t>(0x01 & upperByte);
}

/**
 * @brief Compare inequality of memory content in constant time.
 *
 * @param a
 * @param b
 * @param n
 * @return 0 for equal, 1 for not equal.
 */
inline uint8_t ConstTimeMemNotEqual( const void *a, const void *b, size_t n ) noexcept
{
	// ConstTimeMemEqual should return in range [0, 1]
	auto initRes = ConstTimeMemEqual(a, b, n);

	// Map 0 to 1 and 1 to 0 using only constant-time arithmetic.
	return static_cast<uint8_t>(0x1 ^ initRes);
}

} // namespace Internal
} // namespace mbedTLScpp
