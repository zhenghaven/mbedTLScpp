#pragma once

#include <string>

#include "../Container.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	namespace Internal
	{
		constexpr char const gsk_hEXLUT[] = "0123456789ABCDEF";

		constexpr char const gsk_hexLUT[] = "0123456789abcdef";

		/**
		 * @brief Convert the higher bit of a single byte into a single hex
		 *        character in upper case.
		 *
		 * @param byte The byte to convert.
		 * @return constexpr char The hex character in upper case.
		 */
		inline constexpr char HiBit2HEX(uint8_t byte)
		{
			return gsk_hEXLUT[(byte >> 4) & 0x0F];
		}

		/**
		 * @brief Convert the lower bit of a single byte into a single hex
		 *        character in upper case.
		 *
		 * @param byte The byte to convert.
		 * @return constexpr char The hex character in upper case.
		 */
		inline constexpr char LoBit2HEX(uint8_t byte)
		{
			return gsk_hEXLUT[byte &        0x0F];
		}

		/**
		 * @brief Convert the higher bit of a single byte into a single hex
		 *        character in lower case.
		 *
		 * @param byte The byte to convert.
		 * @return constexpr char The hex character in lower case.
		 */
		inline constexpr char HiBit2Hex(uint8_t byte)
		{
			return gsk_hexLUT[(byte >> 4) & 0x0F];
		}

		/**
		 * @brief Convert the lower bit of a single byte into a single hex
		 *        character in lower case.
		 *
		 * @param byte The byte to convert.
		 * @return constexpr char The hex character in lower case.
		 */
		inline constexpr char LoBit2Hex(uint8_t byte)
		{
			return gsk_hexLUT[byte &        0x0F];
		}

		/**
		 * @brief Convert an array of bytes into a hex string in upper case and
		 *        big endian.
		 *
		 * @tparam ContainerType The type of container storing the bytes.
		 * @param cnt The data container.
		 * @return std::string The hex string.
		 */
		template<typename ContainerType>
		inline std::string Bytes2HEXBigEnd(ContCtnReadOnlyRef<ContainerType> cnt)
		{
			std::string res;
			res.reserve(cnt.GetRegionSize() * 2);

			for(const uint8_t* it = cnt.EndBytePtr(); it > cnt.BeginBytePtr(); --it)
			{
				res.push_back(HiBit2HEX(*(it - 1)));
				res.push_back(LoBit2HEX(*(it - 1)));
			}

			return res;
		}

		/**
		 * @brief Convert an array of bytes into a hex string in upper case and
		 *        small endian.
		 *
		 * @tparam ContainerType The type of container storing the bytes.
		 * @param cnt The data container.
		 * @return std::string The hex string.
		 */
		template<typename ContainerType>
		inline std::string Bytes2HEXSmlEnd(ContCtnReadOnlyRef<ContainerType> cnt)
		{
			std::string res;
			res.reserve(cnt.GetRegionSize() * 2);

			for(const uint8_t* it = cnt.BeginBytePtr(); it < cnt.EndBytePtr(); ++it)
			{
				res.push_back(HiBit2HEX(*it));
				res.push_back(LoBit2HEX(*it));
			}

			return res;
		}

		/**
		 * @brief Convert an array of bytes into a hex string in lower case and
		 *        big endian.
		 *
		 * @tparam ContainerType The type of container storing the bytes.
		 * @param cnt The data container.
		 * @return std::string The hex string.
		 */
		template<typename ContainerType>
		inline std::string Bytes2HexBigEnd(ContCtnReadOnlyRef<ContainerType> cnt)
		{
			std::string res;
			res.reserve(cnt.GetRegionSize() * 2);

			for(const uint8_t* it = cnt.EndBytePtr(); it > cnt.BeginBytePtr(); --it)
			{
				res.push_back(HiBit2Hex(*(it - 1)));
				res.push_back(LoBit2Hex(*(it - 1)));
			}

			return res;
		}

		/**
		 * @brief Convert an array of bytes into a hex string in lower case and
		 *        small endian.
		 *
		 * @tparam ContainerType The type of container storing the bytes.
		 * @param cnt The data container.
		 * @return std::string The hex string.
		 */
		template<typename ContainerType>
		inline std::string Bytes2HexSmlEnd(ContCtnReadOnlyRef<ContainerType> cnt)
		{
			std::string res;
			res.reserve(cnt.GetRegionSize() * 2);

			for(const uint8_t* it = cnt.BeginBytePtr(); it < cnt.EndBytePtr(); ++it)
			{
				res.push_back(HiBit2Hex(*it));
				res.push_back(LoBit2Hex(*it));
			}

			return res;
		}
	}
}