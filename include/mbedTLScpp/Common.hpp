#pragma once

#include <array>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief Dummy struct to indicate safety check is unnecessary. Usually it's
	 *        because the safety check is already done before calling the
	 *        function using this dummy struct.
	 *        The similar usage of dummy struct can be found in std::unique_lock
	 *
	 */
	struct NoSafeCheck
	{
		explicit NoSafeCheck() = default;
	};
	constexpr NoSafeCheck gsk_noSafeCheck;

	/**
	 * @brief a constexpr that represents bits per byte.
	 *
	 */
	constexpr uint8_t gsk_bitsPerByte = 8;

	/**
	 * @brief An item in InDataList.
	 *
	 */
	struct InDataListItem
	{
		const void*  m_data;
		const size_t m_size;
	};

	/**
	 * @brief A list that summarize a list of input containers' memory region.
	 *
	 * @tparam Len Number of items in the list.
	 */
	template<size_t Len>
	using InDataList = std::array<InDataListItem, Len>;

}

