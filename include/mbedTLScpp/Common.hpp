#pragma once

#include <array>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief A helper for std::enable_if. This will be provided in std library
	 *        after C++14 standard. For details, please refer to:
	 *        https://en.cppreference.com/w/cpp/types/enable_if
	 *
	 * @tparam B A boolean expression/value given to std::enable_if
	 * @tparam T A type given to std::enable_if
	 */
	template<bool B, class T = void>
	using enable_if_t = typename std::enable_if<B,T>::type;

	/**
	 * @brief Type trait that removes const and reference.
	 *        It's a combination of std::remove_cv and std::remove_reference.
	 *        This will be provided in std library after C++20 standard. For
	 *        details, please refer to:
	 *        https://en.cppreference.com/w/cpp/types/remove_cvref
	 *
	 * @tparam T Data type to operate on.
	 */
	template<class T>
	struct remove_cvref
	{
		typedef typename std::remove_cv<typename std::remove_reference<T>::type >::type type;
	};

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
	 * @brief Number of bits per byte.
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

	/**
	 * @brief Convert and copy the content of a C array to the std::array
	 *
	 * @tparam _ValType The type of value in the array.
	 * @tparam _Size    The length of the array.
	 * @param in The input C array
	 * @return std::array<_ValType, _Size> The std::array that has been generated.
	 */
	template<typename _ValType, size_t _Size>
	std::array<_ValType, _Size> ToArray(const _ValType (&in)[_Size])
	{
		std::array<_ValType, _Size> out;
		std::copy(std::begin(in), std::end(in), out.begin());
		return out;
	}

	/**
	 * @brief Convert and copy the content of a std::array to the C array
	 *
	 * @tparam _ValType The type of value in the array.
	 * @tparam _Size    The length of the array.
	 * @param out The output C array
	 * @param in  The input std::array
	 */
	template<typename _ValType, size_t _Size>
	void ToCArray(_ValType (&out)[_Size], const std::array<_ValType, _Size>& in)
	{
		std::copy(in.begin(), in.end(), std::begin(out));
	}
}

