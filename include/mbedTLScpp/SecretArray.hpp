#pragma once

#include <array>

#include "Common.hpp"
#include "LoadedFunctions.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief A container, which is basically a wrapper around std::array, that
	 *        is used to store secret data, so that the container will be zeroize
	 *        at destruction.
	 *
	 * @tparam _ValType The type of the value stored in array.
	 * @tparam _Size    The length (i.e., number of items) stored in array.
	 */
	template<typename _ValType, size_t _Size>
	class SecretArray
	{
	public: //static member

		/**
		 * @brief The type of the value stored in array.
		 *
		 */
		using ValType = _ValType;

		/**
		 * @brief The length (i.e., number of items) stored in array.
		 *
		 */
		static constexpr size_t sk_itemCount = _Size;

		/**
		 * @brief The size of the type of the value stored in array.
		 *
		 */
		static constexpr size_t sk_valSize = sizeof(ValType);

	public:

		/**
		 * @brief Construct a new Secret Array object
		 *
		 */
		SecretArray() :
			m_data()
		{}

		/**
		 * @brief Construct a new Secret Array object by copying a existing
		 *        Secret Array.
		 *
		 * @param other The existing Secret Array.
		 */
		SecretArray(const SecretArray& other) :
			m_data(other.m_data)
		{}

		/**
		 * @brief Destroy the Secret Array object
		 *
		 */
		virtual ~SecretArray()
		{
			Zeroize();
		}

		/**
		 * @brief Copy assignment
		 *
		 * @param rhs The right-hand-side value.
		 * @return SecretArray& The reference to self.
		 */
		SecretArray& operator=(const SecretArray& rhs)
		{
			m_data = std::forward<decltype(m_data)>(rhs.m_data);
			return *this;
		}

		/**
		 * @brief Move assignment
		 *
		 * @param rhs The right-hand-size value.
		 * @return SecretArray& The reference to self.
		 */
		SecretArray& operator=(SecretArray&& rhs)
		{
			Zeroize();
			m_data = std::forward<decltype(m_data)>(rhs.m_data);
			return *this;
		}

		/**
		 * @brief Zeroize the container.
		 *
		 */
		void Zeroize() noexcept
		{
			StaticLoadedFunctions::GetInstance().SecureZeroize(m_data.data(), m_data.size());
		}

		/**
		 * @brief Get the reference to the inner array.
		 *
		 * @return std::array<_ValType, _Size>& The reference to the inner array.
		 */
		std::array<_ValType, _Size>& Get() noexcept
		{
			return m_data;
		}

		/**
		 * @brief Get the const reference to the inner array.
		 *
		 * @return const std::array<_ValType, _Size>& The const reference to the inner array.
		 */
		const std::array<_ValType, _Size>& Get() const noexcept
		{
			return m_data;
		}

	private:
		std::array<_ValType, _Size> m_data;
	};

}
