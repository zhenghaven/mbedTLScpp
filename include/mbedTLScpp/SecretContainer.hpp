#pragma once

#include <array>
#include <vector>

#include <mbedtls/platform_util.h>

#include "Common.hpp"

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
			mbedtls_platform_zeroize(m_data.data(), m_data.size());
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

	/* TODO: Secret Vectors and Secret Strings, which will need a special allocator. */

	/**
	 * @brief Trait to determine if a type is a Secret Container Type.
	 *
	 * @tparam T Type to be determined.
	 */
	template <class T>
	struct IsSecretContainer : std::false_type
	{};

	template <typename _ValType, size_t _Size>
	struct IsSecretContainer<SecretArray<_ValType, _Size> > : std::true_type
	{
		static constexpr size_t GetCtnSize(const SecretArray<_ValType, _Size>& ctn) noexcept
		{
			return sizeof(_ValType) * _Size;
		}

		static const void* GetPtr(const SecretArray<_ValType, _Size>& ctn) noexcept
		{
			return ctn.Get().data();
		}

		static const uint8_t* GetBytePtr(const SecretArray<_ValType, _Size>& ctn, size_t offsetInByte) noexcept
		{
			return static_cast<const uint8_t*>(GetPtr(ctn)) + offsetInByte;
		}

		static const void* GetPtr(const SecretArray<_ValType, _Size>& ctn, size_t offsetInByte) noexcept
		{
			return GetBytePtr(ctn, offsetInByte);
		}

		static void* GetPtr(SecretArray<_ValType, _Size>& ctn)
		{
			return ctn.Get().data();
		}

		static uint8_t* GetBytePtr(SecretArray<_ValType, _Size>& ctn, size_t offsetInByte)
		{
			return static_cast<uint8_t*>(GetPtr(ctn)) + offsetInByte;
		}

		static void* GetPtr(SecretArray<_ValType, _Size>& ctn, size_t offsetInByte)
		{
			return GetBytePtr(ctn, offsetInByte);
		}
	};

	/**
	 * @brief Trait to determine if a type is a Static Secret Container Type.
	 *
	 * @tparam T Type to be determined.
	 */
	template <class T>
	struct IsStaticSecretContainer : std::false_type
	{};

	template <typename _ValType, size_t _Size>
	struct IsStaticSecretContainer<SecretArray<_ValType, _Size> > : std::true_type
	{
		static constexpr size_t sk_ctnSize = sizeof(_ValType) * _Size;
	};

	template<typename ContainerType,
		enable_if_t<IsSecretContainer<typename remove_cvref<ContainerType>::type>::value, int> = 0>
	struct ContSecretCtnReadOnlyRef
	{
		/**
		 * @brief The pure type of the container, which means all "const" and "&"
		 *        specification have been removed.
		 *
		 */
		typedef typename remove_cvref<ContainerType>::type PureContainerType;

		/**
		 * @brief The const-reference to the container.
		 *
		 */
		const PureContainerType& m_ctn;

		/**
		 * @brief The offset (in Bytes, starts from the begining of the
		 *        container) for the begining of the memory region.
		 *
		 */
		const size_t m_beginOffset;

		/**
		 * @brief The offset (in Bytes, starts from the begining of the
		 *        container) for the end of the memory region.
		 *
		 */
		const size_t m_endOffset;

		/**
		 * @brief Construct a new Contiguous Container Read Only Reference object.
		 *
		 * @exception std::invalid_argument Thrown if endOffset < beginOffset.
		 * @exception std::out_of_range Thrown if endOffset is out of the size of the container.
		 * @param ctn         The const reference to the container.
		 * @param beginOffset The offset (in Bytes, starts from the begining of
		 *                    the container) for the begining of the memory region.
		 * @param endOffset   The offset (in Bytes, starts from the begining of
		 *                    the container) for the end of the memory region.
		 */
		ContSecretCtnReadOnlyRef(const PureContainerType& ctn, size_t beginOffset, size_t endOffset) :
			m_ctn(ctn),
			m_beginOffset(beginOffset),
			m_endOffset(endOffset)
		{
			if(endOffset < beginOffset)
			{
				throw std::invalid_argument("The end of the range is smaller than the begining of the range.");
			}

			if(endOffset > IsSecretContainer<PureContainerType>::GetCtnSize(m_ctn))
			{
				throw std::out_of_range("The end if the range is outside of the container.");
			}
		}

		/**
		 * @brief Construct a new Contiguous Container Read Only Reference object.
		 *        NOTE: Call this constructor only if you already done the safety
		 *        checks on beginOffset and endOffset!
		 *
		 * @exception None No exception thrown
		 * @param ctn         The const reference to the container.
		 * @param beginOffset The offset (in Bytes, starts from the begining of
		 *                    the container) for the begining of the memory region.
		 * @param endOffset   The offset (in Bytes, starts from the begining of
		 *                    the container) for the end of the memory region.
		 */
		ContSecretCtnReadOnlyRef(const PureContainerType& ctn, size_t beginOffset, size_t endOffset, NoSafeCheck) noexcept :
			m_ctn(ctn),
			m_beginOffset(beginOffset),
			m_endOffset(endOffset)
		{}

		/**
		 * @brief Construct a new Contiguous Container Read Only Reference object
		 *        by copying the reference from an existing instance.
		 *
		 * @exception None No exception thrown
		 * @param rhs The existing instance.
		 */
		ContSecretCtnReadOnlyRef(const ContSecretCtnReadOnlyRef& rhs) noexcept :
			m_ctn(rhs.m_ctn),
			m_beginOffset(rhs.m_beginOffset),
			m_endOffset(rhs.m_endOffset)
		{}

		ContSecretCtnReadOnlyRef& operator=(const ContSecretCtnReadOnlyRef& rhs) = delete;

		ContSecretCtnReadOnlyRef& operator=(ContSecretCtnReadOnlyRef&& rhs) = delete;

		/**
		 * @brief Get the size (in bytes) of a *single* value stored in the container.
		 *
		 * @exception None No exception thrown
		 * @return size_t the size (in bytes) of a *single* value
		 */
		size_t GetValSize() const noexcept
		{
			return PureContainerType::sk_valSize;
		}

		/**
		 * @brief Get the size of the memory region
		 *
		 * @exception None No exception thrown
		 * @return size_t The size of the memory region
		 */
		size_t GetRegionSize() const noexcept
		{
			return m_endOffset - m_beginOffset;
		}

		/**
		 * @brief Get the void pointer to the begining of the memory region.
		 *
		 * @exception None No exception thrown
		 * @return const void* The pointer to the begining of the memory region.
		 */
		const void* BeginPtr() const noexcept
		{
			return IsSecretContainer<PureContainerType>::GetPtr(m_ctn, m_beginOffset);
		}

		/**
		 * @brief Get the byte pointer to the begining of the memory region.
		 *
		 * @exception None No exception thrown
		 * @return const byte The pointer to the begining of the memory region.
		 */
		const uint8_t* BeginBytePtr() const noexcept
		{
			return IsSecretContainer<PureContainerType>::GetBytePtr(m_ctn, m_beginOffset);
		}

		/**
		 * @brief Get the void pointer to the end of the memory region.
		 *
		 * @exception None No exception thrown
		 * @return const void* The pointer to the end of the memory region.
		 */
		const void* EndPtr() const noexcept
		{
			return IsSecretContainer<PureContainerType>::GetPtr(m_ctn, m_endOffset);
		}

		/**
		 * @brief Get the byte pointer to the end of the memory region.
		 *
		 * @exception None No exception thrown
		 * @return const uint8_t* The pointer to the end of the memory region.
		 */
		const uint8_t* EndBytePtr() const noexcept
		{
			return IsSecretContainer<PureContainerType>::GetBytePtr(m_ctn, m_endOffset);
		}
	};

	/**
	 * @brief Helper function to construct the ContSecretCtnReadOnlyRef struct easily for
	 *        A) the entire range of the container
	 *        B) containers with static size
	 *
	 * @exception None No exception thrown
	 * @tparam ContainerType Type of the container, which will be inferred from
	 *                       the giving parameter.
	 * @param ctn The const-reference to the container.
	 * @return ContSecretCtnReadOnlyRef<ContainerType> The constructed ContSecretCtnReadOnlyRef struct
	 */
	template<typename ContainerType,
		enable_if_t<IsStaticSecretContainer<ContainerType>::value, int> = 0>
	inline ContSecretCtnReadOnlyRef<ContainerType> SCtnFullR(const ContainerType& ctn) noexcept
	{
		return ContSecretCtnReadOnlyRef<ContainerType>(ctn, 0, IsStaticSecretContainer<ContainerType>::sk_ctnSize, gsk_noSafeCheck);
	}





	/**
	 * @brief Helper function to construct the ContSecretCtnReadOnlyRef struct easily for
	 *        A) a specific range of the container
	 *        B) containers with static size
	 *        C) range is specified statically
	 *
	 * @exception None No exception thrown
	 * @tparam beginOffset   The left end of the range (inclusive, in bytes).
	 * @tparam endOffset     The right end of the range (exclusive, in bytes).
	 * @tparam ContainerType Type of the container, which will be inferred from
	 *                       the giving parameter.
	 * @param ctn The const-reference to the container.
	 * @return ContSecretCtnReadOnlyRef<ContainerType> The constructed ContSecretCtnReadOnlyRef struct
	 */
	template<size_t beginOffset, size_t endOffset,
		typename ContainerType,
		enable_if_t<IsStaticSecretContainer<ContainerType>::value, int> = 0>
	inline ContSecretCtnReadOnlyRef<ContainerType> SCtnByteRangeR(const ContainerType& ctn) noexcept
	{
		static_assert(beginOffset <= endOffset, "The begining of the range should be smaller than or equal to the end of the range.");
		static_assert(endOffset < IsStaticSecretContainer<ContainerType>::sk_ctnSize, "The end of the range is outside of the container.");

		return ContSecretCtnReadOnlyRef<ContainerType>(ctn, beginOffset, endOffset, gsk_noSafeCheck);
	}

	/**
	 * @brief Helper function to construct the ContSecretCtnReadOnlyRef struct easily for
	 *        A) a specific range of the container, where the end of range is the end of container
	 *        B) containers with static size
	 *        C) range is specified statically
	 *
	 * @exception None No exception thrown
	 * @tparam beginOffset   The left end of the range (inclusive, in bytes).
	 * @tparam ContainerType Type of the container, which will be inferred from
	 *                       the giving parameter.
	 * @param ctn The const-reference to the container.
	 * @return ContSecretCtnReadOnlyRef<ContainerType> The constructed ContSecretCtnReadOnlyRef struct
	 */
	template<size_t beginOffset,
		typename ContainerType,
		enable_if_t<IsStaticSecretContainer<ContainerType>::value, int> = 0>
	inline ContSecretCtnReadOnlyRef<ContainerType> SCtnByteRangeR(const ContainerType& ctn) noexcept
	{
		static_assert(beginOffset < IsStaticSecretContainer<ContainerType>::sk_ctnSize, "The begining of the range is outside of the container.");

		constexpr size_t endOffset = IsStaticSecretContainer<ContainerType>::sk_ctnSize;
		return ContSecretCtnReadOnlyRef<ContainerType>(ctn, beginOffset, endOffset, gsk_noSafeCheck);
	}






	/**
	 * @brief Helper function to construct the ContSecretCtnReadOnlyRef struct easily for
	 *        A) a specific range of the container
	 *        B) containers with dynamic size
	 *        C) range is specified dynamically
	 *
	 * @exception std::invalid_argument Thrown if endOffset < beginOffset.
	 * @exception std::out_of_range Thrown if endOffset is out of the size of the container.
	 * @tparam ContainerType Type of the container, which will be inferred from
	 *                       the giving parameter.
	 * @param ctn         The const-reference to the container.
	 * @param beginOffset The left end of the range (inclusive, in bytes).
	 * @param endOffset   The right end of the range (exclusive, in bytes).
	 * @return ContSecretCtnReadOnlyRef<ContainerType> The constructed ContSecretCtnReadOnlyRef struct
	 */
	template<typename ContainerType,
		enable_if_t<IsSecretContainer<ContainerType>::value, int> = 0>
	inline ContSecretCtnReadOnlyRef<ContainerType> SCtnByteRangeR(const ContainerType& ctn, size_t beginOffset, size_t endOffset)
	{
		return ContSecretCtnReadOnlyRef<ContainerType>(ctn, beginOffset, endOffset);
	}

	/**
	 * @brief Helper function to construct the ContSecretCtnReadOnlyRef struct easily for
	 *        A) a specific range of the container, where the end of range is the end of container
	 *        B) containers with dynamic size
	 *        C) range is specified dynamically
	 *
	 * @exception std::invalid_argument Thrown if endOffset < beginOffset.
	 * @exception std::out_of_range Thrown if begining is out of the size of the container.
	 * @tparam ContainerType Type of the container, which will be inferred from
	 *                       the giving parameter.
	 * @param ctn         The const-reference to the container.
	 * @param beginOffset The left end of the range (inclusive, in bytes).
	 * @return ContSecretCtnReadOnlyRef<ContainerType> The constructed ContSecretCtnReadOnlyRef struct
	 */
	template<typename ContainerType,
		enable_if_t<IsSecretContainer<ContainerType>::value, int> = 0>
	inline ContSecretCtnReadOnlyRef<ContainerType> SCtnByteRangeR(const ContainerType& ctn, size_t beginOffset)
	{
		const size_t endOffset = IsSecretContainer<ContainerType>::GetCtnSize(ctn);
		if(beginOffset > endOffset)
		{
			throw std::out_of_range("The begining of the range is outside of the container.");
		}

		return ContSecretCtnReadOnlyRef<ContainerType>(ctn, beginOffset, endOffset);
	}




	/**
	 * @brief Helper function to construct the ContSecretCtnReadOnlyRef struct easily for
	 *        A) a specific range of the container
	 *        B) containers with static size
	 *        C) range is specified statically
	 *
	 * @exception None No exception thrown
	 * @tparam beginCount   The left end of the range (inclusive, in item counts).
	 * @tparam endCount     The right end of the range (exclusive, in item counts).
	 * @tparam ContainerType Type of the container, which will be inferred from
	 *                       the giving parameter.
	 * @param ctn The const-reference to the container.
	 * @return ContSecretCtnReadOnlyRef<ContainerType> The constructed ContSecretCtnReadOnlyRef struct
	 */
	template<size_t beginCount, size_t endCount,
		typename ContainerType,
		enable_if_t<IsStaticSecretContainer<ContainerType>::value, int> = 0>
	inline ContSecretCtnReadOnlyRef<ContainerType> SCtnItemRangeR(const ContainerType& ctn) noexcept
	{
		static_assert(beginCount <= endCount, "The begining of the range should be smaller than or equal to the end of the range.");
		static_assert(endCount <= ContainerType::sk_itemCount, "The end of the range is outside of the container.");

		constexpr size_t beginOffset = beginCount * ContainerType::sk_valSize;
		constexpr size_t endOffset   = endCount *   ContainerType::sk_valSize;

		return ContSecretCtnReadOnlyRef<ContainerType>(ctn, beginOffset, endOffset, gsk_noSafeCheck);
	}

	/**
	 * @brief Helper function to construct the ContSecretCtnReadOnlyRef struct easily for
	 *        A) a specific range of the container, where the end of range is the end of container
	 *        B) containers with static size
	 *        C) range is specified statically
	 *
	 * @exception None No exception thrown
	 * @tparam beginCount    The left end of the range (inclusive, in item counts).
	 * @tparam ContainerType Type of the container, which will be inferred from
	 *                       the giving parameter.
	 * @param ctn The const-reference to the container.
	 * @return ContSecretCtnReadOnlyRef<ContainerType> The constructed ContSecretCtnReadOnlyRef struct
	 */
	template<size_t beginCount,
		typename ContainerType,
		enable_if_t<IsStaticSecretContainer<ContainerType>::value, int> = 0>
	inline ContSecretCtnReadOnlyRef<ContainerType> SCtnItemRangeR(const ContainerType& ctn) noexcept
	{
		static_assert(beginCount <= ContainerType::sk_itemCount, "The begining of the range is outside of the container.");

		constexpr size_t beginOffset = beginCount * ContainerType::sk_valSize;
		constexpr size_t endOffset   = IsStaticSecretContainer<ContainerType>::sk_ctnSize;
		return ContSecretCtnReadOnlyRef<ContainerType>(ctn, beginOffset, endOffset, gsk_noSafeCheck);
	}

	/**
	 * @brief Helper function to construct the ContSecretCtnReadOnlyRef struct easily for
	 *        A) a specific range of the container
	 *        B) containers with dynamic size
	 *        C) range is specified dynamically
	 *
	 * @exception std::invalid_argument Thrown if beginCount < endCount.
	 * @exception std::out_of_range Thrown if endCount is out of the size of the container.
	 * @tparam ContainerType Type of the container, which will be inferred from
	 *                       the giving parameter.
	 * @param ctn         The const-reference to the container.
	 * @param beginCount  The left end of the range (inclusive, in item counts).
	 * @param endCount    The right end of the range (exclusive, in item counts).
	 * @return ContSecretCtnReadOnlyRef<ContainerType> The constructed ContSecretCtnReadOnlyRef struct
	 */
	template<typename ContainerType,
		enable_if_t<IsSecretContainer<ContainerType>::value, int> = 0>
	inline ContSecretCtnReadOnlyRef<ContainerType> SCtnItemRangeR(const ContainerType& ctn, size_t beginCount, size_t endCount)
	{
		const size_t beginOffset = beginCount * ContainerType::sk_valSize;
		const size_t endOffset   = endCount *   ContainerType::sk_valSize;

		return ContSecretCtnReadOnlyRef<ContainerType>(ctn, beginOffset, endOffset);
	}

	/**
	 * @brief Helper function to construct the ContSecretCtnReadOnlyRef struct easily for
	 *        A) a specific range of the container, where the end of range is the end of container
	 *        B) containers with dynamic size
	 *        C) range is specified dynamically
	 *
	 * @exception std::invalid_argument Thrown if beginCount < endCount.
	 * @exception std::out_of_range Thrown if beginCount is out of the size of the container.
	 * @tparam ContainerType Type of the container, which will be inferred from
	 *                       the giving parameter.
	 * @param ctn         The const-reference to the container.
	 * @param beginCount  The left end of the range (inclusive, in item counts).
	 * @return ContSecretCtnReadOnlyRef<ContainerType> The constructed ContSecretCtnReadOnlyRef struct
	 */
	template<typename ContainerType,
		enable_if_t<IsSecretContainer<ContainerType>::value, int> = 0>
	inline ContSecretCtnReadOnlyRef<ContainerType> SCtnItemRangeR(const ContainerType& ctn, size_t beginCount)
	{
		const size_t beginOffset = beginCount * ContainerType::sk_valSize;
		const size_t endOffset   = IsSecretContainer<ContainerType>::GetCtnSize(ctn);
		if(beginOffset > endOffset)
		{
			throw std::out_of_range("The begining of the range is outside of the container.");
		}

		return ContSecretCtnReadOnlyRef<ContainerType>(ctn, beginOffset, endOffset);
	}
}
