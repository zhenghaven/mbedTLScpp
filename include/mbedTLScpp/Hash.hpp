#pragma once

#include "MegDigestBase.hpp"

#include "Container.hpp"
#include "Exceptions.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief The container type used to store the hash result (for a known hash type).
	 *
	 * @tparam _HashTypeValue The type of the hash.
	 */
	template<HashType _HashTypeValue>
	using Hash = std::array<uint8_t, GetHashByteSize(_HashTypeValue)>;

	/**
	 * @brief The base class for Hash calculator. It can accept some raw pointer
	 *        parameters, and hash type can be specified at runtime.
	 *
	 */
	class HasherBase : public MsgDigestBase
	{
	public:

		HasherBase() = delete;

		/**
		 * @brief	Constructor. mbedtls_md_starts is called here.
		 *
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @param	mdInfo	Information describing the md.
		 */
		HasherBase(const mbedtls_md_info_t& mdInfo)  :
			MsgDigestBase(mdInfo, false)
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::HasherBase, mbedtls_md_starts, Get());
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other HasherBase instance.
		 */
		HasherBase(HasherBase&& rhs) noexcept :
			MsgDigestBase(std::forward<MsgDigestBase>(rhs))
		{}

		HasherBase(const HasherBase& rhs) = delete;

		/** @brief	Destructor */
		virtual ~HasherBase()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other HasherBase instance.
		 * @return HasherBase& A reference to this instance.
		 */
		HasherBase& operator=(HasherBase&& rhs) noexcept
		{
			MsgDigestBase::operator=(std::forward<MsgDigestBase>(rhs));

			return *this;
		}

		HasherBase& operator=(const HasherBase& other) = delete;

		/**
		 * @brief Updates the calculation with the given data.
		 *
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam ContainerType The type of the container that stores the data.
		 * @param data The data to be hashed.
		 */
		template<typename ContainerType>
		void Update(ContCtnReadOnlyRef<ContainerType> data)
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::Update, mbedtls_md_update,
				Get(),
				static_cast<const unsigned char*>(data.BeginPtr()),
				data.GetRegionSize());
		}

		/**
		 * @brief Finishes the hash calculation and get the hash result.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @return std::vector<uint8_t> The hash result.
		 */
		std::vector<uint8_t> Finish()
		{
			NullCheck();

			const size_t size = mbedtls_md_get_size(Get()->md_info);
			std::vector<uint8_t> hash(size);

			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::Finish, mbedtls_md_finish,
				Get(),
				static_cast<unsigned char*>(hash.data()));

			return hash;
		}

		/**
		 * @brief Restart the hash calculation, so that the previous hash state
		 *        will be wiped out. It's useful if you want to reuse the same
		 *        hasher instance.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 */
		void Restart()
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::HasherBase, mbedtls_md_starts, Get());
		}

	protected:

		void Update(const void* data, size_t size)
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::Update, mbedtls_md_update,
				Get(),
				static_cast<const unsigned char*>(data),
				size);
		}
	};

	/**
	 * @brief The hash calculator. Only accept C++ objects as parameters, and
	 *        hash type must be specified at compile time.
	 *
	 * @tparam _HashTypeValue
	 */
	template<HashType _HashTypeValue>
	class Hasher : public HasherBase
	{
	public: //static members:
		static constexpr size_t sk_hashByteSize = GetHashByteSize(_HashTypeValue);

	public:

		/**
		 * @brief Construct a new Hasher object
		 *
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 */
		Hasher() :
			HasherBase(MsgDigestBase::GetMdInfo(_HashTypeValue))
		{}

		/**
		 * @brief Destroy the Hasher object
		 *
		 */
		virtual ~Hasher()
		{}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other Hasher instance.
		 */
		Hasher(Hasher&& rhs) noexcept :
			HasherBase(std::forward<HasherBase>(rhs)) //noexcept
		{}

		Hasher(const Hasher& rhs) = delete;

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other Hasher instance.
		 * @return Hasher& A reference to this instance.
		 */
		Hasher& operator=(Hasher&& rhs) noexcept
		{
			HasherBase::operator=(std::forward<HasherBase>(rhs)); //noexcept

			return *this;
		}

		Hasher& operator=(const Hasher& other) = delete;

		/**
		 * @brief Finishes the hash calculation and get the hash result.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @return Hash<_HashTypeValue> The hash result.
		 */
		Hash<_HashTypeValue> Finish()
		{
			NullCheck();

			return FinishNoCheck();
		}

		/**
		 * @brief Update the hash calculation with a list of Input Data Items.
		 *        NOTE: This function will not clean the previous state, thus,
		 *        it will update the calculation state based on the existing state;
		 *        Thus, you may need to call restart first.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam ListLen The length of the list.
		 * @param list The list of Input Data Items.
		 * @return Hash<_HashTypeValue> The hash result.
		 */
		template<size_t ListLen>
		Hash<_HashTypeValue> CalcList(const InDataList<ListLen>& list)
		{
			NullCheck();

			for(auto it = list.begin(); it != list.end(); ++it)
			{
				Update(it->m_data, it->m_size);
			}

			return FinishNoCheck();
		}

		/**
		 * @brief Update the hash calculation with a sequence of containers wrapped
		 *        by ContCtnReadOnlyRef. The sequence of containers can be in any
		 *        length.
		 *        NOTE: This function will not clean the previous state, thus,
		 *        it will update the calculation state based on the existing state;
		 *        Thus, you may need to call restart first.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam Args The type of the container wrapped by ContCtnReadOnlyRef
		 * @param args The container.
		 * @return Hash<_HashTypeValue> The hash result.
		 */
		template<class... Args>
		Hash<_HashTypeValue> Calc(ContCtnReadOnlyRef<Args>... args)
		{
			return CalcList(ConstructInDataList(args...));
		}

	private:

		Hash<_HashTypeValue> FinishNoCheck()
		{
			Hash<_HashTypeValue> hash;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(Hasher::Finish, mbedtls_md_finish,
				Get(),
				static_cast<unsigned char*>(hash.data()));

			return hash;
		}
	};
}
