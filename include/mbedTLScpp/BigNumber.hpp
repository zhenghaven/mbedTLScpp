#pragma once

#include "ObjectBase.hpp"

#include <mbedtls/bignum.h>

#include "Common.hpp"
#include "Exceptions.hpp"
#include "Internal/Codec.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{

	/**
	 * @brief Normal Big Number allocator.
	 *
	 */
	struct BigNumAllocator : DefaultAllocBase
	{
		typedef mbedtls_mpi      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_mpi_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_mpi_free(ptr);
		}
	};

	/**
	 * @brief Normal Big Number trait.
	 *
	 */
	using DefaultBigNumObjTrait = ObjTraitBase<BigNumAllocator,
									false,
									false>;

	template<typename _BigNumTrait,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	class BigNumberBase : public ObjectBase<_BigNumTrait>
	{
	public: //static members:

		using BigNumTrait = _BigNumTrait;
		static constexpr bool sk_isConst = BigNumTrait::sk_isConst;
		static constexpr bool sk_isBorrower = BigNumTrait::sk_isBorrower;

	public:

		using ObjectBase<BigNumTrait>::ObjectBase;

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other Hasher instance.
		 */
		BigNumberBase(BigNumberBase&& rhs) noexcept :
			ObjectBase<BigNumTrait>::ObjectBase(std::forward<ObjectBase<BigNumTrait> >(rhs)) //noexcept
		{}

		BigNumberBase(const BigNumberBase& rhs) = delete;

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other BigNumberBase instance.
		 * @return BigNumberBase& A reference to this instance.
		 */
		BigNumberBase& operator=(BigNumberBase&& rhs) noexcept
		{
			ObjectBase<BigNumTrait>::operator=(std::forward<ObjectBase<BigNumTrait> >(rhs)); //noexcept

			return *this;
		}

		BigNumberBase& operator=(const BigNumberBase& other) = delete;

		/**
		 * @brief Check if the current instance is holding a null pointer for
		 *        the mbedTLS object. If so, exception will be thrown. Helper
		 *        function to be called before accessing the mbedTLS object.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 */
		virtual void NullCheck() const
		{
			ObjectBase<BigNumTrait>::NullCheck(typeid(BigNumberBase).name());
		}

		using ObjectBase<BigNumTrait>::Get;


		bool IsPositive() const
		{
			NullCheck();
			return Get()->s > 0;
		}


		size_t GetSize() const
		{
			NullCheck();
			return mbedtls_mpi_size(Get());
		}

		size_t GetBitSize() const
		{
			NullCheck();
			return mbedtls_mpi_bitlen(Get());
		}

		bool GetBit(const size_t pos) const
		{
			NullCheck();
			return mbedtls_mpi_get_bit(Get(), pos) == 1;
		}

		template<bool _SmlEndian = true, bool _LowerCase = true>
		std::string Hex() const
		{
			NullCheck();

			if(_SmlEndian && _LowerCase)       // Small Endian & Lower Case
			{
				return Internal::Bytes2HexSmlEnd(CtnFullR(CDynArray<mbedtls_mpi_uint>{Get()->p, Get()->n}));
			}
			else if(_SmlEndian && !_LowerCase) // Small Endian & Upper Case
			{
				return Internal::Bytes2HEXSmlEnd(CtnFullR(CDynArray<mbedtls_mpi_uint>{Get()->p, Get()->n}));
			}
			else if(!_SmlEndian && _LowerCase) // Big Endian & Lower Case
			{
				return Internal::Bytes2HexBigEnd(CtnFullR(CDynArray<mbedtls_mpi_uint>{Get()->p, Get()->n}));
			}
			else                               // Big Endian & Upper Case
			{
				return Internal::Bytes2HEXBigEnd(CtnFullR(CDynArray<mbedtls_mpi_uint>{Get()->p, Get()->n}));
			}
		}

		int Compare(const BigNumberBase & rhs) const
		{
			NullCheck();
			rhs.NullCheck();
			return mbedtls_mpi_cmp_mpi(Get(), rhs.Get());
		}


		bool operator==(const BigNumberBase & rhs) const
		{
			return Compare(rhs) == 0;
		}

		bool operator!=(const BigNumberBase & rhs) const
		{
			return Compare(rhs) != 0;
		}

		bool operator<(const BigNumberBase & rhs) const
		{
			return Compare(rhs) < 0;
		}

		bool operator<=(const BigNumberBase & rhs) const
		{
			return Compare(rhs) <= 0;
		}

		bool operator>(const BigNumberBase & rhs) const
		{
			return Compare(rhs) > 0;
		}

		bool operator>=(const BigNumberBase & rhs) const
		{
			return Compare(rhs) >= 0;
		}

		mbedtls_mpi_uint operator%(mbedtls_mpi_sint rhs) const
		{
			//static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit integers.");
			NullCheck();

			mbedtls_mpi_uint res = 0;
			CALL_MBEDTLS_C_FUNC(mbedtls_mpi_mod_int, &res, Get(), rhs);

			return res;
		}
	};
}