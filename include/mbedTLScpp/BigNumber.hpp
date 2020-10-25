#pragma once

#include "ObjectBase.hpp"

#include <mbedtls/bignum.h>

#include <cstring>

#include "Common.hpp"
#include "Exceptions.hpp"
#include "Container.hpp"
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
		 * @brief Destroy the Big Number Base object
		 *
		 */
		virtual ~BigNumberBase()
		{}

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

		virtual void Swap(BigNumberBase& other) noexcept
		{
			ObjectBase<_BigNumTrait>::Swap(other);
		}

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

		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		int Compare(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			NullCheck();
			rhs.NullCheck();
			return mbedtls_mpi_cmp_mpi(Get(), rhs.Get());
		}

		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator==(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) == 0;
		}

		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator!=(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) != 0;
		}

		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator<(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) < 0;
		}

		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator<=(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) <= 0;
		}

		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator>(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) > 0;
		}

		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator>=(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) >= 0;
		}

		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		int Compare(_ValType rhs) const
		{
			NullCheck();
			const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
			return mbedtls_mpi_cmp_int(Get(), rhsVal);
		}

		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator==(_ValType rhs) const
		{
			return Compare(rhs) == 0;
		}

		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator!=(_ValType rhs) const
		{
			return Compare(rhs) != 0;
		}

		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator<(_ValType rhs) const
		{
			return Compare(rhs) < 0;
		}

		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator<=(_ValType rhs) const
		{
			return Compare(rhs) <= 0;
		}

		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator>(_ValType rhs) const
		{
			return Compare(rhs) > 0;
		}

		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator>=(_ValType rhs) const
		{
			return Compare(rhs) >= 0;
		}

		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		_ValType Mod(_ValType rhs) const
		{
			NullCheck();

			mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
			mbedtls_mpi_uint res = 0;
			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumberBase::Mod, mbedtls_mpi_mod_int, &res, Get(), rhsVal);

			return static_cast<_ValType>(res);
		}

		template<bool _SmlEndian = true, bool _LowerCase = true, size_t _MinWidth = 0, uint8_t _PaddingVal = 0>
		std::string Hex() const
		{
			NullCheck();

			if(_SmlEndian && _LowerCase)       // Small Endian & Lower Case
			{
				return Internal::Bytes2HexSmlEnd<_MinWidth, _PaddingVal>(
					CtnFullR(CDynArray<const uint8_t>{
						reinterpret_cast<const uint8_t*>(Get()->p),
						mbedtls_mpi_size(Get())
					}));
			}
			else if(_SmlEndian && !_LowerCase) // Small Endian & Upper Case
			{
				return Internal::Bytes2HEXSmlEnd<_MinWidth, _PaddingVal>(
					CtnFullR(CDynArray<const uint8_t>{
						reinterpret_cast<const uint8_t*>(Get()->p),
						mbedtls_mpi_size(Get())
					}));
			}
			else if(!_SmlEndian && _LowerCase) // Big Endian & Lower Case
			{
				return Internal::Bytes2HexBigEnd<_MinWidth, _PaddingVal>(
					CtnFullR(CDynArray<const uint8_t>{
						reinterpret_cast<const uint8_t*>(Get()->p),
						mbedtls_mpi_size(Get())
					}));
			}
			else                               // Big Endian & Upper Case
			{
				return Internal::Bytes2HEXBigEnd<_MinWidth, _PaddingVal>(
					CtnFullR(CDynArray<const uint8_t>{
						reinterpret_cast<const uint8_t*>(Get()->p),
						mbedtls_mpi_size(Get())
					}));
			}
		}

		template<bool _SmlEndian = true, size_t _MinWidth = 0, uint8_t _PaddingVal = 0>
		std::string Bin() const
		{
			NullCheck();

			if(_SmlEndian)       // Small Endian
			{
				return Internal::Bytes2BinSmlEnd<_MinWidth, _PaddingVal>(
					CtnFullR(CDynArray<const uint8_t>{
						reinterpret_cast<const uint8_t*>(Get()->p),
						mbedtls_mpi_size(Get())
					}));
			}
			else                // Big Endian
			{
				return Internal::Bytes2BinBigEnd<_MinWidth, _PaddingVal>(
					CtnFullR(CDynArray<const uint8_t>{
						reinterpret_cast<const uint8_t*>(Get()->p),
						mbedtls_mpi_size(Get())
					}));
			}
		}

		template<size_t _MinWidth = 0, uint8_t _PaddingCh = '0'>
		std::string Dec() const
		{
			//static constexpr int32_t divisor       = 1000000000;
			static constexpr int64_t divisor       = 1000000000000000000;
			static constexpr size_t  divisorDigits = sizeof("1000000000000000000") - 1 - 1;

			//static_assert(divisor <= std::numeric_limits<int32_t>::max(), "Programming Error.");
			NullCheck();

			std::string res;
			//int64_t rem = 0;
			mbedtls_mpi_uint rem = 0;
			BigNumberBase<DefaultBigNumObjTrait> tmp;
			BigNumberBase<DefaultBigNumObjTrait> bigRem;

			// Create an copy
			BigNumberBase<DefaultBigNumObjTrait> cpy;
			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumberBase::Dec, mbedtls_mpi_copy, cpy.Get(), Get());

			// Is positive?
			bool isPos = cpy.IsPositive();

			// To absolute value
			if (!isPos)
			{
				cpy.Get()->s = 1;
			}

			// while cpy > 0
			while (cpy > 0)
			{
				size_t midPadNeeded = (res.size() % divisorDigits);
				midPadNeeded = midPadNeeded == 0 ? 0 : (divisorDigits - midPadNeeded);

				// rem = cpy mod divisor
				// rem = cpy.Mod(divisor);

				// bignum /= divisor
				MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumberBase::Dec, mbedtls_mpi_div_int, tmp.Get(), bigRem.Get(), cpy.Get(), divisor);
				cpy.Swap(tmp);
				rem = *(bigRem.Get()->p);


				// Add str(rem) to result string.
				// std::cerr << "REM: " << std::to_string(rem) << " PadNeeded: " << midPadNeeded << " RES: " << res << std::endl;
				res = std::to_string(rem) + std::string(midPadNeeded, '0') + res;
			}

			// Add padding
			if(_MinWidth > res.size())
			{
				res = std::string(_MinWidth - res.size(), _PaddingCh) + res;
			}

			// if not positive, add '-'.
			if(!isPos)
			{
				res = '-' + res;
			}

			return res;
		}

		template<bool _SmlEndian = true>
		std::vector<uint8_t> Bytes() const
		{
			NullCheck();
			const size_t size = GetSize();
			std::vector<uint8_t> res(size);

			if (_SmlEndian) // Small Endian
			{
				std::memcpy(res.data(), Get()->p, size);
			}
			else            // Big Endian
			{
				MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumberBase::Bytes, mbedtls_mpi_write_binary, Get(), res.data(), size);
			}

			return res;
		}
	};


	/**
	 * @brief Constant Big Number allocator.
	 *
	 */
	struct ConstBigNumAllocator : DefaultAllocBase
	{
		typedef mbedtls_mpi      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{}

		static void Free(CObjType* ptr) noexcept
		{}
	};

	/**
	 * @brief Constant Big Number trait.
	 *
	 */
	using ConstBigNumObjTrait = ObjTraitBase<ConstBigNumAllocator,
									false,
									true>;

	class ConstBigNumber : public BigNumberBase<ConstBigNumObjTrait>
	{
	public:

		template<typename ContainerType>
		ConstBigNumber(ContCtnReadOnlyRef<ContainerType> data, bool isPositive = true) :
			BigNumberBase<ConstBigNumObjTrait>::BigNumberBase()
		{
			if (data.GetRegionSize() % sizeof(mbedtls_mpi_uint) != 0)
			{
				throw InvalidArgumentException("The size of data region must be a factor of the size of mbedtls_mpi_uint type.");
			}

			InternalGet()->s = isPositive ? 1 : -1;
			InternalGet()->n = data.GetRegionSize() / sizeof(mbedtls_mpi_uint);
			InternalGet()->p = static_cast<mbedtls_mpi_uint*>(const_cast<void*>(data.BeginPtr()));
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other Hasher instance.
		 */
		ConstBigNumber(ConstBigNumber&& rhs) noexcept :
			BigNumberBase<ConstBigNumObjTrait>::BigNumberBase(std::forward<BigNumberBase<ConstBigNumObjTrait> >(rhs)) //noexcept
		{}

		ConstBigNumber(const ConstBigNumber& rhs) = delete;

		/**
		 * @brief Destroy the Big Number Base object
		 *
		 */
		virtual ~ConstBigNumber()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other ConstBigNumber instance.
		 * @return ConstBigNumber& A reference to this instance.
		 */
		ConstBigNumber& operator=(ConstBigNumber&& rhs) noexcept
		{
			BigNumberBase<ConstBigNumObjTrait>::operator=(std::forward<BigNumberBase<ConstBigNumObjTrait> >(rhs)); //noexcept

			return *this;
		}

		ConstBigNumber& operator=(const ConstBigNumber& other) = delete;

		ConstBigNumber& FlipSign()
		{
			NullCheck();

			InternalGet()->s *= -1;
			return *this;
		}
	};

	class BigNumber : public BigNumberBase<DefaultBigNumObjTrait>
	{
	public:

		BigNumber() :
			BigNumberBase<DefaultBigNumObjTrait>::BigNumberBase()
		{}

		template<typename _other_BigNumTrait,
			enable_if_t<std::is_same<typename _other_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		BigNumber(const BigNumberBase<_other_BigNumTrait>& other) :
			BigNumberBase<DefaultBigNumObjTrait>::BigNumberBase()
		{
			if(other.IsNull())
			{
				FreeBaseObject();
			}
			else
			{
				MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::BigNumber, mbedtls_mpi_copy, Get(), other.Get());
			}
		}

		template<typename ContainerType>
		BigNumber(ContCtnReadOnlyRef<ContainerType> data, bool isPositive = true, bool isSmallEndian = true) :
			BigNumberBase<DefaultBigNumObjTrait>::BigNumberBase()
		{
			if (isSmallEndian)
			{
				const size_t size = data.GetRegionSize();
				const size_t extraLimb  = (size % sizeof(mbedtls_mpi_uint)) ? 1 : 0;
				const size_t totalLimbs = (size / sizeof(mbedtls_mpi_uint)) + extraLimb;
				MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::BigNumber, mbedtls_mpi_grow, Get(), totalLimbs);

				memcpy(Get()->p, data.BeginPtr(), size);
			}
			else
			{
				MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::BigNumber,
					mbedtls_mpi_read_binary,
					Get(),
					static_cast<const unsigned char*>(data.BeginPtr()),
					data.GetRegionSize())
			}

			Get()->s = isPositive ? 1 : -1;
		}

		BigNumber(mbedtls_mpi_uint val, bool isPositive = true) :
			BigNumber(CtnFullR(CDynArray<mbedtls_mpi_uint>{
						&val,
						1
					}),
			isPositive, true)
		{}

		template<typename _ValType,
			enable_if_t<std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_uint), int> = 0>
		BigNumber(_ValType val)
			: BigNumber(static_cast<mbedtls_mpi_uint>(val), true)
		{}

		template<typename _ValType,
			enable_if_t<std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_uint), int> = 0>
		BigNumber(_ValType val)
			: BigNumber(static_cast<mbedtls_mpi_uint>(val >= 0 ? val : -val), val >= 0)
		{}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other Hasher instance.
		 */
		BigNumber(BigNumber&& rhs) noexcept :
			BigNumberBase<DefaultBigNumObjTrait>::BigNumberBase(std::forward<BigNumberBase<DefaultBigNumObjTrait> >(rhs)) //noexcept
		{}

		/**
		 * @brief Destroy the Big Number Base object
		 *
		 */
		virtual ~BigNumber()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other BigNumber instance.
		 * @return BigNumber& A reference to this instance.
		 */
		BigNumber& operator=(BigNumber&& rhs) noexcept
		{
			BigNumberBase<DefaultBigNumObjTrait>::operator=(std::forward<BigNumberBase<DefaultBigNumObjTrait> >(rhs)); //noexcept

			return *this;
		}

		template<typename _rhs_BigNumTrait,
			enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		BigNumber& operator=(const BigNumberBase<_rhs_BigNumTrait>& rhs)
		{
			if (this != &rhs)
			{
				if(rhs.IsNull())
				{
					FreeBaseObject();
				}
				else
				{
					MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator=, mbedtls_mpi_copy, Get(), rhs.Get());
				}
			}
			return *this;
		}

		virtual void Swap(BigNumber& other) noexcept
		{
			BigNumberBase<DefaultBigNumObjTrait>::Swap(other);
		}

		BigNumber& FlipSign()
		{
			NullCheck();

			InternalGet()->s *= -1;
			return *this;
		}

		BigNumber & operator<<=(size_t rhs)
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator<<=, mbedtls_mpi_shift_l, Get(), rhs);

			return *this;
		}

		BigNumber & operator>>=(size_t rhs)
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator>>=, mbedtls_mpi_shift_r, Get(), rhs);

			return *this;
		}

		template<typename _rhs_BigNumTrait,
			enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		BigNumber& operator+=(const BigNumberBase<_rhs_BigNumTrait>& rhs)
		{
			NullCheck();
			rhs.NullCheck();

			// Can call it as A = A + B, see bignum.c
			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator+=, mbedtls_mpi_add_mpi, Get(), Get(), rhs.Get());

			return *this;
		}

		template<typename _rhs_ValType,
			enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		BigNumber& operator+=(_rhs_ValType rhs)
		{
			const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
			NullCheck();

			// Can call it as A = A + B, see bignum.c
			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator+=, mbedtls_mpi_add_int, Get(), Get(), rhsVal);

			return *this;
		}

		template<typename _rhs_BigNumTrait,
			enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		BigNumber& operator-=(const BigNumberBase<_rhs_BigNumTrait>& rhs)
		{
			NullCheck();
			rhs.NullCheck();

			// Can call it as A = A - B, see bignum.c
			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator-=, mbedtls_mpi_sub_mpi, Get(), Get(), rhs.Get());

			return *this;
		}

		template<typename _rhs_ValType,
			enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		BigNumber& operator-=(_rhs_ValType rhs)
		{
			const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
			NullCheck();

			// Can call it as A = A - B, see bignum.c
			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator-=, mbedtls_mpi_sub_int, Get(), Get(), rhsVal);

			return *this;
		}

		template<typename _rhs_BigNumTrait,
			enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		BigNumber& operator*=(const BigNumberBase<_rhs_BigNumTrait>& rhs)
		{
			NullCheck();
			rhs.NullCheck();

			// Can call it as A = A * B, see bignum.c
			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator*=, mbedtls_mpi_mul_mpi, Get(), Get(), rhs.Get());

			return *this;
		}

		template<typename _rhs_ValType,
			enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_uint)) ||
			(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_uint)), int> = 0>
		BigNumber& operator*=(_rhs_ValType rhs)
		{
			const bool isPos = rhs >= 0;
			const mbedtls_mpi_uint rhsVal = static_cast<mbedtls_mpi_uint>(isPos ? rhs : -rhs );
			NullCheck();

			// Can call it as A = A * B, see bignum.c
			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator*=, mbedtls_mpi_mul_int, Get(), Get(), rhsVal);
			if(!isPos)
			{
				FlipSign();
			}

			return *this;
		}

		template<typename _rhs_BigNumTrait,
			enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		BigNumber& operator/=(const BigNumberBase<_rhs_BigNumTrait>& rhs)
		{
			NullCheck();
			rhs.NullCheck();

			BigNumber res;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator/=, mbedtls_mpi_div_mpi, res.Get(), nullptr, Get(), rhs.Get());
			Swap(res);

			return *this;
		}

		template<typename _rhs_ValType,
			enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		BigNumber& operator/=(_rhs_ValType rhs)
		{
			const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
			NullCheck();

			BigNumber res;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator/=, mbedtls_mpi_div_int, res.Get(), nullptr, Get(), rhsVal);
			Swap(res);

			return *this;
		}

		template<typename _rhs_BigNumTrait,
			enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		BigNumber& operator%=(const BigNumberBase<_rhs_BigNumTrait>& rhs)
		{
			NullCheck();
			rhs.NullCheck();

			BigNumber res;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator%=, mbedtls_mpi_div_mpi, nullptr, res.Get(), Get(), rhs.Get());
			Swap(res);

			return *this;
		}

		template<typename _rhs_ValType,
			enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		BigNumber& operator%=(_rhs_ValType rhs)
		{
			const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
			NullCheck();

			BigNumber res;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator%=, mbedtls_mpi_div_int, nullptr, res.Get(), Get(), rhsVal);
			Swap(res);

			return *this;
		}

		BigNumber& operator++()
		{
			*this += 1;

			return *this;
		}

		BigNumber& operator--()
		{
			*this -= 1;

			return *this;
		}

		BigNumber operator++(int)
		{
			NullCheck();

			BigNumber res;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator++, mbedtls_mpi_add_int, res.Get(), Get(), 1);
			Swap(res);

			return res;
		}

		BigNumber operator--(int)
		{
			NullCheck();

			BigNumber res;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator--, mbedtls_mpi_sub_int, res.Get(), Get(), 1);
			Swap(res);

			return res;
		}

		BigNumber & SetBit(size_t pos, bool bit)
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::SetBit, mbedtls_mpi_set_bit, Get(), pos, bit ? 1 : 0);

			return *this;
		}


	};

	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator==(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		return rhs == lhs;
	}

	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator!=(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		return rhs != lhs;
	}

	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator>=(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		// lhs >= rhs
		return rhs <= lhs;
	}

	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator>(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		// lhs > rhs
		return rhs < lhs;
	}

	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator<=(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		// lhs <= rhs
		return rhs >= lhs;
	}

	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator<(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		// lhs < rhs
		return rhs > lhs;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator+(const BigNumberBase<_lhs_BigNumTrait>& lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		lhs.NullCheck();
		rhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator+_lhsBigNum-_rhsBigNum, mbedtls_mpi_add_mpi, res.Get(), lhs.Get(), rhs.Get());

		return res;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator-(const BigNumberBase<_lhs_BigNumTrait>& lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		lhs.NullCheck();
		rhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator-_lhsBigNum-_rhsBigNum, mbedtls_mpi_sub_mpi, res.Get(), lhs.Get(), rhs.Get());

		return res;
	}

	template<typename _rhs_BigNumTrait,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator-(const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		BigNumber cpy(rhs);
		cpy.FlipSign();
		return cpy;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator*(const BigNumberBase<_lhs_BigNumTrait>& lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		lhs.NullCheck();
		rhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator*_lhsBigNum-_rhsBigNum, mbedtls_mpi_mul_mpi, res.Get(), lhs.Get(), rhs.Get());

		return res;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator/(const BigNumberBase<_lhs_BigNumTrait>& lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		lhs.NullCheck();
		rhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator/_lhsBigNum-_rhsBigNum, mbedtls_mpi_div_mpi, res.Get(), nullptr, lhs.Get(), rhs.Get());

		return res;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator%(const BigNumberBase<_lhs_BigNumTrait>& lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		lhs.NullCheck();
		rhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator%_lhsBigNum-_rhsBigNum, mbedtls_mpi_div_mpi, nullptr, res.Get(), lhs.Get(), rhs.Get());

		return res;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber Mod(const BigNumberBase<_lhs_BigNumTrait>& lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		lhs.NullCheck();
		rhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::Mod_lhsBigNum-_rhsBigNum, mbedtls_mpi_mod_mpi, res.Get(), lhs.Get(), rhs.Get());

		return res;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_ValType,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator+(const BigNumberBase<_lhs_BigNumTrait>& lhs, _rhs_ValType rhs)
	{
		const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
		lhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator+_lhsBigNum-_rhsInt, mbedtls_mpi_add_int, res.Get(), lhs.Get(), rhsVal);

		return res;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_ValType,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator-(const BigNumberBase<_lhs_BigNumTrait>& lhs, _rhs_ValType rhs)
	{
		const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
		lhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator-_lhsBigNum-_rhsInt, mbedtls_mpi_sub_int, res.Get(), lhs.Get(), rhsVal);

		return res;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_ValType,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_uint)) ||
		(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_uint)), int> = 0>
	inline BigNumber operator*(const BigNumberBase<_lhs_BigNumTrait>& lhs, _rhs_ValType rhs)
	{
		const bool isPos = rhs >= 0;
		const mbedtls_mpi_uint rhsVal = static_cast<mbedtls_mpi_uint>(isPos ? rhs : -rhs );
		lhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator*_lhsBigNum-_rhsInt, mbedtls_mpi_mul_int, res.Get(), lhs.Get(), rhsVal);

		if(!isPos)
		{
			res.FlipSign();
		}

		return res;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_ValType,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator/(const BigNumberBase<_lhs_BigNumTrait>& lhs, _rhs_ValType rhs)
	{
		const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
		lhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator/_lhsBigNum-_rhsInt, mbedtls_mpi_div_int, res.Get(), nullptr, lhs.Get(), rhsVal);

		return res;
	}

	template<typename _lhs_BigNumTrait, typename _rhs_ValType,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_rhs_ValType>::value && std::is_signed<_rhs_ValType>::value && sizeof(_rhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_rhs_ValType>::value && std::is_unsigned<_rhs_ValType>::value && sizeof(_rhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator%(const BigNumberBase<_lhs_BigNumTrait>& lhs, _rhs_ValType rhs)
	{
		const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
		lhs.NullCheck();

		BigNumber res;

		MBEDTLSCPP_MAKE_C_FUNC_CALL(::operator%_lhsBigNum-_rhsInt, mbedtls_mpi_div_int, nullptr, res.Get(), lhs.Get(), rhsVal);

		return res;
	}

	template<typename _rhs_BigNumTrait, typename _lhs_ValType,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_lhs_ValType>::value && std::is_signed<_lhs_ValType>::value && sizeof(_lhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_lhs_ValType>::value && std::is_unsigned<_lhs_ValType>::value && sizeof(_lhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator+(_lhs_ValType lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		return rhs + lhs;
	}

	template<typename _rhs_BigNumTrait, typename _lhs_ValType,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_lhs_ValType>::value && std::is_signed<_lhs_ValType>::value && sizeof(_lhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_lhs_ValType>::value && std::is_unsigned<_lhs_ValType>::value && sizeof(_lhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator-(_lhs_ValType lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		return lhs + (-rhs);
	}

	template<typename _rhs_BigNumTrait, typename _lhs_ValType,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_lhs_ValType>::value && std::is_signed<_lhs_ValType>::value && sizeof(_lhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_lhs_ValType>::value && std::is_unsigned<_lhs_ValType>::value && sizeof(_lhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator*(_lhs_ValType lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		return rhs * lhs;
	}

	template<typename _lhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator<<(const BigNumberBase<_lhs_BigNumTrait>& lhs, size_t rhs)
	{
		BigNumber res(lhs);
		res <<= rhs;
		return res;
	}

	template<typename _lhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator>>(const BigNumberBase<_lhs_BigNumTrait>& lhs, size_t rhs)
	{
		BigNumber res(lhs);
		res >>= rhs;
		return res;
	}
}
