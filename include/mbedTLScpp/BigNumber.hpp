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

	/**
	 * @brief The base class for big number objects. It defines all the basic and
	 *        constant (immutable) operations.
	 *
	 * @tparam _BigNumTrait The trait of big number.
	 */
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
		 * @exception None No exception thrown
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
		 * @exception None No exception thrown
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

		/**
		 * @brief Swap the internal pointer of a Big Number base object with the
		 *        same trait.
		 *
		 * @exception None No exception thrown
		 * @param other The other big number object to swap with
		 */
		virtual void Swap(BigNumberBase& other) noexcept
		{
			ObjectBase<_BigNumTrait>::Swap(other);
		}

		/**
		 * @brief Is the big number positive?
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @return true If it's positive number
		 * @return false If it's negative number
		 */
		bool IsPositive() const
		{
			NullCheck();
			return Get()->s > 0;
		}

		/**
		 * @brief Get the size of the number in granularity of bytes.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @return size_t the size of the number in bytes.
		 */
		size_t GetSize() const
		{
			NullCheck();
			return mbedtls_mpi_size(Get());
		}

		/**
		 * @brief Get the size of the number in granularity of bits.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @return size_t the size of the number in bits.
		 */
		size_t GetBitSize() const
		{
			NullCheck();
			return mbedtls_mpi_bitlen(Get());
		}

		/**
		 * @brief Get the value of a individual bit.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @param pos The position of the bit to get.
		 * @return bool true - 1, false - 0;
		 */
		bool GetBit(const size_t pos) const
		{
			NullCheck();
			return mbedtls_mpi_get_bit(Get(), pos) == 1;
		}

		/**
		 * @brief Compare this big number with another big number.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number in
		 *                          right hand side.
		 * @param rhs The right hand side of the comparasion.
		 *
		 * @return \c 1  if \p this is greater than \p rhs.
		 * @return \c -1 if \p this is lesser than  \p rhs.
		 * @return \c 0  if \p this is equal to     \p rhs.
		 */
		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		int Compare(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			NullCheck();
			rhs.NullCheck();
			return mbedtls_mpi_cmp_mpi(Get(), rhs.Get());
		}

		/**
		 * @brief Overloading \p operator== .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number in
		 *                          right hand side.
		 * @param rhs The right hand side.
		 * @return bool \c true if both side are equal; \c false if otherwise.
		 */
		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator==(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) == 0;
		}

		/**
		 * @brief Overloading \p operator!= .
		 *
		 * @tparam _rhs_BigNumTrait The trait used by the other big number in
		 *                          right hand side.
		 * @param rhs The right hand side.
		 * @return bool \c true if both side are not equal; \c false if otherwise.
		 */
		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator!=(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) != 0;
		}

		/**
		 * @brief Overloading \p operator< .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number in
		 *                          right hand side.
		 * @param rhs The right hand side.
		 * @return bool \c true if \p LHS is less than \p RHS; \c false if otherwise.
		 */
		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator<(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) < 0;
		}

		/**
		 * @brief Overloading \p operator<= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number in
		 *                          right hand side.
		 * @param rhs The right hand side.
		 * @return bool \c true if \p LHS is less than or equal to \p RHS; \c false if otherwise.
		 */
		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator<=(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) <= 0;
		}

		/**
		 * @brief Overloading \p operator> .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number in
		 *                          right hand side.
		 * @param rhs The right hand side.
		 * @return bool \c true if \p LHS is greater than \p RHS; \c false if otherwise.
		 */
		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator>(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) > 0;
		}

		/**
		 * @brief Overloading \p operator>= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number in
		 *                          right hand side.
		 * @param rhs The right hand side.
		 * @return bool \c true if \p LHS is greater than or equal to \p RHS; \c false if otherwise.
		 */
		template<typename _rhs_BigNumTrait,
				enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
		bool operator>=(const BigNumberBase<_rhs_BigNumTrait> & rhs) const
		{
			return Compare(rhs) >= 0;
		}

		/**
		 * @brief Compare this big number with a integral number.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _ValType The type of the integral number.
		 * @param rhs The right hand side of the comparasion.
		 *
		 * @return \c 1  if \p this is greater than \p rhs.
		 * @return \c -1 if \p this is lesser than  \p rhs.
		 * @return \c 0  if \p this is equal to     \p rhs.
		 */
		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		int Compare(_ValType rhs) const
		{
			NullCheck();
			const mbedtls_mpi_sint rhsVal = static_cast<mbedtls_mpi_sint>(rhs);
			return mbedtls_mpi_cmp_int(Get(), rhsVal);
		}

		/**
		 * @brief Overloading \p operator== .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return bool \c true if both side are equal; \c false if otherwise.
		 */
		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator==(_ValType rhs) const
		{
			return Compare(rhs) == 0;
		}

		/**
		 * @brief Overloading \p operator!= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return bool \c true if both side are not equal; \c false if otherwise.
		 */
		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator!=(_ValType rhs) const
		{
			return Compare(rhs) != 0;
		}

		/**
		 * @brief Overloading \p operator< .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return bool \c true if \p LHS is less than \p RHS; \c false if otherwise.
		 */
		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator<(_ValType rhs) const
		{
			return Compare(rhs) < 0;
		}

		/**
		 * @brief Overloading \p operator<= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return bool \c true if \p LHS is less than or equal to \p RHS; \c false if otherwise.
		 */
		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator<=(_ValType rhs) const
		{
			return Compare(rhs) <= 0;
		}

		/**
		 * @brief Overloading \p operator> .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return bool \c true if \p LHS is greater than \p RHS; \c false if otherwise.
		 */
		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator>(_ValType rhs) const
		{
			return Compare(rhs) > 0;
		}

		/**
		 * @brief Overloading \p operator>= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam _ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return bool \c true if \p LHS is greater than or equal to \p RHS; \c false if otherwise.
		 */
		template<typename _ValType,
			enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
			(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
		bool operator>=(_ValType rhs) const
		{
			return Compare(rhs) >= 0;
		}

		/**
		 * @brief Calculate the modulo value with a given integral number.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return _ValType The result of calculation.
		 */
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

		/**
		 * @brief Convert this big number to a hex string. This string doesn't
		 *        contain neither the \c '0x' prefix nor the negative sign.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 * @tparam _LitEndian  Should output in little-endian format? (Default to \c true )
		 * @tparam _LowerCase  Should output alphabet in lower case? (Default to \c true )
		 * @tparam _MinWidth   The minmum width of the output string, in bytes. (Default to \c 0 )
		 * @tparam _PaddingVal The byte value used for padding to get to the minimum width.
		 * @return std::string The output hex string.
		 */
		template<bool _LitEndian = true, bool _LowerCase = true, size_t _MinWidth = 0, uint8_t _PaddingVal = 0>
		std::string Hex() const
		{
			NullCheck();

			if(_LitEndian && _LowerCase)       // Little Endian & Lower Case
			{
				return Internal::Bytes2HexLitEnd<_MinWidth, _PaddingVal>(
					CtnFullR(CDynArray<const uint8_t>{
						reinterpret_cast<const uint8_t*>(Get()->p),
						mbedtls_mpi_size(Get())
					}));
			}
			else if(_LitEndian && !_LowerCase) // Little Endian & Upper Case
			{
				return Internal::Bytes2HEXLitEnd<_MinWidth, _PaddingVal>(
					CtnFullR(CDynArray<const uint8_t>{
						reinterpret_cast<const uint8_t*>(Get()->p),
						mbedtls_mpi_size(Get())
					}));
			}
			else if(!_LitEndian && _LowerCase) // Big Endian & Lower Case
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

		/**
		 * @brief Convert this big number to a binary string with \c 0 's and \c 1 's.
		 *        This string doesn't contain neither \c '0b' prefix nor the negative sign.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 * @tparam _LitEndian  Should output in little-endian format? (Default to \c true )
		 * @tparam _MinWidth   The minmum width of the output string, in bytes. (Default to \c 0 )
		 * @tparam _PaddingVal The byte value used for padding to get to the minimum width.
		 * @return std::string The output binary string.
		 */
		template<bool _LitEndian = true, size_t _MinWidth = 0, uint8_t _PaddingVal = 0>
		std::string Bin() const
		{
			NullCheck();

			if(_LitEndian)       // Little Endian
			{
				return Internal::Bytes2BinLitEnd<_MinWidth, _PaddingVal>(
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

		/**
		 * @brief Convert this big number to a human-readable decimal number string.
		 *        This string contain the negative sign.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 * @tparam _MinWidth The minmum width of the output string, in number of chractors. (Default to \c 0 )
		 * @tparam _PaddingCh The chractor used for padding to get to the minimum width.
		 * @return std::string The output string.
		 */
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

		/**
		 * @brief Convert this big number to an array of bytes.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 * @tparam _LitEndian Should output in little-endian format? (Default to \c true )
		 * @return std::vector<uint8_t> The output array of bytes.
		 */
		template<bool _LitEndian = true>
		std::vector<uint8_t> Bytes() const
		{
			NullCheck();
			const size_t size = GetSize();
			std::vector<uint8_t> res(size);

			if (_LitEndian) // Little Endian
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

	/**
	 * @brief A big number class used to share a little-endian bytes array to use
	 *        as a big number object.
	 *        NOTE: This object doesn't own the array, instead, it only share the
	 *        array. Thus, the array shared with must be alive before this object
	 *        is destroyed.
	 *
	 */
	class ConstBigNumber : public BigNumberBase<ConstBigNumObjTrait>
	{
	public:

		/**
		 * @brief Construct a new Const Big Number object with a reference to an
		 *        existing container.
		 *
		 * @exception InvalidArgumentException Thrown when data size can't fit in whole mbedtls_mpi_uint.
		 * @exception std::bad_alloc           Thrown when memory allocation failed.
		 * @tparam ContainerType The type of the container.
		 * @param data The container stores the data.
		 * @param isPositive Should it be a positive number (since we assume the
		 *                   byte array only stores unsigned value)?
		 */
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
		 * @exception None No exception thrown
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
		 * @exception None No exception thrown
		 * @param rhs The other ConstBigNumber instance.
		 * @return ConstBigNumber& A reference to this instance.
		 */
		ConstBigNumber& operator=(ConstBigNumber&& rhs) noexcept
		{
			BigNumberBase<ConstBigNumObjTrait>::operator=(std::forward<BigNumberBase<ConstBigNumObjTrait> >(rhs)); //noexcept

			return *this;
		}

		ConstBigNumber& operator=(const ConstBigNumber& other) = delete;

		/**
		 * @brief Flip the sign of the big number. The sign is a extra piece info
		 *        owned only by this object, thus, we can mutate it.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @return ConstBigNumber& A reference to this instance.
		 */
		ConstBigNumber& FlipSign()
		{
			NullCheck();

			InternalGet()->s *= -1;
			return *this;
		}
	};

	/**
	 * @brief The class for a normal Big Number object.
	 *
	 */
	class BigNumber : public BigNumberBase<DefaultBigNumObjTrait>
	{
	public:

		/**
		 * @brief Construct a new Big Number object, which is initialized, but
		 *        with zero value.
		 *
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 *
		 */
		BigNumber() :
			BigNumberBase<DefaultBigNumObjTrait>::BigNumberBase()
		{}

		/**
		 * @brief Construct a new Big Number object by copying other BigNumber.
		 *        If \c other is null, then this instance will be null as well.
		 *        Otherwise, deep copy will be performed.
		 *
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 * @tparam _other_BigNumTrait The trait used by the other big number.
		 * @param other The other big number to copy from.
		 */
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

		/**
		 * @brief Construct a new Big Number object by copying bytes from a byte array.
		 *
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 * @tparam ContainerType The type of the data container.
		 * @param data The reference to data container.
		 * @param isPositive Should the constructed big number be positive?
		 *                   (since we assume the byte array only stores
		 *                   unsigned value)
		 * @param isLittleEndian Is the input bytes in little-endian format?
		 */
		template<typename ContainerType>
		BigNumber(ContCtnReadOnlyRef<ContainerType> data, bool isPositive = true, bool isLittleEndian = true) :
			BigNumberBase<DefaultBigNumObjTrait>::BigNumberBase()
		{
			if (isLittleEndian)
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

		/**
		 * @brief Construct a new Big Number object by copying value from a native integral value.
		 *
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 * @param val The value to copy from.
		 * @param isPositive Should the constructed big number be positive?
		 *                   (since here we accpet an unsigned value)
		 */
		BigNumber(mbedtls_mpi_uint val, bool isPositive = true) :
			BigNumber(CtnFullR(CDynArray<mbedtls_mpi_uint>{
						&val,
						1
					}),
			isPositive, true)
		{}


		/**
		 * @brief Construct a new Big Number object by copying value from a native integral value.
		 *
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 * @tparam _ValType The type of the integral number.
		 *                  It should be an unsigned type.
		 *                  Thus, the constructed big number will be positive.
		 * @param val The value to copy from.
		 */
		template<typename _ValType,
			enable_if_t<std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_uint), int> = 0>
		BigNumber(_ValType val)
			: BigNumber(static_cast<mbedtls_mpi_uint>(val), true)
		{}

		/**
		 * @brief Construct a new Big Number object by copying value from a native integral value.
		 *
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @exception std::bad_alloc Thrown when memory allocation failed.
		 * @tparam _ValType The type of the integral number. It should be an signed type.
		 * @param val The value to copy from.
		 */
		template<typename _ValType,
			enable_if_t<std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_uint), int> = 0>
		BigNumber(_ValType val)
			: BigNumber(static_cast<mbedtls_mpi_uint>(val >= 0 ? val : -val), val >= 0)
		{}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
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
		 * @exception None No exception thrown
		 * @param rhs The other BigNumber instance.
		 * @return BigNumber& A reference to this instance.
		 */
		BigNumber& operator=(BigNumber&& rhs) noexcept
		{
			BigNumberBase<DefaultBigNumObjTrait>::operator=(std::forward<BigNumberBase<DefaultBigNumObjTrait> >(rhs)); //noexcept

			return *this;
		}

		/**
		 * @brief Copy assignment. If \c RHS is null, then this instance will become
		 *        null as well. Otherwise, deep copy will be performed.
		 *
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_BigNumTrait The trait used by the \c RHS big number.
		 * @param rhs The number in right hand side.
		 * @return BigNumber& The reference to this instance.
		 */
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

		/**
		 * @brief Swap the internal pointer of a Big Number base object with the
		 *        same trait.
		 *
		 * @exception None No exception thrown
		 * @param other The other big number object to swap with
		 */
		virtual void Swap(BigNumber& other) noexcept
		{
			BigNumberBase<DefaultBigNumObjTrait>::Swap(other);
		}

		/**
		 * @brief Flip the sign of the big number.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @return ConstBigNumber& A reference to this instance.
		 */
		BigNumber& FlipSign()
		{
			NullCheck();

			InternalGet()->s *= -1;
			return *this;
		}

		/**
		 * @brief Overloading \p operator<<= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @param rhs The value on right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
		BigNumber & operator<<=(size_t rhs)
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator<<=, mbedtls_mpi_shift_l, Get(), rhs);

			return *this;
		}

		/**
		 * @brief Overloading \p operator>>= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @param rhs The value on right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
		BigNumber & operator>>=(size_t rhs)
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator>>=, mbedtls_mpi_shift_r, Get(), rhs);

			return *this;
		}

		/**
		 * @brief Overloading \p operator+= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number on
		 *                          right hand side.
		 * @param rhs The value on right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator+= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator-= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number on
		 *                          right hand side.
		 * @param rhs The value on right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator-= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator*= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number on
		 *                          right hand side.
		 * @param rhs The value on right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator*= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator/= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number on
		 *                          right hand side.
		 * @param rhs The value on right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator/= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator%= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_BigNumTrait The trait used by the other big number on
		 *                          right hand side.
		 * @param rhs The value on right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator%= .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @tparam _rhs_ValType The type of the integral number.
		 * @param rhs The right hand side.
		 * @return BigNumber& A reference to this instance.
		 */
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

		/**
		 * @brief Overloading \p operator++ .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @return BigNumber& A reference to this instance.
		 */
		BigNumber& operator++()
		{
			*this += 1;

			return *this;
		}

		/**
		 * @brief Overloading \p operator-- .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @return BigNumber& A reference to this instance.
		 */
		BigNumber& operator--()
		{
			*this -= 1;

			return *this;
		}

		/**
		 * @brief Overloading \p operator++ .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @return BigNumber& A reference to this instance.
		 */
		BigNumber operator++(int)
		{
			NullCheck();

			BigNumber res;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator++, mbedtls_mpi_add_int, res.Get(), Get(), 1);
			Swap(res);

			return res;
		}

		/**
		 * @brief Overloading \p operator-- .
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @return BigNumber& A reference to this instance.
		 */
		BigNumber operator--(int)
		{
			NullCheck();

			BigNumber res;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::operator--, mbedtls_mpi_sub_int, res.Get(), Get(), 1);
			Swap(res);

			return res;
		}

		/**
		 * @brief Set an individual bit in the big number.
		 *
		 * @exception InvalidObjectException Thrown when one or more given objects are
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @param pos The position of the bit to set.
		 * @param bit The bit value: \c true - 1, \c false - 0.
		 * @return BigNumber& A reference to this instance.
		 */
		BigNumber & SetBit(size_t pos, bool bit)
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(BigNumber::SetBit, mbedtls_mpi_set_bit, Get(), pos, bit ? 1 : 0);

			return *this;
		}


	};

	/**
	 * @brief Overloading \p operator== .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _ValType The type of the native integral number on left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number in
	 *                          right hand side.
	 * @param lhs The left hand side.
	 * @param rhs The right hand side.
	 * @return bool \c true if both side are equal; \c false if otherwise.
	 */
	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator==(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		return rhs == lhs;
	}

	/**
	 * @brief Overloading \p operator!= .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _ValType The type of the native integral number on left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number in
	 *                          right hand side.
	 * @param lhs The left hand side.
	 * @param rhs The right hand side.
	 * @return bool \c true if both side are not equal; \c false if otherwise.
	 */
	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator!=(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		return rhs != lhs;
	}

	/**
	 * @brief Overloading \p operator>= .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _ValType The type of the native integral number on left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number in
	 *                          right hand side.
	 * @param lhs The left hand side.
	 * @param rhs The right hand side.
	 * @return bool \c true if \p LHS is greater than or equal to \p RHS; \c false if otherwise.
	 */
	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator>=(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		// lhs >= rhs
		return rhs <= lhs;
	}

	/**
	 * @brief Overloading \p operator> .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _ValType The type of the native integral number on left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number in
	 *                          right hand side.
	 * @param lhs The left hand side.
	 * @param rhs The right hand side.
	 * @return bool \c true if \p LHS is greater than \p RHS; \c false if otherwise.
	 */
	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator>(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		// lhs > rhs
		return rhs < lhs;
	}

	/**
	 * @brief Overloading \p operator< .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _ValType The type of the native integral number on left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number in
	 *                          right hand side.
	 * @param lhs The left hand side.
	 * @param rhs The right hand side.
	 * @return bool \c true if \p LHS is less than or equal to \p RHS; \c false if otherwise.
	 */
	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator<=(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		// lhs <= rhs
		return rhs >= lhs;
	}

	/**
	 * @brief Overloading \p operator< .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _ValType The type of the native integral number on left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number in
	 *                          right hand side.
	 * @param lhs The left hand side.
	 * @param rhs The right hand side.
	 * @return bool \c true if \p LHS is less than \p RHS; \c false if otherwise.
	 */
	template<typename _ValType, typename _BigNumTrait,
		enable_if_t<(std::is_integral<_ValType>::value && std::is_signed<_ValType>::value && sizeof(_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_ValType>::value && std::is_unsigned<_ValType>::value && sizeof(_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0,
		enable_if_t<std::is_same<typename _BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline bool operator<(_ValType lhs, const BigNumberBase<_BigNumTrait> & rhs)
	{
		// lhs < rhs
		return rhs > lhs;
	}

	/**
	 * @brief Overloading \p operator+ .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator- .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator- (negation operator).
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
	template<typename _rhs_BigNumTrait,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator-(const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		BigNumber cpy(rhs);
		cpy.FlipSign();
		return cpy;
	}

	/**
	 * @brief Overloading \p operator* .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator/ .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator% .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Calculate modulo of two big numbers.
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator+ .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_ValType     The type of the native integral number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator- .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_ValType     The type of the native integral number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator* .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_ValType     The type of the native integral number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator/ .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_ValType     The type of the native integral number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator% .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @tparam _rhs_ValType     The type of the native integral number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
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

	/**
	 * @brief Overloading \p operator+ .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_ValType     The type of the native integral number on
	 *                          left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
	template<typename _rhs_BigNumTrait, typename _lhs_ValType,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_lhs_ValType>::value && std::is_signed<_lhs_ValType>::value && sizeof(_lhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_lhs_ValType>::value && std::is_unsigned<_lhs_ValType>::value && sizeof(_lhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator+(_lhs_ValType lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		return rhs + lhs;
	}

	/**
	 * @brief Overloading \p operator- .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_ValType     The type of the native integral number on
	 *                          left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
	template<typename _rhs_BigNumTrait, typename _lhs_ValType,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_lhs_ValType>::value && std::is_signed<_lhs_ValType>::value && sizeof(_lhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_lhs_ValType>::value && std::is_unsigned<_lhs_ValType>::value && sizeof(_lhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator-(_lhs_ValType lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		return lhs + (-rhs);
	}

	/**
	 * @brief Overloading \p operator* .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_ValType     The type of the native integral number on
	 *                          left hand side.
	 * @tparam _rhs_BigNumTrait The trait used by the other big number on
	 *                          right hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
	template<typename _rhs_BigNumTrait, typename _lhs_ValType,
		enable_if_t<std::is_same<typename _rhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0,
		enable_if_t<(std::is_integral<_lhs_ValType>::value && std::is_signed<_lhs_ValType>::value && sizeof(_lhs_ValType) <= sizeof(mbedtls_mpi_sint)) ||
		(std::is_integral<_lhs_ValType>::value && std::is_unsigned<_lhs_ValType>::value && sizeof(_lhs_ValType) < sizeof(mbedtls_mpi_sint)), int> = 0>
	inline BigNumber operator*(_lhs_ValType lhs, const BigNumberBase<_rhs_BigNumTrait>& rhs)
	{
		return rhs * lhs;
	}

	/**
	 * @brief Overloading \p operator<< .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
	template<typename _lhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator<<(const BigNumberBase<_lhs_BigNumTrait>& lhs, size_t rhs)
	{
		BigNumber res(lhs);
		res <<= rhs;
		return res;
	}

	/**
	 * @brief Overloading \p operator>> .
	 *
	 * @exception InvalidObjectException Thrown when one or more given objects are
	 *                                   holding a null pointer for the C mbed TLS
	 *                                   object.
	 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
	 * @tparam _lhs_BigNumTrait The trait used by the other big number on
	 *                          left hand side.
	 * @param lhs The value on left hand side.
	 * @param rhs The value on right hand side.
	 * @return BigNumber The result of calculation, a new Big Number object.
	 */
	template<typename _lhs_BigNumTrait,
		enable_if_t<std::is_same<typename _lhs_BigNumTrait::CObjType, mbedtls_mpi>::value, int> = 0>
	inline BigNumber operator>>(const BigNumberBase<_lhs_BigNumTrait>& lhs, size_t rhs)
	{
		BigNumber res(lhs);
		res >>= rhs;
		return res;
	}
}
