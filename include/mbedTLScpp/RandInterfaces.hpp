#pragma once

#include <cstddef>

#include <memory>
#include <type_traits>

#include <mbedtls/error.h>

#include "Common.hpp"
#include "Exceptions.hpp"
#include "Container.hpp"
#include "Internal/make_unique.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	class RbgInterface
	{
	public: // Static member:

		/**
		 * @brief	Call back function provided for mbedTLS library call back needs.
		 *
		 * @param [in,out]	ctx	The pointer point to a RbgInterface instance. Must not null.
		 * @param [out]	  	buf	The buffer to be filled with random bits.
		 * @param 		  	len	The length of the buffer.
		 *
		 * @return	mbedTLS errorcode.
		 */
		static int CallBack(void * ctx, unsigned char * buf, size_t len) noexcept
		{
			if (ctx == nullptr)
			{
				return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
				// Or MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ? which one is better?
			}

			try
			{
				RbgInterface* rbg = static_cast<RbgInterface*>(ctx);
				rbg->Rand(buf, len);
				return MBEDTLS_EXIT_SUCCESS;
			}
			catch (const mbedTLSRuntimeError& e)
			{
				return e.GetErrorCode();
			}
			catch (...)
			{
				return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
			}
		}

	public:
		RbgInterface() = default;

		virtual ~RbgInterface()
		{}

		/**
		 * @brief	Generate Random bits to fill the given buffer.
		 *
		 * @param [in,out]	buf 	The buffer to store the generated random bits.
		 * @param 		  	size	The size.
		 */
		virtual void Rand(void* buf, const size_t size) = 0;

		/**
		 * @brief Generate Random bits to fill a given C standard structs
		 *        (including primitive types).
		 *
		 * @tparam T   The type of the struct.
		 * @param stru A reference to the struct.
		 */
		template<typename T,
			enable_if_t<IsCTypeAlike<T>::value, int> = 0>
		void RandStruct(T& stru)
		{
			Rand(&stru, sizeof(T));
		}

		/**
		 * @brief Get a random number
		 *
		 * @tparam ResultType The type of the number.
		 * @return ResultType The generated random number.
		 */
		template<typename ResultType,
			enable_if_t<std::is_signed<ResultType>::value || std::is_unsigned<ResultType>::value, int> = 0>
		ResultType GetRand()
		{
			ResultType res;
			RandStruct(res);
			return res;
		}
	};

	/**
	 * @brief A wrapper for Random Bit Generator, so that RBGs can be used with
	 *        standard C++ libraries such as uniform_int_distribution, etc.
	 *
	 * @tparam _UIntType              The unsigned int type that will be
	 *                                generated by this RBG wrap.
	 * @tparam _RbgType               The RBG class
	 * @tparam _HasDefaultConstructor Does the RBG class has default constructor?
	 */
	template<typename _UIntType, typename _RbgType,
		bool _HasDefaultConstructor = true,
		enable_if_t<std::is_unsigned<_UIntType>::value, int> = 0,
		enable_if_t<std::is_base_of<RbgInterface, _RbgType>::value, int> = 0>
	class RbgCppWrap
	{
	public: // Static members:

		using ResultType = _UIntType;

		using result_type = ResultType;

		using RbgType = _RbgType;

		static constexpr ResultType max()
		{
			return std::numeric_limits<ResultType>::max();
		}

		static constexpr ResultType min()
		{
			return std::numeric_limits<ResultType>::min();
		}

	public:

		template<bool _dummy_HasDefault = _HasDefaultConstructor,
			enable_if_t<_dummy_HasDefault, int> = 0>
		RbgCppWrap() :
			m_rbg(Internal::make_unique<RbgType>())
		{}

		RbgCppWrap(std::unique_ptr<RbgInterface> rbg) :
			m_rbg(std::move(rbg))
		{}

		virtual ~RbgCppWrap()
		{}

		ResultType operator()()
		{
			ResultType res;
			m_rbg->RandStruct(res);
			return res;
		}

	private:
		std::unique_ptr<RbgInterface> m_rbg;
	};
}
