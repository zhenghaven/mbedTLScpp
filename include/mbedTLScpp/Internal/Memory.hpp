#pragma once

#ifdef MBEDTLSCPP_TEST
#include <atomic> //size_t
#endif

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	namespace Internal
	{
#ifdef MBEDTLSCPP_TEST
		/**
		 * @brief The count for memory allocation.
		 *        It's only used for memory leak testing.
		 *
		 */
		std::atomic_int64_t gs_allocationLeft(0);
#endif

		/**
		 * @brief Allocate memory address for given object type.
		 *
		 * @tparam T The type of object to allocate space for.
		 * @tparam _Args The type of data used for constructor.
		 * @param __args The data used for constructor.
		 * @return T* The memory address.
		 */
		template<typename T, class... _Args>
		inline T* NewObject(_Args&&... __args)
		{
#ifdef MBEDTLSCPP_TEST
			gs_allocationLeft++;
#endif

			return new T(std::forward<_Args>(__args)...);
		}

		/**
		 * @brief Deallocate the memory the was allocated by NewObject.
		 *
		 * @tparam T The type of object to be deallocated.
		 * @param ptr The pointer to the object that needs to be deleted.
		 */
		template<typename T>
		inline void DelObject(T* ptr)
		{
#ifdef MBEDTLSCPP_TEST
			gs_allocationLeft--;
#endif

			delete ptr;
		}
	}
}
