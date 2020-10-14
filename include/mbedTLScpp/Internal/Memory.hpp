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
		std::atomic_int64_t gs_allocationLeft(0);
#endif

		template<typename T, class... _Args>
		inline T* NewObject(_Args&&... __args)
		{
#ifdef MBEDTLSCPP_TEST
			gs_allocationLeft++;
#endif

			return new T(std::forward<_Args>(__args)...);
		}

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
