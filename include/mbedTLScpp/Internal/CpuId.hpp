#pragma once

#include <cstdint>

#include <tuple>
#include <type_traits>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	namespace Internal
	{
		std::tuple<uint32_t, uint32_t, uint32_t, uint32_t>
			RunCpuid(uint32_t func, uint32_t subfunc)
		{
			static_assert(std::is_same<uint32_t, unsigned int>::value, "Programming Error.");

			uint32_t eax = 0;
			uint32_t ebx = 0;
			uint32_t ecx = 0;
			uint32_t edx = 0;

			asm volatile("cpuid"
						: "=a" (eax),
						  "=b" (ebx),
						  "=c" (ecx),
						  "=d" (edx)
						: "a"  (func),
						  "c"  (subfunc)
			);

			return std::make_tuple(eax, ebx, ecx, edx);
		}
	}
}
