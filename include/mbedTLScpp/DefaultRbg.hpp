#pragma once

#ifndef MBEDTLSCPP_CUSTOMIZED_DEFAULT_RBG
#include "CtrDrbg.hpp"
#else
MBEDTLSCPP_CUSTOMIZED_DEFAULT_RBG
#endif

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
#ifndef MBEDTLSCPP_CUSTOMIZED_DEFAULT_RBG
	using DefaultRbg = CtrDrbg<>;
#endif
}
