#pragma once

#include <mbedtls/hkdf.h>

#include "SKey.hpp"
#include "MsgDigestBase.hpp"
#include "Container.hpp"

#include "Exceptions.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief The standard HMAC Key Derivation Function.
	 *
	 * @tparam _HashType           The type of Hash algorithm to use.
	 * @tparam _keyLenInBits       The length of the output key in \b bits .
	 * @tparam _SContainerType     The type of the container that stores input key.
	 * @tparam _LabelContainerType The type of the container that stores the label.
	 * @tparam _SaltContainerType  The type of the container that stores the salt.
	 * @param skey  The input secret key.
	 * @param label The label for HKDF.
	 * @param salt  The salt for HKDF.
	 * @return SKey<_keyLenInBits> The output derived key.
	 */
	template<HashType _HashType,
			 size_t   _keyLenInBits,
			 typename _SContainerType,
			 typename _LabelContainerType, bool _LabelContainerSecrecy,
			 typename _SaltContainerType, bool _SaltContainerSecrecy>
	inline SKey<_keyLenInBits> Hkdf(ContCtnReadOnlyRef<_SContainerType, true> skey,
		ContCtnReadOnlyRef<_LabelContainerType, _LabelContainerSecrecy> label,
		ContCtnReadOnlyRef<_SaltContainerType, _SaltContainerSecrecy> salt)
	{
		SKey<_keyLenInBits> res;
		MBEDTLSCPP_MAKE_C_FUNC_CALL(::Hkdf, mbedtls_hkdf,
			&GetMdInfo(_HashType),
			static_cast<const unsigned char*>(salt.BeginPtr()), salt.GetRegionSize(),
			static_cast<const unsigned char*>(skey.BeginPtr()), skey.GetRegionSize(),
			static_cast<const unsigned char*>(label.BeginPtr()), label.GetRegionSize(),
			static_cast<unsigned char*>(res.Get().data()), res.Get().size()
		);

		return res;
	}
}