# Copyright (c) 2022 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.


include_guard()


macro(mbedTLScpp_UseMbedtlsHeaders_Normal arg_mbedtls_target)
	target_include_directories(${arg_mbedtls_target}
		PUBLIC
			$<BUILD_INTERFACE:${MBEDTLSCPP_MBEDTLS_HEADERS}/common>
			$<INSTALL_INTERFACE:include/mbedTLScpp/mbedtls-headers/common>
			$<BUILD_INTERFACE:${MBEDTLSCPP_MBEDTLS_HEADERS}/normal>
			$<INSTALL_INTERFACE:include/mbedTLScpp/mbedtls-headers/normal>
	)
	target_compile_definitions(${arg_mbedtls_target}
		PUBLIC
			MBEDTLS_CONFIG_FILE="mbedtlscpp_config.h"
	)
endmacro()

macro(mbedTLScpp_UseMbedtlsHeaders_Enclave arg_mbedtls_target)
	target_include_directories(${arg_mbedtls_target}
		PUBLIC
			$<BUILD_INTERFACE:${MBEDTLSCPP_MBEDTLS_HEADERS}/common>
			$<INSTALL_INTERFACE:include/mbedTLScpp/mbedtls-headers/common>
			$<BUILD_INTERFACE:${MBEDTLSCPP_MBEDTLS_HEADERS}/enclave>
			$<INSTALL_INTERFACE:include/mbedTLScpp/mbedtls-headers/enclave>
	)
	target_compile_definitions(${arg_mbedtls_target}
		PUBLIC
			MBEDTLS_CONFIG_FILE="mbedtlscpp_config.h"
	)
endmacro()
