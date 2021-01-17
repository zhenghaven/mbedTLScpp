macro(mbedTLScpp_UseMbedtlsHeaders_Normal arg_mbedtls_target)
	target_include_directories(${arg_mbedtls_target}
		PUBLIC
			$<BUILD_INTERFACE:$ENV{MBEDTLSCPP_MBEDTLS_HEADERS}/common>
			$<INSTALL_INTERFACE:include/mbedTLScpp/mbedtls-headers/common>
			$<BUILD_INTERFACE:$ENV{MBEDTLSCPP_MBEDTLS_HEADERS}/normal>
			$<INSTALL_INTERFACE:include/mbedTLScpp/mbedtls-headers/normal>
	)
	target_compile_definitions(${arg_mbedtls_target}
		PUBLIC
			MBEDTLS_CONFIG_FILE="mbedtlscpp-config.h"
	)
endmacro()

macro(mbedTLScpp_UseMbedtlsHeaders_Enclave arg_mbedtls_target)
	target_include_directories(${arg_mbedtls_target}
		PUBLIC
			$<BUILD_INTERFACE:$ENV{MBEDTLSCPP_MBEDTLS_HEADERS}/common>
			$<INSTALL_INTERFACE:include/mbedTLScpp/mbedtls-headers/common>
			$<BUILD_INTERFACE:$ENV{MBEDTLSCPP_MBEDTLS_HEADERS}/enclave>
			$<INSTALL_INTERFACE:include/mbedTLScpp/mbedtls-headers/enclave>
	)
	target_compile_definitions(${arg_mbedtls_target}
		PUBLIC
			MBEDTLS_CONFIG_FILE="mbedtlscpp-config.h"
	)
endmacro()
