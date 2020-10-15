#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/Exceptions.hpp>
#include <mbedtls/ssl.h>
#include <mbedtls/md.h>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestException, ThrowIfErrorMacro)
{
	EXPECT_THROW(
		MBEDTLSCPP_THROW_IF_ERROR_CODE_NON_SUCCESS(MBEDTLS_ERR_SSL_INVALID_RECORD, TestCaller, TestCallee),
		mbedTLSRuntimeError);
}

GTEST_TEST(TestException, CFuncCall)
{
	EXPECT_THROW(
		MBEDTLSCPP_C_FUNC_CALL(TestCaller, mbedtls_md_setup, mbedtls_md_setup(nullptr, nullptr, false)),
		mbedTLSRuntimeError);
}

GTEST_TEST(TestException, MakeCFuncCall)
{
	EXPECT_THROW(
		MBEDTLSCPP_MAKE_C_FUNC_CALL(TestCaller, mbedtls_md_setup, nullptr, nullptr, false),
		mbedTLSRuntimeError);
}
