// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <gtest/gtest.h>

#include <mbedTLScpp/Exceptions.hpp>
#include <mbedtls/ssl.h>
#include <mbedtls/md.h>

#ifdef MBEDTLSCPPTEST_TEST_STD_NS
using namespace std;
#endif

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

namespace mbedTLScpp_Test
{
	extern size_t g_numOfTestFile;
}

GTEST_TEST(TestException, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestException, ThrowIfErrorMacro)
{
	EXPECT_THROW(
		int errCode = MBEDTLS_ERR_SSL_INVALID_RECORD;
		MBEDTLSCPP_THROW_IF_ERROR_CODE_NON_SUCCESS(
			errCode,
			TestCaller,
			TestCallee
		),
		mbedTLSRuntimeError
	);
}

GTEST_TEST(TestException, CFuncCall)
{
	EXPECT_THROW(
		MBEDTLSCPP_C_FUNC_CALL(
			TestCaller,
			mbedtls_md_setup, mbedtls_md_setup(nullptr, nullptr, false)
		),
		mbedTLSRuntimeError
	);
}

GTEST_TEST(TestException, MakeCFuncCall)
{
	EXPECT_THROW(
		MBEDTLSCPP_MAKE_C_FUNC_CALL(
			TestCaller,
			mbedtls_md_setup,
			nullptr,
			nullptr,
			false
		),
		mbedTLSRuntimeError
	);
}
