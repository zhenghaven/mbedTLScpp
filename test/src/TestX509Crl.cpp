#include <gtest/gtest.h>

#include <mbedTLScpp/X509Crl.hpp>

#include "SharedVars.hpp"
#include "MemoryTest.hpp"
#include "SelfMoveTest.hpp"


namespace mbedTLScpp_Test
{
	extern size_t g_numOfTestFile;
}


#ifdef MBEDTLSCPPTEST_TEST_STD_NS
using namespace std;
#endif

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

using namespace mbedTLScpp_Test;


GTEST_TEST(TestX509Crl, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestX509Crl, X509CrlClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		X509Crl crl1 = X509Crl::FromPEM(
			std::string(GetTestX509CrlPem().data())
		);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		X509Crl crl2 = X509Crl::FromDER(CtnFullR(crl1.GetDer()));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		MBEDTLSCPPTEST_SELF_MOVE_TEST(crl1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		crl1 = std::move(crl2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		X509Crl crl3(std::move(crl1));

		// This should success.
		crl3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(crl1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(crl2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestX509Crl, X509CrlExport)
{
	X509Crl crl = X509Crl::FromPEM(
		std::string(GetTestX509CrlPem().data())
	);

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EXPECT_NO_THROW(X509Crl crl1 = X509Crl::FromPEM(crl.GetPem()););
		EXPECT_NO_THROW(X509Crl crl1 = X509Crl::FromDER(CtnFullR(crl.GetDer())););
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
