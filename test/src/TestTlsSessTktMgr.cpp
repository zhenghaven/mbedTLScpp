#include <gtest/gtest.h>

#include <mbedTLScpp/TlsSession.hpp>
#include <mbedTLScpp/TlsSessTktMgr.hpp>

#include "MemoryTest.hpp"

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

GTEST_TEST(TestTlsSessTktMgr, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestTlsSessTktMgr, TlsSessTktMgrClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM> tlsSess1;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM> tlsSess2;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tlsSess1 = std::move(tlsSess1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tlsSess1 = std::move(tlsSess2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM> tlsSess3(std::move(tlsSess1));

		// This should success.
		tlsSess3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(tlsSess1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(tlsSess2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestTlsSessTktMgr, TlsSessTktMgrFunc)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM> tlsSessMgr;
		TlsSession tlsSess;

		tlsSess.Get()->id_len = 32;
		uint8_t id[32] = {
			0,1,2,3,4,5,6,7,
			0,1,2,3,4,5,6,7,
			0,1,2,3,4,5,6,7,
			0,1,2,3,4,5,6,7,
		};
		std::copy(std::begin(id), std::begin(id), std::begin(tlsSess.Get()->id));
		tlsSess.Get()->start = mbedtls_time(NULL);

		std::vector<uint8_t> buf(2048);
		size_t   len = 0;
		uint32_t lifetime = 0;
		tlsSessMgr.Write(*tlsSess.Get(),
			buf.data(), buf.data() + buf.size(), len, lifetime);

		tlsSessMgr.Parse(*tlsSess.Get(),
			buf.data(), len);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
