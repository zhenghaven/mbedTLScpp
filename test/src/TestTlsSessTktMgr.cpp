#include <gtest/gtest.h>

#include <mbedTLScpp/DefaultRbg.hpp>
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

#ifdef MBEDTLS_THREADING_C
	static constexpr bool gsk_threadEnabled = true;
#else
	static constexpr bool gsk_threadEnabled = false;
#endif

GTEST_TEST(TestTlsSessTktMgr, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestTlsSessTktMgr, TlsSessTktMgrClass)
{
	using TestingTktMgtType =
		TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM, 86400>;

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		TestingTktMgtType tlsSess1(Internal::make_unique<DefaultRbg>());

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2 + (gsk_threadEnabled ? 2 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		TestingTktMgtType tlsSess2(Internal::make_unique<DefaultRbg>());

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4 + (gsk_threadEnabled ? 4 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tlsSess1 = std::move(tlsSess1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4 + (gsk_threadEnabled ? 4 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		tlsSess1 = std::move(tlsSess2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2 + (gsk_threadEnabled ? 2 : 0));
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		TestingTktMgtType tlsSess3(std::move(tlsSess1));

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
	using TestingTktMgtType =
		TlsSessTktMgr<CipherType::AES, 256, CipherMode::GCM, 86400>;

	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		TestingTktMgtType tlsSessMgr(Internal::make_unique<DefaultRbg>());
		TlsSession tlsSess;

		tlsSess.Get()->MBEDTLS_PRIVATE(tls_version) =
			mbedtls_ssl_protocol_version::MBEDTLS_SSL_VERSION_TLS1_2;
		tlsSess.Get()->MBEDTLS_PRIVATE(id_len) = 32;
		uint8_t id[32] = {
			0,1,2,3,4,5,6,7,
			0,1,2,3,4,5,6,7,
			0,1,2,3,4,5,6,7,
			0,1,2,3,4,5,6,7,
		};
		std::copy(
			std::begin(id),
			std::begin(id),
			std::begin(tlsSess.Get()->MBEDTLS_PRIVATE(id))
		);
		tlsSess.Get()->MBEDTLS_PRIVATE(start) = mbedtls_time(NULL);

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
