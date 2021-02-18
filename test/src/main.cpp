#include <gtest/gtest.h>

#include <mbedtls/version.h>
#include <mbedtls/threading.h>

#include <mbedTLScpp/Entropy.hpp>

#ifdef MBEDTLSCPP_MEMORY_TEST
#include <atomic> //size_t

#ifdef MBEDTLSCPPTEST_TEST_STD_NS
using namespace std;
#endif

namespace mbedTLScpp
{
	namespace Internal
	{
		std::atomic_int64_t gs_allocationLeft(0);
	}

	std::atomic_int64_t gs_secretAllocationLeft(0);
}
#endif

namespace mbedTLScpp_Test
{
	size_t g_numOfTestFile = 0;
}

int main(int argc, char** argv)
{
	constexpr size_t EXPECTED_NUM_OF_TEST_FILE = 29;

	std::cout << "===== mbed TLS cpp test program =====" << std::endl;
	std::cout << std::endl;

	std::cout << "      mbed TLS Ver: " MBEDTLS_VERSION_STRING_FULL "." << std::endl;

#ifdef MBEDTLS_CONFIG_FILE
	std::cout << "      mbed TLS Cfg: " MBEDTLS_CONFIG_FILE "." << std::endl;
#else
	std::cout << "      mbed TLS Cfg: default - config.h." << std::endl;
#endif

#ifdef MBEDTLS_THREADING_C
	std::cout << "      Thread test: ON." << std::endl;
#else
	std::cout << "      Thread test: OFF." << std::endl;
#endif

#ifdef MBEDTLSCPP_MEMORY_TEST
	std::cout << "      memory test: ON." << std::endl;
#else
	std::cout << "      memory test: OFF." << std::endl;
#endif

#ifdef MBEDTLSCPPTEST_TEST_STD_NS
	std::cout << "      std NS test: ON." << std::endl;
#else
	std::cout << "      std NS test: OFF." << std::endl;
#endif

	std::cout << std::endl;
	std::cout << "===== mbed TLS cpp test start   =====" << std::endl;

	{
		std::unique_ptr<mbedTLScpp::EntropyInterface> shared = mbedTLScpp::GetSharedEntropy();
	}

	testing::InitGoogleTest(&argc, argv);
	int testRet = RUN_ALL_TESTS();

	if (mbedTLScpp_Test::g_numOfTestFile != EXPECTED_NUM_OF_TEST_FILE)
	{
		std::cout << "********************************************************************************" << std::endl;
		std::cout << "***** WARNING: Expecting " << EXPECTED_NUM_OF_TEST_FILE;
		std::cout << " testing source files, but only ";
		std::cout << mbedTLScpp_Test::g_numOfTestFile << " were ran. *****" << std::endl;
		std::cout << "********************************************************************************" << std::endl;

		return -1;
	}

	return testRet;
}
