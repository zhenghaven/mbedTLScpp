#include <gtest/gtest.h>

#include "TestTester.hpp"
#include "TestContainer.hpp"
#include "TestSecretContainer.hpp"
#include "TestException.hpp"

#include "TestHash.hpp"
#include "TestHmac.hpp"

#include "TestCipher.hpp"
#include "TestCmac.hpp"

#include "TestEntropy.hpp"

#include "TestRbg.hpp"

#include "TestBigNumber.hpp"

#include "TestHkdf.hpp"

#include "TestSecretAllocator.hpp"
#include "TestSecretVector.hpp"
#include "TestSecretString.hpp"

#include "TestPKey.hpp"

int main(int argc, char** argv)
{
	std::cout << "===== mbed TLS cpp test program =====" << std::endl;
	std::cout << std::endl;

#ifdef MBEDTLSCPP_MEMORY_TEST
	std::cout << "      memory test: ON." << std::endl;
#else
	std::cout << "      memory test: OFF." << std::endl;
#endif

	std::cout << std::endl;
	std::cout << "===== mbed TLS cpp test start   =====" << std::endl;

	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
