#include <gtest/gtest.h>

//using namespace std;

#include "TestTester.hpp"
#include "TestContainer.hpp"
#include "TestSecretArray.hpp"
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
#include "TestEcKey.hpp"

#include "TestX509Req.hpp"
#include "TestX509Crl.hpp"
#include "TestX509Cert.hpp"

#include "TestGcm.hpp"
#include "TestTlsSession.hpp"
#include "TestTlsSessTktMgr.hpp"
#include "TestTlsConfig.hpp"
#include "TestTls.hpp"

#include "TestTlsPrf.hpp"

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
