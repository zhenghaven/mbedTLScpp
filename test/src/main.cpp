#include <gtest/gtest.h>

#include "TestTester.hpp"
#include "TestContainer.hpp"
#include "TestSecretContainer.hpp"
#include "TestException.hpp"

#include "TestHash.hpp"
#include "TestHmac.hpp"

#include "TestCipher.hpp"
#include "TestCmac.hpp"

#include "TestBigNumber.hpp"

#include "TestEntropy.hpp"

int main(int argc, char** argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
