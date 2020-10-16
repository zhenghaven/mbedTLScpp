#include <gtest/gtest.h>

#include "TestTester.hpp"
#include "TestContainer.hpp"
#include "TestSecretContainer.hpp"
#include "TestException.hpp"

#include "TestHash.hpp"
#include "TestHmac.hpp"

int main(int argc, char** argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
