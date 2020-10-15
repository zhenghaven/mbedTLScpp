#include <gtest/gtest.h>

#include "TestTester.hpp"
#include "TestContainer.hpp"
#include "TestException.hpp"

#include "TestHash.hpp"

int main(int argc, char** argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
