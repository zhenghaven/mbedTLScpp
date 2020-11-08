#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/SecretAllocator.hpp>

#include <vector>
#include <string>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestSecretAllocator, SecretAllocatorWithStl)
{
	int64_t initCount = 0;
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initCount);

	{
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);

		std::vector<uint8_t, SecretAllocator<uint8_t> > uint8Vec(50);
		EXPECT_EQ(uint8Vec.size(), 50);

		for (size_t i = 0; i < uint8Vec.size(); ++i)
		{
			uint8Vec[i] = static_cast<uint8_t>(i);
		}
		for (size_t i = 0; i < uint8Vec.size(); ++i)
		{
			EXPECT_EQ(uint8Vec[i], static_cast<uint8_t>(i));
		}

		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initCount, 50);

		uint8Vec.resize(120);
		EXPECT_EQ(uint8Vec.size(), 120);

		for (size_t i = 0; i < 50; ++i)
		{
			EXPECT_EQ(uint8Vec[i], static_cast<uint8_t>(i));
		}
		for (size_t i = 0; i < uint8Vec.size(); ++i)
		{
			uint8Vec[i] = static_cast<uint8_t>(i);
		}
		for (size_t i = 0; i < uint8Vec.size(); ++i)
		{
			EXPECT_EQ(uint8Vec[i], static_cast<uint8_t>(i));
		}

		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initCount, 120);
	}

	{
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);

		std::vector<uint32_t, SecretAllocator<uint32_t> > uint32Vec(50);
		EXPECT_EQ(uint32Vec.size(), 50);

		for (size_t i = 0; i < uint32Vec.size(); ++i)
		{
			uint32Vec[i] = static_cast<uint8_t>(i);
		}
		for (size_t i = 0; i < uint32Vec.size(); ++i)
		{
			EXPECT_EQ(uint32Vec[i], static_cast<uint8_t>(i));
		}

		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initCount, 50);

		uint32Vec.resize(120);
		EXPECT_EQ(uint32Vec.size(), 120);

		for (size_t i = 0; i < 50; ++i)
		{
			EXPECT_EQ(uint32Vec[i], i);
		}
		for (size_t i = 0; i < uint32Vec.size(); ++i)
		{
			uint32Vec[i] = static_cast<uint8_t>(i);
		}
		for (size_t i = 0; i < uint32Vec.size(); ++i)
		{
			EXPECT_EQ(uint32Vec[i], static_cast<uint8_t>(i));
		}

		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initCount, 120);
	}

	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}
