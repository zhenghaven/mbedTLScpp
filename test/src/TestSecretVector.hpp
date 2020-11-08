#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/SecretVector.hpp>

#include <vector>
#include <string>
#include <list>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestSecretVector, ConstructEmpty)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// Default constructor, empty test
	{
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		SecretVector<MemTestObj<int> > vec1;

		EXPECT_EQ(vec1.data(), nullptr);

		EXPECT_EQ(vec1.size(), 0);

		EXPECT_EQ(vec1.capacity(), 0);

		EXPECT_EQ(vec1.max_size(), std::numeric_limits<size_t>::max());

		EXPECT_TRUE(vec1.empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, ConstructFill)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// bytes, fill constructor, content test
	{
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		SecretVector<MemTestObj<int> > vec1(15, 112);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 15);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 15);

		EXPECT_NE(vec1.data(), nullptr);

		EXPECT_EQ(vec1.size(), 15);

		EXPECT_EQ(vec1.capacity(), 15);

		EXPECT_FALSE(vec1.empty());

		// content test
		for(size_t i = 0; i < vec1.size(); ++i)
		{
			EXPECT_EQ(vec1[i].Data(), 112);
			EXPECT_EQ(&vec1[i], vec1.data() + i);
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// objects, fill with default constructor, content test
	{
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		SecretVector<MemTestObj<int> > vec1(15);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 15);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 15);

		EXPECT_NE(vec1.data(), nullptr);

		EXPECT_EQ(vec1.size(), 15);

		EXPECT_EQ(vec1.capacity(), 15);

		EXPECT_FALSE(vec1.empty());

		// content test
		for(size_t i = 0; i < vec1.size(); ++i)
		{
			EXPECT_EQ(vec1[i].Data(), 0);
			EXPECT_EQ(&vec1[i], vec1.data() + i);
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, ConstructIterator)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// copy iterator construct, copy construct, content test
	{
		std::list<MemTestObj<int> >   expList1 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::list<MemTestObj<int> >   expList2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// example list:
		SecretVector<MemTestObj<int> > secVec1(expList1.begin(), expList1.end());
		std::vector <MemTestObj<int> > stdVec1(expList2.begin(), expList2.end());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_NE(secVec1.data(), nullptr);
		EXPECT_LE(secVec1.size(), secVec1.capacity());

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		// Copy vector
		SecretVector<MemTestObj<int> > secVec2(secVec1);
		std::vector <MemTestObj<int> > stdVec2(stdVec1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 20 + 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 10);

		EXPECT_NE(secVec2.data(), nullptr);
		EXPECT_LE(secVec2.size(), secVec2.capacity());

		EXPECT_EQ(secVec2.size(),  stdVec2.size());
		EXPECT_EQ(secVec2.empty(), stdVec2.empty());

		for(size_t i = 0; i < secVec2.size(); ++i)
		{
			EXPECT_EQ(secVec2[i].Data(), stdVec2[i].Data());
		}

		// example vector:
		SecretVector<MemTestObj<int> > secVec3(expVec1.begin(), expVec1.end());
		std::vector <MemTestObj<int> > stdVec3(expVec2.begin(), expVec2.end());

		EXPECT_NE(secVec3.data(), nullptr);
		EXPECT_LE(secVec3.size(), secVec3.capacity());

		EXPECT_EQ(secVec3.size(),  stdVec3.size());
		EXPECT_EQ(secVec3.empty(), stdVec3.empty());

		for(size_t i = 0; i < secVec2.size(); ++i)
		{
			EXPECT_EQ(secVec3[i].Data(), stdVec3[i].Data());
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	// Move iterator construct, move construct, content test
	{
		std::list<MemTestObj<int> >   expList1 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::list<MemTestObj<int> >   expList2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// example list:
		SecretVector<MemTestObj<int> > secVec1(std::make_move_iterator(expList1.begin()), std::make_move_iterator(expList1.end()));
		std::vector <MemTestObj<int> > stdVec1(std::make_move_iterator(expList2.begin()), std::make_move_iterator(expList2.end()));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_NE(secVec1.data(), nullptr);
		EXPECT_LE(secVec1.size(), secVec1.capacity());

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		EXPECT_LE(secVec1.size(), expList1.size());
		for(const auto& item : expList1)
		{
			EXPECT_EQ(item.Empty(), true);
		}

		// Move vector
		SecretVector<MemTestObj<int> > secVec2(std::move(secVec1));
		std::vector <MemTestObj<int> > stdVec2(std::move(stdVec1));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_NE(secVec2.data(), nullptr);
		EXPECT_LE(secVec2.size(), secVec2.capacity());

		EXPECT_EQ(secVec2.size(),  stdVec2.size());
		EXPECT_EQ(secVec2.empty(), stdVec2.empty());

		for(size_t i = 0; i < secVec2.size(); ++i)
		{
			EXPECT_EQ(secVec2[i].Data(), stdVec2[i].Data());
		}

		EXPECT_EQ(secVec1.data(),     nullptr);
		EXPECT_EQ(secVec1.size(),     0);
		EXPECT_EQ(secVec1.capacity(), 0);
		EXPECT_EQ(secVec1.empty(),    true);

		// example vector:
		SecretVector<MemTestObj<int> > secVec3(std::make_move_iterator(expVec1.begin()), std::make_move_iterator(expVec1.end()));
		std::vector <MemTestObj<int> > stdVec3(std::make_move_iterator(expVec2.begin()), std::make_move_iterator(expVec2.end()));

		EXPECT_NE(secVec3.data(), nullptr);
		EXPECT_LE(secVec3.size(), secVec3.capacity());

		EXPECT_EQ(secVec3.size(),  stdVec3.size());
		EXPECT_EQ(secVec3.empty(), stdVec3.empty());

		for(size_t i = 0; i < secVec2.size(); ++i)
		{
			EXPECT_EQ(secVec3[i].Data(), stdVec3[i].Data());
		}

		EXPECT_LE(expVec1.size(), expVec1.size());
		for(const auto& item : expVec1)
		{
			EXPECT_EQ(item.Empty(), true);
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, PushBack)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// push back re-alloc, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		// push back re-alloc
		secVec1.push_back(10);
		stdVec1.push_back(10);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		// push back no alloc
		secVec1.push_back(11);
		stdVec1.push_back(11);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// push back move re-alloc, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MemTestObj<int> secPs1(10);
		MemTestObj<int> stdPs1(10);
		MemTestObj<int> secPs2(11);
		MemTestObj<int> stdPs2(11);

		EXPECT_FALSE(secPs1.Empty());
		EXPECT_FALSE(stdPs1.Empty());
		EXPECT_FALSE(secPs2.Empty());
		EXPECT_FALSE(stdPs2.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		// push back re-alloc
		secVec1.push_back(std::move(secPs1));
		stdVec1.push_back(std::move(stdPs1));

		EXPECT_TRUE(secPs1.Empty());
		EXPECT_TRUE(stdPs1.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		// push back no alloc
		secVec1.push_back(std::move(secPs2));
		stdVec1.push_back(std::move(stdPs2));

		EXPECT_TRUE(secPs2.Empty());
		EXPECT_TRUE(stdPs2.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, PopBack)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// pop back, make sure it's deallocated
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 10);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		secVec1.pop_back();

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 9);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, emplace)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// emplace back, re-alloc, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		// push back re-alloc
		secVec1.emplace_back(10);
		stdVec1.emplace_back(10);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		// push back no alloc
		secVec1.push_back(11);
		stdVec1.push_back(11);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// emplace, somewhere middle, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		// push back re-alloc
		secVec1.emplace(secVec1.begin() + 7, 7);
		stdVec1.emplace(stdVec1.begin() + 7, 7);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		// push back no alloc
		secVec1.emplace(secVec1.begin(), 0);
		stdVec1.emplace(stdVec1.begin(), 0);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, InsertSingle)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// copy, at end, re-alloc, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.end(), 10);
		stdVec1.insert(stdVec1.end(), 10);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.end(), 11);
		stdVec1.insert(stdVec1.end(), 11);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// copy, at begin, re-alloc, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cbegin(), 10);
		stdVec1.insert(stdVec1.cbegin(), 10);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin(), 11);
		stdVec1.insert(stdVec1.cbegin(), 11);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// copy, at middle, re-alloc, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cbegin() + 5, 10);
		stdVec1.insert(stdVec1.cbegin() + 5, 10);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin() + 5, 11);
		stdVec1.insert(stdVec1.cbegin() + 5, 11);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 2 + 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// move, at end, re-alloc, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MemTestObj<int> secPs1(10);
		MemTestObj<int> stdPs1(10);
		MemTestObj<int> secPs2(11);
		MemTestObj<int> stdPs2(11);

		EXPECT_FALSE(secPs1.Empty());
		EXPECT_FALSE(stdPs1.Empty());
		EXPECT_FALSE(secPs2.Empty());
		EXPECT_FALSE(stdPs2.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.end(), std::move(secPs1));
		stdVec1.insert(stdVec1.end(), std::move(stdPs1));

		EXPECT_TRUE(secPs1.Empty());
		EXPECT_TRUE(stdPs1.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.end(), std::move(secPs2));
		stdVec1.insert(stdVec1.end(), std::move(stdPs2));

		EXPECT_TRUE(secPs2.Empty());
		EXPECT_TRUE(stdPs2.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// move, at begin, re-alloc, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MemTestObj<int> secPs1(10);
		MemTestObj<int> stdPs1(10);
		MemTestObj<int> secPs2(11);
		MemTestObj<int> stdPs2(11);

		EXPECT_FALSE(secPs1.Empty());
		EXPECT_FALSE(stdPs1.Empty());
		EXPECT_FALSE(secPs2.Empty());
		EXPECT_FALSE(stdPs2.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cbegin(), std::move(secPs1));
		stdVec1.insert(stdVec1.cbegin(), std::move(stdPs1));

		EXPECT_TRUE(secPs1.Empty());
		EXPECT_TRUE(stdPs1.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin(), std::move(secPs2));
		stdVec1.insert(stdVec1.cbegin(), std::move(stdPs2));

		EXPECT_TRUE(secPs2.Empty());
		EXPECT_TRUE(stdPs2.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// move, at middle, re-alloc, no alloc
	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MemTestObj<int> secPs1(10);
		MemTestObj<int> stdPs1(10);
		MemTestObj<int> secPs2(11);
		MemTestObj<int> stdPs2(11);

		EXPECT_FALSE(secPs1.Empty());
		EXPECT_FALSE(stdPs1.Empty());
		EXPECT_FALSE(secPs2.Empty());
		EXPECT_FALSE(stdPs2.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cbegin() + 5, std::move(secPs1));
		stdVec1.insert(stdVec1.cbegin() + 5, std::move(stdPs1));

		EXPECT_TRUE(secPs1.Empty());
		EXPECT_TRUE(stdPs1.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin() + 5, std::move(secPs2));
		stdVec1.insert(stdVec1.cbegin() + 5, std::move(stdPs2));

		EXPECT_TRUE(secPs2.Empty());
		EXPECT_TRUE(stdPs2.Empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, InsertFill)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// at end, re-alloc, no alloc
	{
		// Empty container
		SecretVector<MemTestObj<int> > secVec1;
		std::vector <MemTestObj<int> > stdVec1;

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		secVec1.insert(secVec1.cbegin(), 15, 125); // 15, re-alloc
		stdVec1.insert(stdVec1.cbegin(), 15, 125);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 30);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 15);

		EXPECT_EQ(secVec1.capacity(), 15);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		// assign with something already there.

		secVec1.insert(secVec1.end(), 10, 15); // 25, no-alloc
		stdVec1.insert(stdVec1.end(), 10, 15);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 30 + 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 30);

		EXPECT_EQ(secVec1.capacity(), 30);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin() + 20, 20, 256); // 45, re-alloc
		stdVec1.insert(stdVec1.cbegin() + 20, 20, 256);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 30 + 20 + 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 60);

		EXPECT_EQ(secVec1.capacity(), 60);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin() + 10, 10, 512); // 55, no-alloc
		stdVec1.insert(stdVec1.cbegin() + 10, 10, 512);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 30 + 20 + 40 + 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 60);

		EXPECT_EQ(secVec1.capacity(), 60);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.end(), 20, 128); // 75, re-alloc
		stdVec1.insert(stdVec1.end(), 20, 128);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 30 + 20 + 40 + 20 + 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 120);

		EXPECT_EQ(secVec1.capacity(), 120);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, InsertCopy)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// copy, at end, re-alloc, no alloc
	{
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cend(), expVec1.begin(), expVec1.begin() + 5); // 15 re-alloc
		stdVec1.insert(stdVec1.cend(), expVec2.begin(), expVec2.begin() + 5);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 10);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cend(), expVec1.begin() + 5, expVec1.begin() + 7); // 17 no-alloc
		stdVec1.insert(stdVec1.cend(), expVec2.begin() + 5, expVec2.begin() + 7);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 10 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// copy, at middle, re-alloc, no alloc
	{
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cbegin() + 5, expVec1.begin(), expVec1.begin() + 2); // 12 re-alloc
		stdVec1.insert(stdVec1.cbegin() + 5, expVec2.begin(), expVec2.begin() + 2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin() + 10, expVec1.begin() + 2, expVec1.begin() + 7); // 17 no-alloc
		stdVec1.insert(stdVec1.cbegin() + 10, expVec2.begin() + 2, expVec2.begin() + 7);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 4 + 10);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin() + 10, expVec1.begin() + 7, expVec1.begin() + 9); // 19 no-alloc
		stdVec1.insert(stdVec1.cbegin() + 10, expVec2.begin() + 7, expVec2.begin() + 9);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 4 + 10 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// copy, at begining, re-alloc, no alloc
	{
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cbegin(), expVec1.begin(), expVec1.begin() + 5); // 15 re-alloc
		stdVec1.insert(stdVec1.cbegin(), expVec2.begin(), expVec2.begin() + 5);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 10);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin(), expVec1.begin() + 5, expVec1.begin() + 7); // 17 no-alloc
		stdVec1.insert(stdVec1.cbegin(), expVec2.begin() + 5, expVec2.begin() + 7);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40 + 10 + 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// move, at end, re-alloc, no alloc
	{
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cend(), std::make_move_iterator(expVec1.begin()), std::make_move_iterator(expVec1.begin()) + 5); // 15 re-alloc
		stdVec1.insert(stdVec1.cend(), std::make_move_iterator(expVec2.begin()), std::make_move_iterator(expVec2.begin()) + 5);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cend(), std::make_move_iterator(expVec1.begin()) + 5, std::make_move_iterator(expVec1.begin()) + 7); // 17 no-alloc
		stdVec1.insert(stdVec1.cend(), std::make_move_iterator(expVec2.begin()) + 5, std::make_move_iterator(expVec2.begin()) + 7);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// move, at middle, re-alloc, no alloc
	{
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cbegin() + 5, std::make_move_iterator(expVec1.begin()), std::make_move_iterator(expVec1.begin()) + 2); // 12 re-alloc
		stdVec1.insert(stdVec1.cbegin() + 5, std::make_move_iterator(expVec2.begin()), std::make_move_iterator(expVec2.begin()) + 2);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin() + 10, std::make_move_iterator(expVec1.begin()) + 2, std::make_move_iterator(expVec1.begin()) + 7); // 17 no-alloc
		stdVec1.insert(stdVec1.cbegin() + 10, std::make_move_iterator(expVec2.begin()) + 2, std::make_move_iterator(expVec2.begin()) + 7);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin() + 10, std::make_move_iterator(expVec1.begin()) + 7, std::make_move_iterator(expVec1.begin()) + 9); // 19 no-alloc
		stdVec1.insert(stdVec1.cbegin() + 10, std::make_move_iterator(expVec2.begin()) + 7, std::make_move_iterator(expVec2.begin()) + 9);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// move, at begining, re-alloc, no alloc
	{
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		secVec1.insert(secVec1.cbegin(), std::make_move_iterator(expVec1.begin()), std::make_move_iterator(expVec1.begin()) + 5); // 15 re-alloc
		stdVec1.insert(stdVec1.cbegin(), std::make_move_iterator(expVec2.begin()), std::make_move_iterator(expVec2.begin()) + 5);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.insert(secVec1.cbegin(), std::make_move_iterator(expVec1.begin()) + 5, std::make_move_iterator(expVec1.begin()) + 7); // 17 no-alloc
		stdVec1.insert(stdVec1.cbegin(), std::make_move_iterator(expVec2.begin()) + 5, std::make_move_iterator(expVec2.begin()) + 7);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, EraseSingle)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		// first element
		secVec1.erase(secVec1.cbegin());
		stdVec1.erase(stdVec1.cbegin());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 - 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		// somewhere middle
		secVec1.erase(secVec1.cbegin() + 5);
		stdVec1.erase(stdVec1.cbegin() + 5);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 - 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		// last element
		secVec1.erase(secVec1.cend() - 1);
		stdVec1.erase(stdVec1.cend() - 1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 - 6);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, EraseRange)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretVector<MemTestObj<int> > secVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		std::vector <MemTestObj<int> > stdVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		// leading elements
		secVec1.erase(secVec1.cbegin(), secVec1.cbegin() + 3);
		stdVec1.erase(stdVec1.cbegin(), stdVec1.cbegin() + 3);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 - 6);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		// somewhere middle
		secVec1.erase(secVec1.cbegin() + 5, secVec1.cbegin() + 7);
		stdVec1.erase(stdVec1.cbegin() + 5, stdVec1.cbegin() + 7);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 - 6 - 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		// tail elements
		secVec1.erase(secVec1.cend() - 3, secVec1.cend());
		stdVec1.erase(stdVec1.cend() - 3, stdVec1.cend());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20 - 6 - 4 - 6);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10);

		EXPECT_EQ(secVec1.capacity(), 10);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, AssignFill)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		// Empty container
		SecretVector<MemTestObj<int> > secVec1;
		std::vector <MemTestObj<int> > stdVec1;

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		secVec1.assign(15, 125);
		stdVec1.assign(15, 125);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 30);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 15);

		EXPECT_EQ(secVec1.capacity(), 15);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		// assign with something already there.

		secVec1.assign(10, 15);
		stdVec1.assign(10, 15);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 15);

		EXPECT_EQ(secVec1.capacity(), 15);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.assign(20, 256);
		stdVec1.assign(20, 256);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretVector, AssignRange)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// copy
	{
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // 50
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // 50

		// Empty container
		SecretVector<MemTestObj<int> > secVec1;
		std::vector <MemTestObj<int> > stdVec1;

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 100);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		secVec1.assign(expVec1.begin(), expVec1.begin() + 15);
		stdVec1.assign(expVec2.begin(), expVec2.begin() + 15);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 100 + 30);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 15);

		EXPECT_EQ(secVec1.capacity(), 15);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		// assign with something already there.

		secVec1.assign(expVec1.begin() + 15, expVec1.begin() + 25);
		stdVec1.assign(expVec2.begin() + 15, expVec2.begin() + 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 100 + 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 15);

		EXPECT_EQ(secVec1.capacity(), 15);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.assign(expVec1.begin() + 25, expVec1.begin() + 45);
		stdVec1.assign(expVec2.begin() + 25, expVec2.begin() + 45);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 100 + 40);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}
	}

	// move
	{
		std::vector<MemTestObj<int> > expVec1  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // 50
		std::vector<MemTestObj<int> > expVec2  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // 50

		// Empty container
		SecretVector<MemTestObj<int> > secVec1;
		std::vector <MemTestObj<int> > stdVec1;

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 100);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		secVec1.assign(std::make_move_iterator(expVec1.begin()), std::make_move_iterator(expVec1.begin()) + 15);
		stdVec1.assign(std::make_move_iterator(expVec2.begin()), std::make_move_iterator(expVec2.begin()) + 15);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 100);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 15);

		EXPECT_EQ(secVec1.capacity(), 15);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		// assign with something already there.

		secVec1.assign(std::make_move_iterator(expVec1.begin()) + 15, std::make_move_iterator(expVec1.begin()) + 25);
		stdVec1.assign(std::make_move_iterator(expVec2.begin()) + 15, std::make_move_iterator(expVec2.begin()) + 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 100 - 30);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 15);

		EXPECT_EQ(secVec1.capacity(), 15);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		secVec1.assign(std::make_move_iterator(expVec1.begin()) + 25, std::make_move_iterator(expVec1.begin()) + 45);
		stdVec1.assign(std::make_move_iterator(expVec2.begin()) + 25, std::make_move_iterator(expVec2.begin()) + 45);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 100 - 30 - 20);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20);

		EXPECT_EQ(secVec1.capacity(), 20);

		EXPECT_EQ(secVec1.size(),  stdVec1.size());
		EXPECT_EQ(secVec1.empty(), stdVec1.empty());

		for(size_t i = 0; i < secVec1.size(); ++i)
		{
			EXPECT_EQ(secVec1[i].Data(), stdVec1[i].Data());
		}

		for(size_t i = 0; i < expVec1.size() - 5; ++i)
		{
			EXPECT_TRUE(expVec1[i].Empty());
			EXPECT_EQ(expVec1[i], expVec2[i]);
		}
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
