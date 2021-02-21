#include <gtest/gtest.h>

#include <list>

#include <mbedTLScpp/SecretString.hpp>

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

GTEST_TEST(TestSecretString, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestSecretString, ConstructEmpty)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// Default constructor, empty test
	{
		SecretString str1;

		EXPECT_EQ(str1.data(), nullptr);

		EXPECT_EQ(str1.size(), 0);

		EXPECT_EQ(str1.capacity(), 0);

		EXPECT_EQ(str1.max_size(), (std::numeric_limits<size_t>::max)() - 1);

		EXPECT_TRUE(str1.empty());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, ConstructFill)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1(20, 'a');
		std::string  stdStr1(20, 'a');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20 + 1);

		EXPECT_EQ(secStr1.capacity(), 20);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 20 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, ConstructCStrCopy)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		EXPECT_EQ(secStr1.capacity(), 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		SecretString secStr2("abcdefghijklmnopqrstuvwxyz", 20);
		std::string  stdStr2("abcdefghijklmnopqrstuvwxyz", 20);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);

		EXPECT_EQ(secStr2.capacity(), 20);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, ConstructStrCopy)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2(secStr1);
		std::string  stdStr2(stdStr1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26 + 1);

		EXPECT_EQ(secStr2.capacity(), 26);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2(secStr1, 6);
		std::string  stdStr2(stdStr1, 6);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);

		EXPECT_EQ(secStr2.capacity(), 20);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2(secStr1, 6, 10);
		std::string  stdStr2(stdStr1, 6, 10);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 10 + 1);

		EXPECT_EQ(secStr2.capacity(), 10);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 10 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2(secStr1, 6, 25);
		std::string  stdStr2(stdStr1, 6, 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);

		EXPECT_EQ(secStr2.capacity(), 20);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2(secStr1, 6, SecretString::npos);
		std::string  stdStr2(stdStr1, 6, std::string::npos);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);

		EXPECT_EQ(secStr2.capacity(), 20);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, ConstructItCopy)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		std::list<char> expList = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', };

		SecretString secStr1(expList.begin(), expList.end());
		std::string  stdStr1(expList.begin(), expList.end());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);

		EXPECT_EQ(secStr1.capacity(), 10);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, ConstructMove)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2(std::move(secStr1));
		std::string  stdStr2(std::move(stdStr1));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		EXPECT_EQ(secStr2.capacity(), 26);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, Assignment)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2;
		std::string  stdStr2;

		secStr2 = secStr1;
		stdStr2 = stdStr1;

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26 + 1);

		EXPECT_EQ(secStr2.capacity(), 26);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26 + 1);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2;
		std::string  stdStr2;

		secStr2 = std::move(secStr1);
		stdStr2 = std::move(stdStr1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		EXPECT_EQ(secStr2.capacity(), 26);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, Append)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.append(5, secStr1[5]);
		stdStr1.append(5, stdStr1[5]);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.append(secStr1);
		stdStr1.append(stdStr1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.append(secStr1, 6);
		stdStr1.append(stdStr1, 6);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.append(secStr1, 6, 25);
		stdStr1.append(stdStr1, 6, 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.append(secStr1, 6, SecretString::npos);
		stdStr1.append(stdStr1, 6, std::string::npos);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.append(secStr1.data());
		stdStr1.append(stdStr1.data());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.append(secStr1.data(), 6);
		stdStr1.append(stdStr1.data(), 6);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.append(secStr1.data(), 6, 25);
		stdStr1.append(stdStr1.data(), 6, 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.append(secStr1.data(), 6, SecretString::npos);
		stdStr1.append(stdStr1.data(), 6, std::string::npos);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, OperatorIncr)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1 += SecretString("zxcvb");
		stdStr1 += std::string("zxcvb");

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1 += "zxcvb";
		stdStr1 += "zxcvb";

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1 += 'z';
		stdStr1 += 'z';

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1 += {'z'};
		stdStr1 += {'z'};

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, ReplaceImpl)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	// copy, len(dest) > len(src), erase extra
	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, secStr1.data(), 5);
		stdStr1.replace(2, 10, stdStr1.data(), 5);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		EXPECT_EQ(secStr1.capacity(), 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	// copy, len(dest) < len(src), expand
	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, secStr1.data(), 15);
		stdStr1.replace(2, 10, stdStr1.data(), 15);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	// copy, len(dest) = len(src), no change
	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, secStr1.data(), 10);
		stdStr1.replace(2, 10, stdStr1.data(), 10);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		EXPECT_EQ(secStr1.capacity(), 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	// fill, len(dest) > len(src), erase extra
	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, 5, secStr1[2]);
		stdStr1.replace(2, 10, 5, stdStr1[2]);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		EXPECT_EQ(secStr1.capacity(), 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	// copy, len(dest) < len(src), expand
	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, 15, secStr1[2]);
		stdStr1.replace(2, 10, 15, stdStr1[2]);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	// copy, len(dest) = len(src), no change
	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, 10, secStr1[2]);
		stdStr1.replace(2, 10, 10, stdStr1[2]);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		EXPECT_EQ(secStr1.capacity(), 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, ReplaceAPI)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, secStr1);
		stdStr1.replace(2, 10, stdStr1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(secStr1.begin() + 2, secStr1.begin() + 10, secStr1);
		stdStr1.replace(stdStr1.begin() + 2, stdStr1.begin() + 10, stdStr1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, secStr1, 0);
		stdStr1.replace(2, 10, stdStr1, 0);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, secStr1, 0, 25);
		stdStr1.replace(2, 10, stdStr1, 0, 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(secStr1.begin() + 2, secStr1.begin() + 10, secStr1.begin(), secStr1.end());
		stdStr1.replace(stdStr1.begin() + 2, stdStr1.begin() + 10, stdStr1.begin(), stdStr1.end());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, secStr1.data(), 25);
		stdStr1.replace(2, 10, stdStr1.data(), 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(secStr1.begin() + 2, secStr1.begin() + 10, secStr1.data(), 25);
		stdStr1.replace(stdStr1.begin() + 2, stdStr1.begin() + 10, stdStr1.data(), 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, secStr1.data());
		stdStr1.replace(2, 10, stdStr1.data());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(secStr1.begin() + 2, secStr1.begin() + 10, secStr1.data());
		stdStr1.replace(stdStr1.begin() + 2, stdStr1.begin() + 10, stdStr1.data());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(secStr1.begin() + 2, secStr1.begin() + 3, { 'x','y','z', });
		stdStr1.replace(stdStr1.begin() + 2, stdStr1.begin() + 3, { 'x','y','z', });

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(2, 10, 25, 'z');
		stdStr1.replace(2, 10, 25, 'z');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.replace(secStr1.begin() + 2, secStr1.begin() + 10, 25, 'z');
		stdStr1.replace(stdStr1.begin() + 2, stdStr1.begin() + 10, 25, 'z');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, SubStr)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2 = secStr1.substr(6);
		std::string  stdStr2 = stdStr1.substr(6);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);

		EXPECT_EQ(secStr2.capacity(), 20);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		SecretString secStr2 = secStr1.substr(5, 20);
		std::string  stdStr2 = stdStr1.substr(5, 20);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);

		EXPECT_EQ(secStr2.capacity(), 20);

		EXPECT_EQ(secStr2.size(),  stdStr2.size());
		EXPECT_EQ(secStr2.empty(), stdStr2.empty());

		for(size_t i = 0; i < secStr2.size(); ++i)
		{
			EXPECT_EQ(secStr2[i], stdStr2[i]);
		}
		EXPECT_EQ(*(secStr2.data() + secStr2.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 20 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, Copy)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		char secBuf[20] = {0};
		char stdBuf[20] = {0};

		EXPECT_EQ(secStr1.copy(secBuf, 20),
					stdStr1.copy(stdBuf, 20));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		for(size_t i = 0; i < (sizeof(secBuf) / sizeof(*secBuf)); ++i)
		{
			EXPECT_EQ(secBuf[i], secBuf[i]);
		}

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		char secBuf[20] = {0};
		char stdBuf[20] = {0};

		EXPECT_EQ(secStr1.copy(secBuf, 20, 5),
					stdStr1.copy(stdBuf, 20, 5));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		for(size_t i = 0; i < (sizeof(secBuf) / sizeof(*secBuf)); ++i)
		{
			EXPECT_EQ(secBuf[i], secBuf[i]);
		}

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		char secBuf[20] = {0};
		char stdBuf[20] = {0};

		EXPECT_EQ(secStr1.copy(secBuf, 20, 15),
					stdStr1.copy(stdBuf, 20, 15));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		for(size_t i = 0; i < (sizeof(secBuf) / sizeof(*secBuf)); ++i)
		{
			EXPECT_EQ(secBuf[i], secBuf[i]);
		}

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		char secBuf[20] = {0};
		char stdBuf[20] = {0};

		EXPECT_EQ(secStr1.copy(secBuf, 1, 15),
					stdStr1.copy(stdBuf, 1, 15));

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);

		for(size_t i = 0; i < (sizeof(secBuf) / sizeof(*secBuf)); ++i)
		{
			EXPECT_EQ(secBuf[i], secBuf[i]);
		}

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, Insert)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.insert(10, 25, 'z');
		stdStr1.insert(10, 25, 'z');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.insert(10, secStr1.data());
		stdStr1.insert(10, stdStr1.data());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.insert(10, secStr1.data(), 25);
		stdStr1.insert(10, stdStr1.data(), 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.insert(10, secStr1);
		stdStr1.insert(10, stdStr1);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.insert(10, secStr1, 5);
		stdStr1.insert(10, stdStr1, 5);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.insert(10, secStr1, 5, 20);
		stdStr1.insert(10, stdStr1, 5, 20);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	{
		SecretString secStr1("abcdefghijklmnopqrstuvwxyz");
		std::string  stdStr1("abcdefghijklmnopqrstuvwxyz");

		secStr1.insert(10, secStr1, 5, 25);
		stdStr1.insert(10, stdStr1, 5, 25);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);

		EXPECT_EQ(secStr1.capacity(), 26 + 26);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 26 + 1 + 26);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, OperatorPlus) //TODO
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		SecretString secStr1 = SecretString("abcde") + SecretString("fghij");
		std::string  stdStr1 = std::string("abcde") + std::string("fghij");

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);

		EXPECT_EQ(secStr1.capacity(), 10);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);
	}

	{
		SecretString secStr1 = SecretString("abcde") + "fghij";
		std::string  stdStr1 = std::string("abcde") + "fghij";

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);

		EXPECT_EQ(secStr1.capacity(), 10);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);
	}

	{
		SecretString secStr1 = SecretString("abcde") + 'f';
		std::string  stdStr1 = std::string("abcde") + 'f';

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);

		EXPECT_EQ(secStr1.capacity(), 10);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);
	}

	{
		SecretString secStr1 = "abcde" + SecretString("fghij");
		std::string  stdStr1 = "abcde" + std::string("fghij");

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);

		EXPECT_EQ(secStr1.capacity(), 10);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);
	}

	{
		SecretString secStr1 = 'a' + SecretString("bcdef");
		std::string  stdStr1 = 'a' + std::string("bcdef");

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);

		EXPECT_EQ(secStr1.capacity(), 10);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 10 + 1);
	}

	{
		const SecretString secExp("fghij");
		const std::string  stdExp("fghij");
		SecretString secStr1 = "abcde" + secExp;
		std::string  stdStr1 = "abcde" + stdExp;

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 5 + 1 + 10 + 1);

		EXPECT_EQ(secStr1.capacity(), 10);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 5 + 1 + 10 + 1);
	}

	{
		const SecretString secExp("bcdef");
		const std::string  stdExp("bcdef");
		SecretString secStr1 = 'a' + secExp;
		std::string  stdStr1 = 'a' + stdExp;

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 5 + 1 + 6 + 1);

		EXPECT_EQ(secStr1.capacity(), 6);

		EXPECT_EQ(secStr1.size(),  stdStr1.size());
		EXPECT_EQ(secStr1.empty(), stdStr1.empty());

		for(size_t i = 0; i < secStr1.size(); ++i)
		{
			EXPECT_EQ(secStr1[i], stdStr1[i]);
		}
		EXPECT_EQ(*(secStr1.data() + secStr1.size()), '\0');

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 5 + 1 + 6 + 1);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, InEquality)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EXPECT_TRUE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") !=
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_TRUE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") !=
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

		EXPECT_TRUE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") !=
					std::string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_TRUE("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" !=
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_TRUE(std::string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") !=
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_FALSE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") !=
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_FALSE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") !=
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

		EXPECT_FALSE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") !=
					std::string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_FALSE("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" !=
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_FALSE(std::string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") !=
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_TRUE(SecretString{'\0'  } !=
					SecretString{'\xff'});

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestSecretString, Equality)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		EXPECT_FALSE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ==
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_FALSE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ==
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

		EXPECT_FALSE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ==
					std::string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_FALSE("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ==
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_FALSE(std::string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ==
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_TRUE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ==
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_TRUE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ==
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

		EXPECT_TRUE(SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ==
					std::string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_TRUE("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ==
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_TRUE(std::string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ==
					SecretString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

		EXPECT_FALSE(SecretString{'\0'  } ==
					SecretString{'\xff'});

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
