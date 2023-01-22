#include <gtest/gtest.h>

#include <mbedTLScpp/Hkdf.hpp>
#include <mbedTLScpp/Internal/Codec.hpp>

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

GTEST_TEST(TestHkdf, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestHkdf, HkdfCalc_SKey)
{
	static constexpr char oriKeyConst[] = "Test_Input_Key_For_HKDF_Key_256_";

	SKey<256> oriKey;
	std::copy(std::begin(oriKeyConst), std::end(oriKeyConst) - 1, oriKey.Get().begin());

	std::string label = "Test_Label"; // 0x546573745f4c6162656c

	{
		auto genKey = Hkdf<HashType::SHA256, 128>(CtnFullR(oriKey), CtnFullR(label), CtnFullR(gsk_emptyCtn));
		EXPECT_EQ(Internal::Bytes2HexLitEnd(CtnFullR(genKey.Get())), "b887d7064cea6f446b4ba466ddd6177a");
	}

	{
		auto genKey = Hkdf<HashType::SHA512, 256>(CtnFullR(oriKey), CtnFullR(label), CtnFullR(gsk_emptyCtn));
		EXPECT_EQ(Internal::Bytes2HexLitEnd(CtnFullR(genKey.Get())), "703ab3362633c91f5943966e8a39538956ba1ae2f7845920dcb1f6e9cc081198");
	}
}

GTEST_TEST(TestHkdf, HkdfCalc_SecretVector)
{
	static constexpr char oriKeyConst[] = "Test_Input_Key_For_HKDF_Key_256_";

	SKey<256> oriKey;
	std::copy(std::begin(oriKeyConst), std::end(oriKeyConst) - 1, oriKey.Get().begin());

	std::string label = "Test_Label"; // 0x546573745f4c6162656c

	{
		auto genKey = Hkdf<HashType::SHA256>(128, CtnFullR(oriKey), CtnFullR(label), CtnFullR(gsk_emptyCtn));
		EXPECT_EQ(Internal::Bytes2HexLitEnd(CtnFullR(genKey)), "b887d7064cea6f446b4ba466ddd6177a");
	}

	{
		auto genKey = Hkdf<HashType::SHA512>(256, CtnFullR(oriKey), CtnFullR(label), CtnFullR(gsk_emptyCtn));
		EXPECT_EQ(Internal::Bytes2HexLitEnd(CtnFullR(genKey)), "703ab3362633c91f5943966e8a39538956ba1ae2f7845920dcb1f6e9cc081198");
	}
}
