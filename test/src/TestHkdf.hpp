#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/Hkdf.hpp>
#include <mbedTLScpp/Internal/Codec.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestHkdf, HkdfCalc)
{
	static constexpr char oriKeyConst[] = "Test_Input_Key_For_HKDF_Key_256_";

	SKey<256> oriKey;
	std::copy(std::begin(oriKeyConst), std::end(oriKeyConst) - 1, oriKey.Get().begin());

	std::string label = "Test_Label"; // 0x546573745f4c6162656c

	{
		auto genKey = Hkdf<HashType::SHA256, 128>(SCtnFullR(oriKey), CtnFullR(label), CtnFullR(gsk_emptyCtn));
		EXPECT_EQ(Internal::Bytes2HexLitEnd(CtnFullR(genKey.Get())), "b887d7064cea6f446b4ba466ddd6177a");
	}

	{
		auto genKey = Hkdf<HashType::SHA512, 256>(SCtnFullR(oriKey), CtnFullR(label), CtnFullR(gsk_emptyCtn));
		EXPECT_EQ(Internal::Bytes2HexLitEnd(CtnFullR(genKey.Get())), "703ab3362633c91f5943966e8a39538956ba1ae2f7845920dcb1f6e9cc081198");
	}
}
