#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/Internal/Codec.hpp>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestGeneral, TestGTest)
{
	EXPECT_EQ(0, 0);
}

GTEST_TEST(TestGeneral, TestBytes2Hex)
{
	const uint8_t bytes[] = { 0xAB, 0xC9, 0x95, 0x34, 0x1F, 0x3A, 0x26, 0x00, 0x1D, 0x7E };
	EXPECT_EQ(Internal::Bytes2HEXBigEnd(CtnFullR(bytes)), "7E1D00263A1F3495C9AB");
	EXPECT_EQ(Internal::Bytes2HEXSmlEnd(CtnFullR(bytes)), "ABC995341F3A26001D7E");
	EXPECT_EQ(Internal::Bytes2HexBigEnd(CtnFullR(bytes)), "7e1d00263a1f3495c9ab");
	EXPECT_EQ(Internal::Bytes2HexSmlEnd(CtnFullR(bytes)), "abc995341f3a26001d7e");
}
