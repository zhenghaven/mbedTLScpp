#include <gtest/gtest.h>

#include <mbedTLScpp/Internal/Codec.hpp>

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

GTEST_TEST(TestInternalCodec, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

GTEST_TEST(TestInternalCodec, TestBytes2Hex)
{
	const uint8_t bytes[] = { 0xAB, 0xC9, 0x95, 0x34, 0x1F, 0x3A, 0x26, 0x00, 0x1D, 0x7E };
	EXPECT_EQ(Internal::Bytes2HEXBigEnd(CtnFullR(bytes)), "7E1D00263A1F3495C9AB");
	EXPECT_EQ(Internal::Bytes2HEXLitEnd(CtnFullR(bytes)), "ABC995341F3A26001D7E");
	EXPECT_EQ(Internal::Bytes2HexBigEnd(CtnFullR(bytes)), "7e1d00263a1f3495c9ab");
	EXPECT_EQ(Internal::Bytes2HexLitEnd(CtnFullR(bytes)), "abc995341f3a26001d7e");
}

GTEST_TEST(TestInternalCodec, TestBytes2Bin)
{
	const uint64_t a = 0x6AA8AAABE494D9ULL;
	const uint64_t b = 0x9ABA955D545D5ULL;
	EXPECT_EQ(
		Internal::Bytes2BinBigEnd(CtnFullR(CDynArray<const uint64_t>{&a, 1})),
		"0000000001101010101010001010101010101011111001001001010011011001"
	);
	EXPECT_EQ(
		Internal::Bytes2BinBigEnd(CtnFullR(CDynArray<const uint64_t>{&b, 1})),
		"0000000000001001101010111010100101010101110101010100010111010101"
	);
	EXPECT_EQ(
		Internal::Bytes2BinBigEnd<9>(CtnFullR(CDynArray<const uint64_t>{&a, 1})),
		"000000000000000001101010101010001010101010101011111001001001010011011001"
	);
	EXPECT_EQ(
		Internal::Bytes2BinBigEnd<9>(CtnFullR(CDynArray<const uint64_t>{&b, 1})),
		"000000000000000000001001101010111010100101010101110101010100010111010101"
	);

	EXPECT_EQ(
		Internal::Bytes2BinLitEnd(CtnFullR(CDynArray<const uint64_t>{&a, 1})),
		"1101100110010100111001001010101110101010101010000110101000000000"
	);
	EXPECT_EQ(
		Internal::Bytes2BinLitEnd(CtnFullR(CDynArray<const uint64_t>{&b, 1})),
		"1101010101000101110101010101010110101001101010110000100100000000"
	);
	EXPECT_EQ(
		Internal::Bytes2BinLitEnd<9>(CtnFullR(CDynArray<const uint64_t>{&a, 1})),
		"110110011001010011100100101010111010101010101000011010100000000000000000"
	);
	EXPECT_EQ(
		Internal::Bytes2BinLitEnd<9>(CtnFullR(CDynArray<const uint64_t>{&b, 1})),
		"110101010100010111010101010101011010100110101011000010010000000000000000"
	);
}
