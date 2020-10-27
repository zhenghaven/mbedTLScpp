#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/BigNumber.hpp>

#include <random>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestBigNumber, BigNumberBaseClass)
{
	{
		BigNumberBase<DefaultBigNumObjTrait> bigNum1;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(1);

		BigNumberBase<DefaultBigNumObjTrait> bigNum2;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(2);

		bigNum1 = std::move(bigNum1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_COUNT(2);

		bigNum1 = std::move(bigNum2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_COUNT(1);

		// Moved to initialize new one, allocation should remain the same.
		BigNumberBase<DefaultBigNumObjTrait> bigNum3(std::move(bigNum1));

		// This should success.
		bigNum3.NullCheck();

		//bigNum1.NullCheck();
		EXPECT_THROW(bigNum1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(bigNum2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestBigNumber, ConstBigNumberClass)
{
	static constexpr uint8_t bignumBytesE1[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytesE2[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytes1[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytes2[] = { 0x89, 0xD3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 512905

	{
		EXPECT_THROW({ConstBigNumber bigNum(CtnFullR(bignumBytesE1));}, InvalidArgumentException);
		EXPECT_THROW({ConstBigNumber bigNum(CtnFullR(bignumBytesE2));}, InvalidArgumentException);

		ConstBigNumber bigNum1(CtnFullR(bignumBytes1));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(1);

		ConstBigNumber bigNum2(CtnFullR(bignumBytes2));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(2);

		bigNum1 = std::move(bigNum1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_COUNT(2);

		bigNum1 = std::move(bigNum2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_COUNT(1);

		// Moved to initialize new one, allocation should remain the same.
		ConstBigNumber bigNum3(std::move(bigNum1));

		// This should success.
		bigNum3.NullCheck();

		//bigNum1.NullCheck();
		EXPECT_THROW(bigNum1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(bigNum2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestBigNumber, ConstBigNumber)
{
	static constexpr uint8_t bignumBytes1[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytes2[] = { 0x89, 0xD3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 512905
	static constexpr uint8_t bignumBytes3[] = { 0x89, 0xD3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 512905
	static constexpr uint8_t bignumBytes4[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 11640895

	{
		ConstBigNumber bigNum1(CtnFullR(bignumBytes1));        // 11640895
		ConstBigNumber bigNum2(CtnFullR(bignumBytes2));        // 512905
		ConstBigNumber bigNum3(CtnFullR(bignumBytes3));        // 512905
		ConstBigNumber bigNum4(CtnFullR(bignumBytes4), false); // -11640895

		EXPECT_TRUE(bigNum1 >  bigNum2);
		EXPECT_TRUE(bigNum1 >= bigNum2);
		EXPECT_TRUE(bigNum2 >  bigNum4);
		EXPECT_TRUE(bigNum2 >= bigNum4);

		EXPECT_TRUE(bigNum2 <  bigNum1);
		EXPECT_TRUE(bigNum2 <= bigNum1);

		EXPECT_TRUE(bigNum3 == bigNum3);
		EXPECT_TRUE(bigNum3 >= bigNum3);
		EXPECT_TRUE(bigNum3 <= bigNum3);
		EXPECT_TRUE(bigNum1 != bigNum2);

		EXPECT_FALSE(bigNum2 >  bigNum1);
		EXPECT_FALSE(bigNum2 >= bigNum1);
		EXPECT_FALSE(bigNum4 >  bigNum2);
		EXPECT_FALSE(bigNum4 >= bigNum2);

		EXPECT_FALSE(bigNum1 <  bigNum2);
		EXPECT_FALSE(bigNum1 <= bigNum2);

		EXPECT_FALSE(bigNum1 == bigNum2);
		EXPECT_FALSE(bigNum3 != bigNum3);

		EXPECT_TRUE (bigNum1.IsPositive());
		EXPECT_FALSE(bigNum4.IsPositive());

		bigNum4.FlipSign();

		EXPECT_TRUE(bigNum4 >  bigNum2);
		EXPECT_TRUE(bigNum4 >= bigNum2);
		EXPECT_TRUE(bigNum4.IsPositive());

		EXPECT_EQ((bigNum1.Hex()), "3fa0b1");
		EXPECT_EQ((bigNum1.Hex<false>()), "b1a03f");
		EXPECT_EQ((bigNum2.Hex()), "89d307");
		EXPECT_EQ((bigNum2.Hex<false>()), "07d389");

		EXPECT_EQ((bigNum1.Hex<true, true, 5>()), "3fa0b10000");
		EXPECT_EQ((bigNum1.Hex<true, true, 16>()), "3fa0b100000000000000000000000000");
		EXPECT_EQ((bigNum2.Hex<true, true, 5>()), "89d3070000");
		EXPECT_EQ((bigNum2.Hex<true, true, 16>()), "89d30700000000000000000000000000");

		EXPECT_EQ((bigNum1.Hex<false, true, 5>()), "0000b1a03f");
		EXPECT_EQ((bigNum1.Hex<false, true, 16>()), "00000000000000000000000000b1a03f");
		EXPECT_EQ((bigNum2.Hex<false, true, 5>()), "000007d389");
		EXPECT_EQ((bigNum2.Hex<false, true, 16>()), "0000000000000000000000000007d389");
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestBigNumber, BigNumberClass)
{
	static constexpr uint8_t bignumBytesE1[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytesE2[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytes1[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytes2[] = { 0x89, 0xD3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 512905

	static constexpr uint8_t bignumBytesB1[] = { 0x00, 0x00, 0x00, 0x00, 0xB1, 0xA0, 0x3F,  }; // 11640895
	static constexpr uint8_t bignumBytesB2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB1, 0xA0, 0x3F, }; // 11640895

	{
		BigNumber bigNum1(CtnFullR(bignumBytes1));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(1);

		BigNumber bigNum2(CtnFullR(bignumBytes2));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_COUNT(2);

		bigNum1 = std::move(bigNum1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_COUNT(2);

		bigNum1 = std::move(bigNum2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_COUNT(1);

		// Moved to initialize new one, allocation should remain the same.
		BigNumber bigNum3(std::move(bigNum1));

		// This should success.
		bigNum3.NullCheck();

		//bigNum1.NullCheck();
		EXPECT_THROW(bigNum1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(bigNum2.NullCheck(), InvalidObjectException);
	}

	{
		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesE1)), BigNumber(CtnFullR(bignumBytesE2)));
		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesE2)), BigNumber(CtnFullR(bignumBytesB1), true, false));
		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesB1), true, false), BigNumber(CtnFullR(bignumBytesB2), true, false));

		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesE1)), BigNumber(11640895));
		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesE1)), BigNumber(11640895ULL));
		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesE1), false), BigNumber(-11640895));
		EXPECT_EQ(ConstBigNumber(CtnFullR(bignumBytes2)), BigNumber(512905));
		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesE1)), ConstBigNumber(CtnFullR(bignumBytes1)));

		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesE1)), 11640895);
		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesE1)), 11640895U);
		EXPECT_TRUE(sizeof(uint64_t) >= sizeof(mbedtls_mpi_sint));
		//BigNumber(CtnFullR(bignumBytesE1)) == 11640895ULL;
		EXPECT_EQ(BigNumber(CtnFullR(bignumBytesE1), false), -11640895);
		EXPECT_EQ(ConstBigNumber(CtnFullR(bignumBytes2)), 512905);

		EXPECT_EQ(11640895, BigNumber(CtnFullR(bignumBytesE1)));
		EXPECT_TRUE(116408 <  BigNumber(CtnFullR(bignumBytesE1)));
		EXPECT_TRUE(116408 <= BigNumber(CtnFullR(bignumBytesE1)));
		EXPECT_TRUE(116408950 >  BigNumber(CtnFullR(bignumBytesE1)));
		EXPECT_TRUE(116408950 >= BigNumber(CtnFullR(bignumBytesE1)));
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}

GTEST_TEST(TestBigNumber, BigNumberCalc)
{
	static constexpr size_t testLoopTime = 500;
	{
		// Prepare random num generator
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<int64_t> distTri(
			std::numeric_limits<int64_t>::min() / 3,
			std::numeric_limits<int64_t>::max() / 3);

		std::uniform_int_distribution<int64_t> distSqr(
			-3037000499LL,
			3037000499LL);

		std::uniform_int_distribution<int64_t> distSqrPos(
			0,
			3037000499LL);

		int64_t a = 0, b = 0;
		BigNumber bigA = 0;

		for(size_t i = 0; i < testLoopTime; ++i)
		{

			// a + b signed -> signed, ((1 / 3) * MAX)
			a = distTri(gen);
			b = distTri(gen);
			bigA = a;
			EXPECT_EQ(BigNumber(a) + BigNumber(b), a + b);
			EXPECT_EQ(BigNumber(a) + b, a + b);
			EXPECT_EQ(a + BigNumber(b), a + b);
			EXPECT_EQ(bigA += b, a += b);

			// a - b signed -> signed, ((1 / 3) * MAX)
			a = distTri(gen);
			b = distTri(gen);
			bigA = a;
			EXPECT_EQ(BigNumber(a) - BigNumber(b), a - b);
			EXPECT_EQ(BigNumber(a) - b, a - b);
			EXPECT_EQ(a - BigNumber(b), a - b);
			EXPECT_EQ(bigA -= b, a -= b);

			// a * b signed -> unsigned, (sqr(MAX))
			a = distSqr(gen);
			b = distSqr(gen);
			bigA = a;
			EXPECT_EQ(BigNumber(a) * BigNumber(b), a * b);
			EXPECT_EQ(BigNumber(a) * b, a * b);
			EXPECT_EQ(a * BigNumber(b), a * b);
			EXPECT_EQ(bigA *= b, a *= b);

			// a / b signed -> signed, ((1 / 3) * MAX), sqr(MAX)
			a = distTri(gen);
			b = distSqr(gen);
			bigA = a;
			EXPECT_EQ(BigNumber(a) / BigNumber(b), a / b);
			EXPECT_EQ(BigNumber(a) / b, a / b);
			EXPECT_EQ(bigA /= b, a /= b);

			// a % b signed -> signed, ((1 / 3) * MAX), sqr(MAX)
			a = distTri(gen);
			b = distSqr(gen);
			bigA = a;
			EXPECT_EQ(BigNumber(a) % BigNumber(b), a % b);
			EXPECT_EQ(BigNumber(a) % b, a % b);
			EXPECT_EQ(bigA %= b, a %= b);

			// a mod b signed -> signed, ((1 / 3) * MAX), pos sqr(MAX)
			a = distTri(gen);
			b = distSqrPos(gen);
			EXPECT_EQ(Mod(BigNumber(a), BigNumber(b)), ((a % b + b) % b));
			EXPECT_EQ(BigNumber(a).Mod(static_cast<uint32_t>(b)), ((a % b + b) % b));

			// a >> 2 size_t, sqr(MAX)
			a = distSqr(gen);
			bigA = a;
			EXPECT_EQ(BigNumber(a) << 2, a << 2);
			EXPECT_EQ(bigA <<= 2, a <<= 2);

			// a << 2 size_t, sqr(MAX)
			a = distSqr(gen);
			b = a >> 2;
			bigA = a;
			EXPECT_EQ(BigNumber(a) >> 2, a >= 0 ? (a >> 2) : (-(-a >> 2)));
			EXPECT_EQ(bigA >>= 2, a >= 0 ? (a >>= 2) : a = (-(-a >> 2)));

			// ++
			a = distTri(gen);
			bigA = a;
			EXPECT_EQ(bigA++, a++);
			EXPECT_EQ(bigA, a);
			EXPECT_EQ(++bigA, ++a);
			EXPECT_EQ(bigA, a);

			// --
			a = distTri(gen);
			bigA = a;
			EXPECT_EQ(bigA--, a--);
			EXPECT_EQ(bigA, a);
			EXPECT_EQ(--bigA, --a);
			EXPECT_EQ(bigA, a);

			// Compares
			a = distTri(gen);
			b = distTri(gen);
			EXPECT_EQ((BigNumber(a) == BigNumber(b)), (a == b));
			EXPECT_EQ((BigNumber(a) != BigNumber(b)), (a != b));
			EXPECT_EQ((BigNumber(a) >= BigNumber(b)), (a >= b));
			EXPECT_EQ((BigNumber(a) >  BigNumber(b)), (a >  b));
			EXPECT_EQ((BigNumber(a) <= BigNumber(b)), (a <= b));
			EXPECT_EQ((BigNumber(a) <  BigNumber(b)), (a <  b));

			EXPECT_EQ((a == BigNumber(b)), (a == b));
			EXPECT_EQ((a != BigNumber(b)), (a != b));
			EXPECT_EQ((a >= BigNumber(b)), (a >= b));
			EXPECT_EQ((a >  BigNumber(b)), (a >  b));
			EXPECT_EQ((a <= BigNumber(b)), (a <= b));
			EXPECT_EQ((a <  BigNumber(b)), (a <  b));

			EXPECT_EQ((BigNumber(a) == b), (a == b));
			EXPECT_EQ((BigNumber(a) != b), (a != b));
			EXPECT_EQ((BigNumber(a) >= b), (a >= b));
			EXPECT_EQ((BigNumber(a) >  b), (a >  b));
			EXPECT_EQ((BigNumber(a) <= b), (a <= b));
			EXPECT_EQ((BigNumber(a) <  b), (a <  b));
		}

		// a = std::numeric_limits<mbedtls_mpi_sint>::max();
		// b = 7516188671; // 6442446847 //std::numeric_limits<uint32_t>::max() + 1000000000LL;
		// std::cerr << "a: " << a << " b: " << b << std::endl;
		// std::cerr << "a * a: " << (BigNumber(a) * BigNumber(a)).Dec() << std::endl;
		// std::cerr << "a * a % b: " << (BigNumber(a) * BigNumber(a)).Mod(b) << std::endl;

		BigNumber realBig(123456789);

		realBig = realBig * realBig * realBig * realBig * realBig;
		EXPECT_EQ(realBig.Dec(), "28679718602997181072337614380936720482949");
		EXPECT_EQ((-realBig).Dec(), "-28679718602997181072337614380936720482949");
		EXPECT_EQ(realBig.Dec<64>(), "0000000000000000000000028679718602997181072337614380936720482949");
		EXPECT_EQ((-realBig).Dec<64>(), "-0000000000000000000000028679718602997181072337614380936720482949");

		realBig = 123456789;
		realBig = realBig * realBig * realBig * realBig * realBig
				* realBig * realBig * realBig * realBig * realBig
				* realBig * realBig * realBig * realBig * realBig
				* realBig * realBig * realBig * realBig * realBig;
		EXPECT_EQ(realBig.Dec(), "676549446986526549840241681265923365873890886323014445550551924313801552444665336674779420755402893771538833531264881148328025788809564706546644134563444979033201");
		EXPECT_EQ((-realBig).Dec(), "-676549446986526549840241681265923365873890886323014445550551924313801552444665336674779420755402893771538833531264881148328025788809564706546644134563444979033201");

		EXPECT_EQ(BigNumber(CtnFullR(realBig.Bytes())), realBig);
		EXPECT_EQ(BigNumber(CtnFullR((-realBig).Bytes()), false), -realBig);
		EXPECT_EQ(BigNumber(CtnFullR((realBig).Bytes<false>()), true, false), realBig);
		EXPECT_EQ(BigNumber(CtnFullR((-realBig).Bytes<false>()), false, false), -realBig);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_COUNT(0);
}
