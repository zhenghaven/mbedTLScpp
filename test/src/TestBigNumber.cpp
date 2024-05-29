#include <random>

#include <gtest/gtest.h>

#include <mbedTLScpp/BigNumber.hpp>
#include <mbedTLScpp/DefaultRbg.hpp>

#include "MemoryTest.hpp"
#include "SelfMoveTest.hpp"

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

GTEST_TEST(TestBigNumber, CountTestFile)
{
	++mbedTLScpp_Test::g_numOfTestFile;
}

static void InitMemLeakCount(int64_t& out)
{
	EXPECT_EQ(BigNum::Zero(), 0);
	EXPECT_EQ(BigNum::NegativeOne(), -1);

	MEMORY_LEAK_TEST_GET_COUNT(out);
}

GTEST_TEST(TestBigNumber, BigNumberBaseClass)
{
	int64_t initCount = 0;
	InitMemLeakCount(initCount);

	{
		BigNumberBase<DefaultBigNumObjTrait> bigNum1;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);

		BigNumberBase<DefaultBigNumObjTrait> bigNum2;

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);

		MBEDTLSCPPTEST_SELF_MOVE_TEST(bigNum1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);

		bigNum1 = std::move(bigNum2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);

		// Moved to initialize new one, allocation should remain the same.
		BigNumberBase<DefaultBigNumObjTrait> bigNum3(std::move(bigNum1));

		// This should success.
		bigNum3.NullCheck();

		//bigNum1.NullCheck();
		EXPECT_THROW(bigNum1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(bigNum2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestBigNumber, BigNumberClass)
{
	int64_t initCount = 0;
	InitMemLeakCount(initCount);

	static constexpr uint8_t bignumBytesE1[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytesE2[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytes1[] = { 0x3F, 0xA0, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 11640895
	static constexpr uint8_t bignumBytes2[] = { 0x89, 0xD3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 512905

	static constexpr uint8_t bignumBytesB1[] = { 0x00, 0x00, 0x00, 0x00, 0xB1, 0xA0, 0x3F,  }; // 11640895
	static constexpr uint8_t bignumBytesB2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB1, 0xA0, 0x3F, }; // 11640895

	{
		BigNum bigNum1(CtnFullR(bignumBytes1));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);

		BigNum bigNum2(CtnFullR(bignumBytes2));

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);

		MBEDTLSCPPTEST_SELF_MOVE_TEST(bigNum1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);

		bigNum1 = std::move(bigNum2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);

		BigNum bigNum3(std::move(bigNum1));
		// Moved to initialize new one, allocation should remain the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);

		// This should success.
		bigNum3.NullCheck();

		//bigNum1.NullCheck();
		EXPECT_THROW(bigNum1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(bigNum2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);

	{
		EXPECT_EQ(BigNum(CtnFullR(bignumBytesE1)), BigNum(CtnFullR(bignumBytesE2)));
		EXPECT_EQ(BigNum(CtnFullR(bignumBytesE2)), BigNum(CtnFullR(bignumBytesB1), true, false));
		EXPECT_EQ(BigNum(CtnFullR(bignumBytesB1), true, false), BigNum(CtnFullR(bignumBytesB2), true, false));

		EXPECT_EQ(BigNum(CtnFullR(bignumBytesE1)), BigNum(11640895));
		EXPECT_EQ(BigNum(CtnFullR(bignumBytesE1)), BigNum(11640895ULL));
		EXPECT_EQ(BigNum(CtnFullR(bignumBytesE1), false), BigNum(-11640895));

		EXPECT_EQ(BigNum(CtnFullR(bignumBytesE1)), 11640895);
		EXPECT_EQ(BigNum(CtnFullR(bignumBytesE1)), 11640895U);
		EXPECT_TRUE(sizeof(uint64_t) >= sizeof(mbedtls_mpi_sint));
		//BigNum(CtnFullR(bignumBytesE1)) == 11640895ULL;
		EXPECT_EQ(BigNum(CtnFullR(bignumBytesE1), false), -11640895);

		EXPECT_EQ(11640895, BigNum(CtnFullR(bignumBytesE1)));
		EXPECT_TRUE(116408 <  BigNum(CtnFullR(bignumBytesE1)));
		EXPECT_TRUE(116408 <= BigNum(CtnFullR(bignumBytesE1)));
		EXPECT_TRUE(116408950 >  BigNum(CtnFullR(bignumBytesE1)));
		EXPECT_TRUE(116408950 >= BigNum(CtnFullR(bignumBytesE1)));
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestBigNumber, BigNumberConstructFromStr)
{
	int64_t initCount = 0;
	InitMemLeakCount(initCount);

	// ===== Decimal
	{
		int64_t expVal = 1234567890LL;

		BigNum val("1234567890");
		EXPECT_EQ(val, expVal);
	}

	{
		int64_t expVal = 9876543210LL;

		BigNum val("9876543210");
		EXPECT_EQ(val, expVal);
	}

	{
		int64_t expVal = 0x1234567890ABCDEFLL;

		BigNum val("1311768467294899695");
		EXPECT_EQ(val, expVal);
	}
	// 128 bits
	{
		std::vector<uint8_t> expValBytes = {
			0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
			0x99U, 0x00U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU,
		};
		BigNum expVal(
			CtnFullR(expValBytes),
			/*isPositive=*/true,
			/*isLittleEndian=*/false
		);

		BigNum val("22774453838368691933710012711845097215");
		EXPECT_EQ(val, expVal);
	}
	// 256 bits
	{
		std::vector<uint8_t> expValBytes = {
			0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
			0x99U, 0x00U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU,
			0x1FU, 0x2EU, 0x3DU, 0x4CU, 0x5BU, 0x6AU, 0x70U, 0x89U,
			0x98U, 0x87U, 0x76U, 0x65U, 0x54U, 0x43U, 0x32U, 0x21U,
		};
		BigNum expVal(
			CtnFullR(expValBytes),
			/*isPositive=*/true,
			/*isLittleEndian=*/false
		);

		BigNum val("7749745057451750595652775467055142246985373987309575996470579829872645059105");
		EXPECT_EQ(val, expVal);
	}


	// ===== Hex
	{
		int64_t expVal = 0x1234567890LL;

		BigNum val("1234567890", /*radix=*/16);
		EXPECT_EQ(val, expVal);
	}

	{
		int64_t expVal = 0xABCDEFLL;

		BigNum val("ABCDEF", /*radix=*/16);
		EXPECT_EQ(val, expVal);

		BigNum vall("abcdef", /*radix=*/16);
		EXPECT_EQ(vall, expVal);
	}

	{
		int64_t expVal = 0x1234567890ABCDEFLL;

		BigNum val("1234567890ABCDEF", /*radix=*/16);
		EXPECT_EQ(val, expVal);

		BigNum vall("1234567890abcdef", /*radix=*/16);
		EXPECT_EQ(vall, expVal);
	}
	// 128 bits
	{
		std::vector<uint8_t> expValBytes = {
			0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
			0x99U, 0x00U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU,
		};
		BigNum expVal(
			CtnFullR(expValBytes),
			/*isPositive=*/true,
			/*isLittleEndian=*/false
		);

		BigNum val("11223344556677889900AABBCCDDEEFF", /*radix=*/16);
		EXPECT_EQ(val, expVal);

		BigNum vall("11223344556677889900aabbccddeeff", /*radix=*/16);
		EXPECT_EQ(vall, expVal);
	}
	// 256 bits
	{
		std::vector<uint8_t> expValBytes = {
			0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
			0x99U, 0x00U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU,
			0x1FU, 0x2EU, 0x3DU, 0x4CU, 0x5BU, 0x6AU, 0x70U, 0x89U,
			0x98U, 0x87U, 0x76U, 0x65U, 0x54U, 0x43U, 0x32U, 0x21U,
		};
		BigNum expVal(
			CtnFullR(expValBytes),
			/*isPositive=*/true,
			/*isLittleEndian=*/false
		);

		BigNum val(
			"11223344556677889900AABBCCDDEEFF1F2E3D4C5B6A70899887766554433221",
			/*radix=*/16
		);
		EXPECT_EQ(val, expVal);

		BigNum vall(
			"11223344556677889900aabbccddeeff1f2e3d4c5b6a70899887766554433221",
			/*radix=*/16
		);
		EXPECT_EQ(vall, expVal);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestBigNumber, BigNumberCalc)
{
	int64_t initCount = 0;
	InitMemLeakCount(initCount);

	static constexpr size_t testLoopTime = 500;
	{
		// Prepare random num generator
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<int64_t> distTri(
			(std::numeric_limits<int64_t>::min)() / 3,
			(std::numeric_limits<int64_t>::max)() / 3);

		std::uniform_int_distribution<int64_t> distSqr(
			-3037000499LL,
			3037000499LL);

		std::uniform_int_distribution<int64_t> distSqrPos(
			0,
			3037000499LL);

		int64_t a = 0, b = 0;
		BigNum bigA = 0;

		for(size_t i = 0; i < testLoopTime; ++i)
		{

			// a + b signed -> signed, ((1 / 3) * MAX)
			a = distTri(gen);
			b = distTri(gen);
			bigA = a;
			EXPECT_EQ(BigNum(a) + BigNum(b), a + b);
			EXPECT_EQ(BigNum(a) + b, a + b);
			EXPECT_EQ(a + BigNum(b), a + b);
			EXPECT_EQ(bigA += b, a += b);

			// a - b signed -> signed, ((1 / 3) * MAX)
			a = distTri(gen);
			b = distTri(gen);
			bigA = a;
			EXPECT_EQ(BigNum(a) - BigNum(b), a - b);
			EXPECT_EQ(BigNum(a) - b, a - b);
			EXPECT_EQ(a - BigNum(b), a - b);
			EXPECT_EQ(bigA -= b, a -= b);

			// a * b signed -> unsigned, (sqr(MAX))
			a = distSqr(gen);
			b = distSqr(gen);
			bigA = a;
			EXPECT_EQ(BigNum(a) * BigNum(b), a * b);
			EXPECT_EQ(BigNum(a) * b, a * b);
			EXPECT_EQ(a * BigNum(b), a * b);
			EXPECT_EQ(bigA *= b, a *= b);

			// a / b signed -> signed, ((1 / 3) * MAX), sqr(MAX)
			a = distTri(gen);
			b = distSqr(gen);
			bigA = a;
			EXPECT_EQ(BigNum(a) / BigNum(b), a / b);
			EXPECT_EQ(BigNum(a) / b, a / b);
			EXPECT_EQ(bigA /= b, a /= b);

			// a % b signed -> signed, ((1 / 3) * MAX), sqr(MAX)
			a = distTri(gen);
			b = distSqr(gen);
			bigA = a;
			EXPECT_EQ(BigNum(a) % BigNum(b), a % b);
			EXPECT_EQ(BigNum(a) % b, a % b);
			EXPECT_EQ(bigA %= b, a %= b);

			// a mod b signed -> signed, ((1 / 3) * MAX), pos sqr(MAX)
			a = distTri(gen);
			b = distSqrPos(gen);
			EXPECT_EQ(Mod(BigNum(a), BigNum(b)), ((a % b + b) % b));
			EXPECT_EQ(BigNum(a).Mod(static_cast<uint32_t>(b)), ((a % b + b) % b));

			// a >> 2 size_t, sqr(MAX)
			a = distSqr(gen);
			bigA = a;
			EXPECT_EQ(BigNum(a) << 2, a << 2);
			EXPECT_EQ(bigA <<= 2, a <<= 2);

			// a << 2 size_t, sqr(MAX)
			a = distSqr(gen);
			b = a >> 2;
			bigA = a;
			EXPECT_EQ(BigNum(a) >> 2, a >= 0 ? (a >> 2) : (-(-a >> 2)));
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
			EXPECT_EQ((BigNum(a) == BigNum(b)), (a == b));
			EXPECT_EQ((BigNum(a) != BigNum(b)), (a != b));
			EXPECT_EQ((BigNum(a) >= BigNum(b)), (a >= b));
			EXPECT_EQ((BigNum(a) >  BigNum(b)), (a >  b));
			EXPECT_EQ((BigNum(a) <= BigNum(b)), (a <= b));
			EXPECT_EQ((BigNum(a) <  BigNum(b)), (a <  b));

			EXPECT_EQ((a == BigNum(b)), (a == b));
			EXPECT_EQ((a != BigNum(b)), (a != b));
			EXPECT_EQ((a >= BigNum(b)), (a >= b));
			EXPECT_EQ((a >  BigNum(b)), (a >  b));
			EXPECT_EQ((a <= BigNum(b)), (a <= b));
			EXPECT_EQ((a <  BigNum(b)), (a <  b));

			EXPECT_EQ((BigNum(a) == b), (a == b));
			EXPECT_EQ((BigNum(a) != b), (a != b));
			EXPECT_EQ((BigNum(a) >= b), (a >= b));
			EXPECT_EQ((BigNum(a) >  b), (a >  b));
			EXPECT_EQ((BigNum(a) <= b), (a <= b));
			EXPECT_EQ((BigNum(a) <  b), (a <  b));
		}

		// a = (std::numeric_limits<mbedtls_mpi_sint>::max)();
		// b = 7516188671; // 6442446847 //(std::numeric_limits<uint32_t>::max)() + 1000000000LL;
		// std::cerr << "a: " << a << " b: " << b << std::endl;
		// std::cerr << "a * a: " << (BigNum(a) * BigNum(a)).Dec() << std::endl;
		// std::cerr << "a * a % b: " << (BigNum(a) * BigNum(a)).Mod(b) << std::endl;

		BigNum realBig(123456789);

		realBig = realBig * realBig * realBig * realBig * realBig;
		EXPECT_EQ(realBig.Dec(), "28679718602997181072337614380936720482949");
		EXPECT_EQ((-realBig).Dec(), "-28679718602997181072337614380936720482949");

		realBig = 123456789;
		realBig = realBig * realBig * realBig * realBig * realBig
				* realBig * realBig * realBig * realBig * realBig
				* realBig * realBig * realBig * realBig * realBig
				* realBig * realBig * realBig * realBig * realBig;
		EXPECT_EQ(realBig.Dec(), "676549446986526549840241681265923365873890886323014445550551924313801552444665336674779420755402893771538833531264881148328025788809564706546644134563444979033201");
		EXPECT_EQ((-realBig).Dec(), "-676549446986526549840241681265923365873890886323014445550551924313801552444665336674779420755402893771538833531264881148328025788809564706546644134563444979033201");

		EXPECT_EQ(BigNum(CtnFullR(realBig.Bytes())), realBig);
		EXPECT_EQ(BigNum(CtnFullR((-realBig).Bytes()), false), -realBig);
		EXPECT_EQ(BigNum(CtnFullR((realBig).Bytes<false>()), true, false), realBig);
		EXPECT_EQ(BigNum(CtnFullR((-realBig).Bytes<false>()), false, false), -realBig);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestBigNumber, ReminderAndMod)
{
	{
		BigNum a(-88091155);
		BigNum b(11579);

		// a % b in python
		// it's `a - (round_down(a / b) * b)`
		// where `a / b = -7607.837896191381`
		// and `round_down(a / b) = -7608`
		BigNum expMod(1877);
		BigNum mod = Mod(a, b);
		EXPECT_EQ(mod, expMod);

		// a % b in C/C++
		// it's `a - (round_towards_zero(a / b) * b)`
		// where `a / b = -7607.837896191381`
		// and `round_towards_zero(a / b) = -7607`
		BigNum expRem(-9702);
		BigNum rem = a % b;
		EXPECT_EQ(rem, expRem);
	}

	{
		BigNum a("-8809115541847889079303914586772286292427582643565204648787975926198236900499775371799643739458926744604258588242226270417256635160805965184937991917108924");
		BigNum b("115792089237316195423570985008687907853269984665640564039457584007908834671663");

		BigNum expMod("60378037945358702174120191576064721420705580920788624404695193057953527100220");
		BigNum mod = Mod(a, b);
		EXPECT_EQ(mod, expMod);

		BigNum expRem("-55414051291957493249450793432623186432564403744851939634762390949955307571443");
		BigNum rem = a % b;
		EXPECT_EQ(rem, expRem);
	}
}

GTEST_TEST(TestBigNumber, Rand)
{
	std::unique_ptr<RbgInterface> rand =
		Internal::make_unique<DefaultRbg>();

	int64_t initCount = 0;
	InitMemLeakCount(initCount);

	{
		BigNum num1 = BigNum::Rand(100, *rand);
		BigNum num2 = BigNum::Rand(100, *rand);

		EXPECT_NE(num1, num2);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestBigNumber, BorrowerConstructor)
{
	int64_t initCount = 0;
	InitMemLeakCount(initCount);

	{
		BigNum num1 = 1;
		BigNumber<BorrowerBigNumTrait> num2(num1.Get());

		EXPECT_EQ(num1, num2);
		EXPECT_EQ(num1.Get(), num2.Get());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}

GTEST_TEST(TestBigNumber, Copy)
{
	int64_t initCount = 0;
	InitMemLeakCount(initCount);

	{
		BigNum num1 = 1;
		BigNum num2 = num1;

		EXPECT_EQ(num1, num2);
		EXPECT_NE(num1.Get(), num2.Get());

		BigNumber<BorrowerBigNumTrait> num3(num1.Get());
		BigNum num4 = num3;

		EXPECT_EQ(num3, num4);
		EXPECT_NE(num3.Get(), num4.Get());

		num2 = num3;
		num4 = num1;

		EXPECT_EQ(num2, num4);
		EXPECT_NE(num2.Get(), num4.Get());
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
}
