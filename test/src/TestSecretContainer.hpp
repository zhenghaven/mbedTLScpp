#pragma once

#include <gtest/gtest.h>

#include <list>

#include <mbedTLScpp/SecretContainer.hpp>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestSecretContainer, IsSecretContainer)
{
	SecretArray<uint8_t,  32> array8;
	SecretArray<uint32_t, 8 > array32;
	std::array <uint8_t,  32> stdArray;

	constexpr bool isSec_array8  = IsSecretContainer<decltype(array8) >::value;
	constexpr bool isSec_array32 = IsSecretContainer<decltype(array32)>::value;
	constexpr bool isSec_stdArray= IsSecretContainer<decltype(stdArray)>::value;

	EXPECT_TRUE(isSec_array8);
	EXPECT_TRUE(isSec_array32);

	EXPECT_FALSE(isSec_stdArray);
}

GTEST_TEST(TestSecretContainer, IsStaticSecretContainer)
{
	SecretArray<uint8_t,  32> array8;
	SecretArray<uint32_t, 8 > array32;
	std::array <uint8_t,  32> stdArray;

	constexpr bool isStSec_array8  = IsStaticSecretContainer<decltype(array8) >::value;
	constexpr bool isStSec_array32 = IsStaticSecretContainer<decltype(array32)>::value;
	constexpr bool isStSec_stdArray= IsStaticSecretContainer<decltype(stdArray)>::value;

	EXPECT_TRUE(isStSec_array8);
	EXPECT_TRUE(isStSec_array32);

	EXPECT_FALSE(isStSec_stdArray);

	constexpr size_t ctnSize_array8  = IsStaticSecretContainer<decltype(array8) >::sk_ctnSize;
	constexpr size_t ctnSize_array32 = IsStaticSecretContainer<decltype(array32)>::sk_ctnSize;

	EXPECT_EQ(ctnSize_array8 , sizeof(uint8_t) * 32);
	EXPECT_EQ(ctnSize_array32, sizeof(uint32_t) * 8);
}

GTEST_TEST(TestSecretContainer, FullRange)
{
	SecretArray<uint8_t,  32> array8;
	SecretArray<uint32_t, 8 > array32;
	std::array <uint8_t,  32> stdArray;

	auto range_array8  = SCtnFullR(array8);
	auto range_array32 = SCtnFullR(array32);
	//auto range_stdArray= SCtnFullR(stdArray);

	EXPECT_EQ(range_array8.GetValSize(),  sizeof(uint8_t));
	EXPECT_EQ(range_array32.GetValSize(), sizeof(uint32_t));

	EXPECT_EQ(range_array8.GetRegionSize(),  32 * sizeof(uint8_t));
	EXPECT_EQ(range_array32.GetRegionSize(), 8  * sizeof(uint32_t));

	EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(range_array8.BeginBytePtr()));
	EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(range_array32.BeginBytePtr()));

	EXPECT_EQ(range_array8.EndPtr(),  static_cast<const void*>(range_array8.EndBytePtr()));
	EXPECT_EQ(range_array32.EndPtr(), static_cast<const void*>(range_array32.EndBytePtr()));

	EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(array8.Get().data()));
	EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(array32.Get().data()));

	EXPECT_EQ(range_array8.EndBytePtr(),  reinterpret_cast<const uint8_t*>(array8.Get().data())  + array8.Get().size()  * sizeof(uint8_t));
	EXPECT_EQ(range_array32.EndBytePtr(), reinterpret_cast<const uint8_t*>(array32.Get().data()) + array32.Get().size() * sizeof(uint32_t));
}

GTEST_TEST(TestSecretContainer, StaticByteRange)
{
	SecretArray<uint8_t,  32> array8;
	SecretArray<uint32_t, 8 > array32;
	std::array <uint8_t,  32> stdArray;

	{
		auto range_array8  = SCtnByteRangeR<3 * sizeof(uint8_t) , 15 * sizeof(uint8_t)>(array8);
		auto range_array32 = SCtnByteRangeR<2 * sizeof(uint32_t), 5  * sizeof(uint32_t)>(array32);

		EXPECT_EQ(range_array8.GetValSize(),  sizeof(uint8_t));
		EXPECT_EQ(range_array32.GetValSize(), sizeof(uint32_t));

		EXPECT_EQ(range_array8.GetRegionSize(),  (15 - 3) * sizeof(uint8_t));
		EXPECT_EQ(range_array32.GetRegionSize(), (5  - 2)  * sizeof(uint32_t));

		EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(range_array8.BeginBytePtr()));
		EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(range_array32.BeginBytePtr()));

		EXPECT_EQ(range_array8.EndPtr(),  static_cast<const void*>(range_array8.EndBytePtr()));
		EXPECT_EQ(range_array32.EndPtr(), static_cast<const void*>(range_array32.EndBytePtr()));

		EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(&array8.Get()[3]));
		EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(&array32.Get()[2]));

		EXPECT_EQ(range_array8.EndBytePtr(),  reinterpret_cast<const uint8_t*>(&array8.Get()[15]));
		EXPECT_EQ(range_array32.EndBytePtr(), reinterpret_cast<const uint8_t*>(&array32.Get()[5]));
	}

	{
		auto range_array8  = SCtnByteRangeR<3 * sizeof(uint8_t)>(array8);
		auto range_array32 = SCtnByteRangeR<2 * sizeof(uint32_t)>(array32);

		EXPECT_EQ(range_array8.GetValSize(),  sizeof(uint8_t));
		EXPECT_EQ(range_array32.GetValSize(), sizeof(uint32_t));

		EXPECT_EQ(range_array8.GetRegionSize(),  (32 - 3) * sizeof(uint8_t));
		EXPECT_EQ(range_array32.GetRegionSize(), (8  - 2)  * sizeof(uint32_t));

		EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(range_array8.BeginBytePtr()));
		EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(range_array32.BeginBytePtr()));

		EXPECT_EQ(range_array8.EndPtr(),  static_cast<const void*>(range_array8.EndBytePtr()));
		EXPECT_EQ(range_array32.EndPtr(), static_cast<const void*>(range_array32.EndBytePtr()));

		EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(&array8.Get()[3]));
		EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(&array32.Get()[2]));

		EXPECT_EQ(range_array8.EndBytePtr(),  reinterpret_cast<const uint8_t*>(array8.Get().data())  + array8.Get().size()  * sizeof(uint8_t));
		EXPECT_EQ(range_array32.EndBytePtr(), reinterpret_cast<const uint8_t*>(array32.Get().data()) + array32.Get().size() * sizeof(uint32_t));
	}
}

GTEST_TEST(TestSecretContainer, StaticItemAndByteRange)
{
	SecretArray<uint8_t,  32> array8;
	SecretArray<uint32_t, 8 > array32;
	std::array <uint8_t,  32> stdArray;

	{
		auto brange_array8  = SCtnByteRangeR<3 * sizeof(uint8_t) , 15 * sizeof(uint8_t)>(array8);
		auto brange_array32 = SCtnByteRangeR<2 * sizeof(uint32_t), 5  * sizeof(uint32_t)>(array32);

		auto irange_array8  = SCtnItemRangeR<3, 15>(array8);
		auto irange_array32 = SCtnItemRangeR<2, 5 >(array32);

		EXPECT_EQ(brange_array8.GetValSize(),  irange_array8.GetValSize());
		EXPECT_EQ(brange_array32.GetValSize(), irange_array32.GetValSize());

		EXPECT_EQ(brange_array8.GetRegionSize(),  irange_array8.GetRegionSize());
		EXPECT_EQ(brange_array32.GetRegionSize(), irange_array32.GetRegionSize());

		EXPECT_EQ(brange_array8.BeginPtr(),  irange_array8.BeginPtr());
		EXPECT_EQ(brange_array32.BeginPtr(), irange_array32.BeginPtr());

		EXPECT_EQ(brange_array8.EndPtr(),  irange_array8.EndPtr());
		EXPECT_EQ(brange_array32.EndPtr(), irange_array32.EndPtr());

		EXPECT_EQ(brange_array8.BeginBytePtr(),  irange_array8.BeginBytePtr());
		EXPECT_EQ(brange_array32.BeginBytePtr(), irange_array32.BeginBytePtr());

		EXPECT_EQ(brange_array8.EndBytePtr(),  irange_array8.EndBytePtr());
		EXPECT_EQ(brange_array32.EndBytePtr(), irange_array32.EndBytePtr());
	}

	{
		auto brange_array8  = SCtnByteRangeR<3 * sizeof(uint8_t)>(array8);
		auto brange_array32 = SCtnByteRangeR<2 * sizeof(uint32_t)>(array32);

		auto irange_array8  = SCtnItemRangeR<3>(array8);
		auto irange_array32 = SCtnItemRangeR<2>(array32);

		EXPECT_EQ(brange_array8.GetValSize(),  irange_array8.GetValSize());
		EXPECT_EQ(brange_array32.GetValSize(), irange_array32.GetValSize());

		EXPECT_EQ(brange_array8.GetRegionSize(),  irange_array8.GetRegionSize());
		EXPECT_EQ(brange_array32.GetRegionSize(), irange_array32.GetRegionSize());

		EXPECT_EQ(brange_array8.BeginPtr(),  irange_array8.BeginPtr());
		EXPECT_EQ(brange_array32.BeginPtr(), irange_array32.BeginPtr());

		EXPECT_EQ(brange_array8.EndPtr(),  irange_array8.EndPtr());
		EXPECT_EQ(brange_array32.EndPtr(), irange_array32.EndPtr());

		EXPECT_EQ(brange_array8.BeginBytePtr(),  irange_array8.BeginBytePtr());
		EXPECT_EQ(brange_array32.BeginBytePtr(), irange_array32.BeginBytePtr());

		EXPECT_EQ(brange_array8.EndBytePtr(),  irange_array8.EndBytePtr());
		EXPECT_EQ(brange_array32.EndBytePtr(), irange_array32.EndBytePtr());
	}
}

GTEST_TEST(TestSecretContainer, DynByteRange)
{
	SecretArray<uint8_t,  32> array8;
	SecretArray<uint32_t, 8 > array32;
	std::array <uint8_t,  32> stdArray;

	{
		auto range_array8  = SCtnByteRangeR(array8,  3 * sizeof(uint8_t) , 15 * sizeof(uint8_t));
		auto range_array32 = SCtnByteRangeR(array32, 2 * sizeof(uint32_t), 5  * sizeof(uint32_t));

		EXPECT_EQ(range_array8.GetValSize(),  sizeof(uint8_t));
		EXPECT_EQ(range_array32.GetValSize(), sizeof(uint32_t));

		EXPECT_EQ(range_array8.GetRegionSize(),  (15 - 3) * sizeof(uint8_t));
		EXPECT_EQ(range_array32.GetRegionSize(), (5  - 2)  * sizeof(uint32_t));

		EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(range_array8.BeginBytePtr()));
		EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(range_array32.BeginBytePtr()));

		EXPECT_EQ(range_array8.EndPtr(),  static_cast<const void*>(range_array8.EndBytePtr()));
		EXPECT_EQ(range_array32.EndPtr(), static_cast<const void*>(range_array32.EndBytePtr()));

		EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(&array8.Get()[3]));
		EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(&array32.Get()[2]));

		EXPECT_EQ(range_array8.EndBytePtr(),  reinterpret_cast<const uint8_t*>(&array8.Get()[15]));
		EXPECT_EQ(range_array32.EndBytePtr(), reinterpret_cast<const uint8_t*>(&array32.Get()[5]));
	}

	{
		auto range_array8  = SCtnByteRangeR(array8,  3 * sizeof(uint8_t));
		auto range_array32 = SCtnByteRangeR(array32, 2 * sizeof(uint32_t));

		EXPECT_EQ(range_array8.GetValSize(),  sizeof(uint8_t));
		EXPECT_EQ(range_array32.GetValSize(), sizeof(uint32_t));

		EXPECT_EQ(range_array8.GetRegionSize(),  (32 - 3) * sizeof(uint8_t));
		EXPECT_EQ(range_array32.GetRegionSize(), (8  - 2)  * sizeof(uint32_t));

		EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(range_array8.BeginBytePtr()));
		EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(range_array32.BeginBytePtr()));

		EXPECT_EQ(range_array8.EndPtr(),  static_cast<const void*>(range_array8.EndBytePtr()));
		EXPECT_EQ(range_array32.EndPtr(), static_cast<const void*>(range_array32.EndBytePtr()));

		EXPECT_EQ(range_array8.BeginPtr(),  static_cast<const void*>(&array8.Get()[3]));
		EXPECT_EQ(range_array32.BeginPtr(), static_cast<const void*>(&array32.Get()[2]));

		EXPECT_EQ(range_array8.EndBytePtr(),  reinterpret_cast<const uint8_t*>(array8.Get().data())  + array8.Get().size()  * sizeof(uint8_t));
		EXPECT_EQ(range_array32.EndBytePtr(), reinterpret_cast<const uint8_t*>(array32.Get().data()) + array32.Get().size() * sizeof(uint32_t));
	}
}

GTEST_TEST(TestSecretContainer, DynItemAndByteRange)
{
	SecretArray<uint8_t,  32> array8;
	SecretArray<uint32_t, 8 > array32;
	std::array <uint8_t,  32> stdArray;

	{
		EXPECT_THROW(({SCtnByteRangeR(array8,  3 * sizeof(uint8_t) , 33 * sizeof(uint8_t ));}), std::out_of_range);
		EXPECT_THROW(({SCtnByteRangeR(array32, 2 * sizeof(uint32_t) , 9 * sizeof(uint32_t));}), std::out_of_range);
		EXPECT_THROW(({SCtnByteRangeR(array8,  33 * sizeof(uint8_t) , 33 * sizeof(uint8_t ));}), std::out_of_range);
		EXPECT_THROW(({SCtnByteRangeR(array32,  9 * sizeof(uint32_t) , 9 * sizeof(uint32_t));}), std::out_of_range);

		EXPECT_THROW(({SCtnByteRangeR(array8,  32 * sizeof(uint8_t) , 30 * sizeof(uint8_t ));}), std::invalid_argument);
		EXPECT_THROW(({SCtnByteRangeR(array32,  8 * sizeof(uint32_t) , 7 * sizeof(uint32_t));}), std::invalid_argument);

		EXPECT_THROW(({SCtnItemRangeR(array8,  3, 33);}), std::out_of_range);
		EXPECT_THROW(({SCtnItemRangeR(array32, 2,  9);}), std::out_of_range);
		EXPECT_THROW(({SCtnItemRangeR(array8,  33, 33);}), std::out_of_range);
		EXPECT_THROW(({SCtnItemRangeR(array32,  9,  9);}), std::out_of_range);

		EXPECT_THROW(({SCtnItemRangeR(array8,  32 * sizeof(uint8_t) , 30 * sizeof(uint8_t ));}), std::invalid_argument);
		EXPECT_THROW(({SCtnItemRangeR(array32,  8 * sizeof(uint32_t) , 7 * sizeof(uint32_t));}), std::invalid_argument);

		auto brange_array8  = SCtnByteRangeR(array8,  3 * sizeof(uint8_t) , 15 * sizeof(uint8_t ));
		auto brange_array32 = SCtnByteRangeR(array32, 2 * sizeof(uint32_t), 5  * sizeof(uint32_t));

		auto irange_array8  = SCtnItemRangeR(array8,  3, 15);
		auto irange_array32 = SCtnItemRangeR(array32, 2, 5);

		EXPECT_EQ(brange_array8.GetValSize(),  irange_array8.GetValSize());
		EXPECT_EQ(brange_array32.GetValSize(), irange_array32.GetValSize());

		EXPECT_EQ(brange_array8.GetRegionSize(),  irange_array8.GetRegionSize());
		EXPECT_EQ(brange_array32.GetRegionSize(), irange_array32.GetRegionSize());

		EXPECT_EQ(brange_array8.BeginPtr(),  irange_array8.BeginPtr());
		EXPECT_EQ(brange_array32.BeginPtr(), irange_array32.BeginPtr());

		EXPECT_EQ(brange_array8.EndPtr(),  irange_array8.EndPtr());
		EXPECT_EQ(brange_array32.EndPtr(), irange_array32.EndPtr());

		EXPECT_EQ(brange_array8.BeginBytePtr(),  irange_array8.BeginBytePtr());
		EXPECT_EQ(brange_array32.BeginBytePtr(), irange_array32.BeginBytePtr());

		EXPECT_EQ(brange_array8.EndBytePtr(),  irange_array8.EndBytePtr());
		EXPECT_EQ(brange_array32.EndBytePtr(), irange_array32.EndBytePtr());
	}

	{
		auto brange_array8  = SCtnByteRangeR(array8,  3 * sizeof(uint8_t));
		auto brange_array32 = SCtnByteRangeR(array32, 2 * sizeof(uint32_t));

		auto irange_array8  = SCtnItemRangeR(array8,  3);
		auto irange_array32 = SCtnItemRangeR(array32, 2);

		EXPECT_EQ(brange_array8.GetValSize(),  irange_array8.GetValSize());
		EXPECT_EQ(brange_array32.GetValSize(), irange_array32.GetValSize());

		EXPECT_EQ(brange_array8.GetRegionSize(),  irange_array8.GetRegionSize());
		EXPECT_EQ(brange_array32.GetRegionSize(), irange_array32.GetRegionSize());

		EXPECT_EQ(brange_array8.BeginPtr(),  irange_array8.BeginPtr());
		EXPECT_EQ(brange_array32.BeginPtr(), irange_array32.BeginPtr());

		EXPECT_EQ(brange_array8.EndPtr(),  irange_array8.EndPtr());
		EXPECT_EQ(brange_array32.EndPtr(), irange_array32.EndPtr());

		EXPECT_EQ(brange_array8.BeginBytePtr(),  irange_array8.BeginBytePtr());
		EXPECT_EQ(brange_array32.BeginBytePtr(), irange_array32.BeginBytePtr());

		EXPECT_EQ(brange_array8.EndBytePtr(),  irange_array8.EndBytePtr());
		EXPECT_EQ(brange_array32.EndBytePtr(), irange_array32.EndBytePtr());
	}
}
