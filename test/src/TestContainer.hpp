#pragma once

#include <gtest/gtest.h>

#include <list>

#include <mbedTLScpp/Container.hpp>
#include <mbedTLScpp/Internal/make_unique.hpp>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

GTEST_TEST(TestContainer, IsContiguous)
{
	uint8_t cArrayCtn[100];
	std::array<uint8_t, 101> stdArrayCtn;
	std::vector<uint8_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	constexpr bool isCont_cArrayCtn = CtnType<decltype(cArrayCtn)>::sk_isCtnCont;
	constexpr bool isCont_stdArrayCtn = CtnType<decltype(stdArrayCtn)>::sk_isCtnCont;
	constexpr bool isCont_vecCtn = CtnType<decltype(vecCtn)>::sk_isCtnCont;
	constexpr bool isCont_strCtn = CtnType<decltype(strCtn)>::sk_isCtnCont;
	constexpr bool isCont_cDynCtn = CtnType<decltype(cDynArrayCtnSt)>::sk_isCtnCont;

	constexpr bool isCont_vecBoolCtn = CtnType<decltype(vecBoolCtn)>::sk_isCtnCont;
	constexpr bool isCont_listCtn = CtnType<decltype(listCtn)>::sk_isCtnCont;

	EXPECT_TRUE(isCont_cArrayCtn);
	EXPECT_TRUE(isCont_stdArrayCtn);
	EXPECT_TRUE(isCont_vecCtn);
	EXPECT_TRUE(isCont_strCtn);
	EXPECT_TRUE(isCont_cDynCtn);

	EXPECT_FALSE(isCont_vecBoolCtn);
	EXPECT_FALSE(isCont_listCtn);
}

GTEST_TEST(TestContainer, IsStatic)
{
	uint8_t cArrayCtn[100];
	std::array<uint8_t, 101> stdArrayCtn;
	std::vector<uint8_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	constexpr bool isStatic_cArrayCtn = CtnType<decltype(cArrayCtn)>::sk_isCtnStatic;
	constexpr bool isStatic_stdArrayCtn = CtnType<decltype(stdArrayCtn)>::sk_isCtnStatic;
	constexpr bool isStatic_vecCtn = CtnType<decltype(vecCtn)>::sk_isCtnStatic;
	constexpr bool isStatic_strCtn = CtnType<decltype(strCtn)>::sk_isCtnStatic;
	constexpr bool isStatic_cDynCtn = CtnType<decltype(cDynArrayCtnSt)>::sk_isCtnStatic;

	EXPECT_TRUE(isStatic_cArrayCtn);
	EXPECT_TRUE(isStatic_stdArrayCtn);
	EXPECT_FALSE(isStatic_vecCtn);
	EXPECT_FALSE(isStatic_strCtn);
	EXPECT_FALSE(isStatic_cDynCtn);
}

GTEST_TEST(TestContainer, ContainerSize)
{
	uint16_t cArrayCtn[100];
	std::array<uint16_t, 101> stdArrayCtn;
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	vecCtn.resize(50);
	strCtn.resize(55);

	constexpr size_t ctnSize_cArrayCtn = CtnType<decltype(cArrayCtn)>::sk_ctnSize;
	constexpr size_t ctnSize_stdArrayCtn = CtnType<decltype(stdArrayCtn)>::sk_ctnSize;
	size_t ctnSize_vecCtn = CtnType<decltype(vecCtn)>::GetCtnSize(vecCtn);
	size_t ctnSize_strCtn = CtnType<decltype(strCtn)>::GetCtnSize(strCtn);
	size_t ctnSize_cDynCtn = CtnType<decltype(cDynArrayCtnSt)>::GetCtnSize(cDynArrayCtnSt);

	EXPECT_EQ(ctnSize_cArrayCtn, 100 * sizeof(uint16_t));
	EXPECT_EQ(ctnSize_stdArrayCtn, 101 * sizeof(uint16_t));
	EXPECT_EQ(ctnSize_vecCtn, 50 * sizeof(uint16_t));
	EXPECT_EQ(ctnSize_strCtn, 55 * sizeof(char));
	EXPECT_EQ(ctnSize_cDynCtn, 50 * sizeof(uint64_t));
}

GTEST_TEST(TestContainer, ContainerFull)
{
	constexpr uint16_t cArrayCtn[100] = { 0 };
	constexpr std::array<uint16_t, 101> stdArrayCtn = { 0 };
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	vecCtn.resize(50);
	strCtn.resize(55);

	auto ctnFull_cArrayCtn = CtnFullR(cArrayCtn);
	auto ctnFull_stdArrayCtn = CtnFullR(stdArrayCtn);
	auto ctnFull_vecCtn = CtnFullR(vecCtn);
	auto ctnFull_strCtn = CtnFullR(strCtn);
	auto ctnFull_cDynCtn = CtnFullR(cDynArrayCtnSt);

	//auto ctnFull_vecBoolCtn = CtnFullR(vecBoolCtn);
	//auto ctnFull_listCtn = CtnFullR(listCtn);

	// EXPECT_EQ(ctnFull_cArrayCtn.GetCount(),   100);
	// EXPECT_EQ(ctnFull_stdArrayCtn.GetCount(), stdArrayCtn.size());
	// EXPECT_EQ(ctnFull_vecCtn.GetCount(),      vecCtn.size());
	// EXPECT_EQ(ctnFull_strCtn.GetCount(),      strCtn.size());

	EXPECT_EQ(ctnFull_cArrayCtn.GetValSize(),   sizeof(uint16_t));
	EXPECT_EQ(ctnFull_stdArrayCtn.GetValSize(), sizeof(uint16_t));
	EXPECT_EQ(ctnFull_vecCtn.GetValSize(),      sizeof(uint16_t));
	EXPECT_EQ(ctnFull_strCtn.GetValSize(),      sizeof(char));
	EXPECT_EQ(ctnFull_cDynCtn.GetValSize(),     sizeof(uint64_t));

	EXPECT_EQ(ctnFull_cArrayCtn.GetRegionSize(),   100 * sizeof(uint16_t));
	EXPECT_EQ(ctnFull_stdArrayCtn.GetRegionSize(), stdArrayCtn.size() * sizeof(uint16_t));
	EXPECT_EQ(ctnFull_vecCtn.GetRegionSize(),      vecCtn.size() * sizeof(uint16_t));
	EXPECT_EQ(ctnFull_strCtn.GetRegionSize(),      strCtn.size() * sizeof(char));
	EXPECT_EQ(ctnFull_cDynCtn.GetRegionSize(),     50 * sizeof(uint64_t));

	EXPECT_EQ(ctnFull_cArrayCtn.BeginPtr(),   static_cast<const void*>(&cArrayCtn[0]));
	EXPECT_EQ(ctnFull_stdArrayCtn.BeginPtr(), static_cast<const void*>(&stdArrayCtn[0]));
	EXPECT_EQ(ctnFull_vecCtn.BeginPtr(),      static_cast<const void*>(&vecCtn[0]));
	EXPECT_EQ(ctnFull_strCtn.BeginPtr(),      static_cast<const void*>(&strCtn[0]));
	EXPECT_EQ(ctnFull_cDynCtn.BeginPtr(),     static_cast<const void*>(cDynArrayCtn.get()));

	EXPECT_EQ(static_cast<const void*>(ctnFull_cArrayCtn.BeginBytePtr()),   static_cast<const void*>(&cArrayCtn[0]));
	EXPECT_EQ(static_cast<const void*>(ctnFull_stdArrayCtn.BeginBytePtr()), static_cast<const void*>(&stdArrayCtn[0]));
	EXPECT_EQ(static_cast<const void*>(ctnFull_vecCtn.BeginBytePtr()),      static_cast<const void*>(&vecCtn[0]));
	EXPECT_EQ(static_cast<const void*>(ctnFull_strCtn.BeginBytePtr()),      static_cast<const void*>(&strCtn[0]));
	EXPECT_EQ(static_cast<const void*>(ctnFull_cDynCtn.BeginBytePtr()),     static_cast<const void*>(cDynArrayCtn.get()));

	EXPECT_EQ(ctnFull_cArrayCtn.EndPtr(),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnFull_stdArrayCtn.EndPtr(), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnFull_vecCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnFull_strCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(ctnFull_cDynCtn.EndPtr(),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));

	EXPECT_EQ(static_cast<const void*>(ctnFull_cArrayCtn.EndBytePtr()),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnFull_stdArrayCtn.EndBytePtr()), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnFull_vecCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnFull_strCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(static_cast<const void*>(ctnFull_cDynCtn.EndBytePtr()),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));
}

GTEST_TEST(TestContainer, ContainerByteStaticRangeWithBothEnds)
{
	uint16_t cArrayCtn[100] = { 0 };
	std::array<uint16_t, 101> stdArrayCtn = { 0 };
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	vecCtn.resize(50);
	strCtn.resize(55);

	auto stat_vecCtn1 = [vecCtn](){CtnByteRangeR<0, 51 * sizeof(uint16_t)>(vecCtn);};
	EXPECT_THROW({stat_vecCtn1();}, std::out_of_range);
	auto stat_strCtn1 = [strCtn](){CtnByteRangeR<0, 56 * sizeof(char)>(strCtn);};
	EXPECT_THROW({stat_strCtn1();}, std::out_of_range);
	auto stat_cDynAr1 = [cDynArrayCtnSt](){CtnByteRangeR<0, 51 * sizeof(uint64_t)>(cDynArrayCtnSt);};
	EXPECT_THROW({stat_cDynAr1();}, std::out_of_range);

	auto stat_vecCtn2 = [vecCtn](){CtnByteRangeR<51 * sizeof(uint16_t), 51 * sizeof(uint16_t)>(vecCtn);};
	EXPECT_THROW({stat_vecCtn2();}, std::out_of_range);
	auto stat_strCtn2 = [strCtn](){CtnByteRangeR<56 * sizeof(char), 56 * sizeof(char)>(strCtn);};
	EXPECT_THROW({stat_strCtn2();}, std::out_of_range);
	auto stat_cDynAr2 = [cDynArrayCtnSt](){CtnByteRangeR<51 * sizeof(uint64_t), 51 * sizeof(uint64_t)>(cDynArrayCtnSt);};
	EXPECT_THROW({stat_cDynAr2();}, std::out_of_range);

	//auto ctnR_vecBoolCtn = CtnByteRangeR<0, 0>(vecBoolCtn);
	//auto ctnR_listCtn = CtnByteRangeR<0, 0>(listCtn);
	//auto ctnR_vecBoolCtn = CtnByteRangeR(vecBoolCtn, 0, 0);
	//auto ctnR_listCtn = CtnByteRangeR(listCtn, 0, 0);

	//auto ctnR_cArrayCtn   = CtnByteRangeR<0, 101 * sizeof(uint16_t)>(cArrayCtn);
	//auto ctnR_cArrayCtn   = CtnByteRangeR<10 * sizeof(uint16_t), 5 * sizeof(uint16_t)>(cArrayCtn);
	//auto ctnR_stdArrayCtn = CtnByteRangeR<0, 102 * sizeof(uint16_t)>(stdArrayCtn);
	auto ctnR_cArrayCtn   = CtnByteRangeR<5  * sizeof(uint16_t), 70 * sizeof(uint16_t)>(cArrayCtn);
	auto ctnR_stdArrayCtn = CtnByteRangeR<10 * sizeof(uint16_t), 75 * sizeof(uint16_t)>(stdArrayCtn);
	auto ctnR_vecCtn      = CtnByteRangeR<15 * sizeof(uint16_t), 45 * sizeof(uint16_t)>(vecCtn);
	auto ctnR_strCtn      = CtnByteRangeR<20 * sizeof(char)    , 50 * sizeof(char)    >(strCtn);
	auto ctnR_cDynCtn     = CtnByteRangeR<25 * sizeof(uint64_t), 49 * sizeof(uint64_t)>(cDynArrayCtnSt);

	EXPECT_EQ(ctnR_cArrayCtn.GetValSize(),   sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetValSize(), sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetValSize(),      sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetValSize(),      sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetValSize(),     sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetRegionSize(),   (70 - 5 ) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetRegionSize(), (75 - 10) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetRegionSize(),      (45 - 15) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetRegionSize(),      (50 - 20) * sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetRegionSize(),     (49 - 25) * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.BeginPtr(),   static_cast<const void*>(&cArrayCtn[5]));
	EXPECT_EQ(ctnR_stdArrayCtn.BeginPtr(), static_cast<const void*>(&stdArrayCtn[10]));
	EXPECT_EQ(ctnR_vecCtn.BeginPtr(),      static_cast<const void*>(&vecCtn[15]));
	EXPECT_EQ(ctnR_strCtn.BeginPtr(),      static_cast<const void*>(&strCtn[20]));
	EXPECT_EQ(ctnR_cDynCtn.BeginPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 25));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.BeginBytePtr()),   static_cast<const void*>(&cArrayCtn[5]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.BeginBytePtr()), static_cast<const void*>(&stdArrayCtn[10]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.BeginBytePtr()),      static_cast<const void*>(&vecCtn[15]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.BeginBytePtr()),      static_cast<const void*>(&strCtn[20]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.BeginBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 25));

	EXPECT_EQ(ctnR_cArrayCtn.EndPtr(),   static_cast<const void*>(&cArrayCtn[70]));
	EXPECT_EQ(ctnR_stdArrayCtn.EndPtr(), static_cast<const void*>(&stdArrayCtn[75]));
	EXPECT_EQ(ctnR_vecCtn.EndPtr(),      static_cast<const void*>(&vecCtn[45]));
	EXPECT_EQ(ctnR_strCtn.EndPtr(),      static_cast<const void*>(&strCtn[50]));
	EXPECT_EQ(ctnR_cDynCtn.EndPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 49));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.EndBytePtr()),   static_cast<const void*>(&cArrayCtn[70]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.EndBytePtr()), static_cast<const void*>(&stdArrayCtn[75]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.EndBytePtr()),      static_cast<const void*>(&vecCtn[45]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.EndBytePtr()),      static_cast<const void*>(&strCtn[50]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.EndBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 49));
}

GTEST_TEST(TestContainer, ContainerByteStaticRangeWithBegin)
{
	constexpr uint16_t cArrayCtn[100] = { 0 };
	constexpr std::array<uint16_t, 101> stdArrayCtn = { 0 };
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	vecCtn.resize(50);
	strCtn.resize(55);

	auto stat_vecCtn1 = [vecCtn](){CtnByteRangeR<51 * sizeof(uint16_t)>(vecCtn);};
	EXPECT_THROW({stat_vecCtn1();}, std::out_of_range);
	auto stat_strCtn1 = [strCtn](){CtnByteRangeR<56 * sizeof(char)>(strCtn);};
	EXPECT_THROW({stat_strCtn1();}, std::out_of_range);
	auto stat_cDynAr1 = [cDynArrayCtnSt](){CtnByteRangeR<51 * sizeof(char)>(cDynArrayCtnSt);};
	EXPECT_THROW({stat_strCtn1();}, std::out_of_range);

	//auto ctnR_vecBoolCtn = CtnByteRangeR<0, 0>(vecBoolCtn);
	//auto ctnR_listCtn = CtnByteRangeR<0, 0>(listCtn);
	//auto ctnR_vecBoolCtn = CtnByteRangeR(vecBoolCtn, 0, 0);
	//auto ctnR_listCtn = CtnByteRangeR(listCtn, 0, 0);

	//auto ctnR_cArrayCtn   = CtnByteRangeR<101 * sizeof(uint16_t)>(cArrayCtn);
	//auto ctnR_stdArrayCtn = CtnByteRangeR<102 * sizeof(uint16_t)>(stdArrayCtn);
	auto ctnR_cArrayCtn   = CtnByteRangeR<12 * sizeof(uint16_t)>(cArrayCtn);
	auto ctnR_stdArrayCtn = CtnByteRangeR<17 * sizeof(uint16_t)>(stdArrayCtn);
	auto ctnR_vecCtn      = CtnByteRangeR<22 * sizeof(uint16_t)>(vecCtn);
	auto ctnR_strCtn      = CtnByteRangeR<27 * sizeof(char)    >(strCtn);
	auto ctnR_cDynCtn     = CtnByteRangeR<29 * sizeof(uint64_t)>(cDynArrayCtnSt);

	EXPECT_EQ(ctnR_cArrayCtn.GetValSize(),   sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetValSize(), sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetValSize(),      sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetValSize(),      sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetValSize(),     sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetRegionSize(),   (100 - 12) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetRegionSize(), (101 - 17) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetRegionSize(),      (50  - 22) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetRegionSize(),      (55  - 27) * sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetRegionSize(),     (50  - 29) * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.BeginPtr(),   static_cast<const void*>(&cArrayCtn[12]));
	EXPECT_EQ(ctnR_stdArrayCtn.BeginPtr(), static_cast<const void*>(&stdArrayCtn[17]));
	EXPECT_EQ(ctnR_vecCtn.BeginPtr(),      static_cast<const void*>(&vecCtn[22]));
	EXPECT_EQ(ctnR_strCtn.BeginPtr(),      static_cast<const void*>(&strCtn[27]));
	EXPECT_EQ(ctnR_cDynCtn.BeginPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 29));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.BeginBytePtr()),   static_cast<const void*>(&cArrayCtn[12]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.BeginBytePtr()), static_cast<const void*>(&stdArrayCtn[17]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.BeginBytePtr()),      static_cast<const void*>(&vecCtn[22]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.BeginBytePtr()),      static_cast<const void*>(&strCtn[27]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.BeginBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 29));

	EXPECT_EQ(ctnR_cArrayCtn.EndPtr(),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_stdArrayCtn.EndPtr(), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_vecCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_strCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(ctnR_cDynCtn.EndPtr(),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.EndBytePtr()),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.EndBytePtr()), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.EndBytePtr()),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));
}

GTEST_TEST(TestContainer, ContainerByteDynRangeWithBothEnds)
{
	constexpr uint16_t cArrayCtn[100] = { 0 };
	constexpr std::array<uint16_t, 101> stdArrayCtn = { 0 };
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	vecCtn.resize(50);
	strCtn.resize(55);

	EXPECT_THROW({CtnByteRangeR(cArrayCtn,   50 * sizeof(uint16_t), 0);}, std::invalid_argument);
	EXPECT_THROW({CtnByteRangeR(stdArrayCtn, 50 * sizeof(uint16_t), 0);}, std::invalid_argument);
	EXPECT_THROW({CtnByteRangeR(vecCtn,      50 * sizeof(uint16_t), 0);}, std::invalid_argument);
	EXPECT_THROW({CtnByteRangeR(strCtn,      50 * sizeof(uint16_t), 0);}, std::invalid_argument);
	EXPECT_THROW({CtnByteRangeR(cDynArrayCtnSt, 50 * sizeof(uint64_t), 0);}, std::invalid_argument);

	EXPECT_THROW({CtnByteRangeR(cArrayCtn,   0, 101 * sizeof(uint16_t));}, std::out_of_range);
	EXPECT_THROW({CtnByteRangeR(stdArrayCtn, 0, 102 * sizeof(uint16_t));}, std::out_of_range);
	EXPECT_THROW({CtnByteRangeR(vecCtn,      0, 51  * sizeof(uint16_t));}, std::out_of_range);
	EXPECT_THROW({CtnByteRangeR(strCtn  ,    0, 56  * sizeof(uint16_t));}, std::out_of_range);
	EXPECT_THROW({CtnByteRangeR(cDynArrayCtnSt, 0, 51  * sizeof(uint64_t));}, std::out_of_range);

	//auto ctnR_vecBoolCtn = CtnByteRangeR<0, 0>(vecBoolCtn);
	//auto ctnR_listCtn = CtnByteRangeR<0, 0>(listCtn);
	//auto ctnR_vecBoolCtn = CtnByteRangeR(vecBoolCtn, 0, 0);
	//auto ctnR_listCtn = CtnByteRangeR(listCtn, 0, 0);

	auto ctnR_cArrayCtn   = CtnByteRangeR(cArrayCtn,   5  * sizeof(uint16_t), 70 * sizeof(uint16_t));
	auto ctnR_stdArrayCtn = CtnByteRangeR(stdArrayCtn, 10 * sizeof(uint16_t), 75 * sizeof(uint16_t));
	auto ctnR_vecCtn      = CtnByteRangeR(vecCtn,      15 * sizeof(uint16_t), 45 * sizeof(uint16_t));
	auto ctnR_strCtn      = CtnByteRangeR(strCtn,      20 * sizeof(char)    , 50 * sizeof(char));
	auto ctnR_cDynCtn     = CtnByteRangeR(cDynArrayCtnSt, 25 * sizeof(uint64_t), 49 * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetValSize(),   sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetValSize(), sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetValSize(),      sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetValSize(),      sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetValSize(),     sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetRegionSize(),   (70 - 5 ) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetRegionSize(), (75 - 10) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetRegionSize(),      (45 - 15) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetRegionSize(),      (50 - 20) * sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetRegionSize(),     (49 - 25) * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.BeginPtr(),   static_cast<const void*>(&cArrayCtn[5]));
	EXPECT_EQ(ctnR_stdArrayCtn.BeginPtr(), static_cast<const void*>(&stdArrayCtn[10]));
	EXPECT_EQ(ctnR_vecCtn.BeginPtr(),      static_cast<const void*>(&vecCtn[15]));
	EXPECT_EQ(ctnR_strCtn.BeginPtr(),      static_cast<const void*>(&strCtn[20]));
	EXPECT_EQ(ctnR_cDynCtn.BeginPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 25));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.BeginBytePtr()),   static_cast<const void*>(&cArrayCtn[5]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.BeginBytePtr()), static_cast<const void*>(&stdArrayCtn[10]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.BeginBytePtr()),      static_cast<const void*>(&vecCtn[15]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.BeginBytePtr()),      static_cast<const void*>(&strCtn[20]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.BeginBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 25));

	EXPECT_EQ(ctnR_cArrayCtn.EndPtr(),   static_cast<const void*>(&cArrayCtn[70]));
	EXPECT_EQ(ctnR_stdArrayCtn.EndPtr(), static_cast<const void*>(&stdArrayCtn[75]));
	EXPECT_EQ(ctnR_vecCtn.EndPtr(),      static_cast<const void*>(&vecCtn[45]));
	EXPECT_EQ(ctnR_strCtn.EndPtr(),      static_cast<const void*>(&strCtn[50]));
	EXPECT_EQ(ctnR_cDynCtn.EndPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 49));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.EndBytePtr()),   static_cast<const void*>(&cArrayCtn[70]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.EndBytePtr()), static_cast<const void*>(&stdArrayCtn[75]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.EndBytePtr()),      static_cast<const void*>(&vecCtn[45]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.EndBytePtr()),      static_cast<const void*>(&strCtn[50]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.EndBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 49));
}

GTEST_TEST(TestContainer, ContainerByteDynRangeWithBegin)
{
	constexpr uint16_t cArrayCtn[100] = { 0 };
	constexpr std::array<uint16_t, 101> stdArrayCtn = { 0 };
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	vecCtn.resize(50);
	strCtn.resize(55);

	EXPECT_THROW({CtnByteRangeR(cArrayCtn,   101 * sizeof(uint16_t));}, std::out_of_range);
	EXPECT_THROW({CtnByteRangeR(stdArrayCtn, 102 * sizeof(uint16_t));}, std::out_of_range);
	EXPECT_THROW({CtnByteRangeR(vecCtn,      51  * sizeof(uint16_t));}, std::out_of_range);
	EXPECT_THROW({CtnByteRangeR(strCtn  ,    56  * sizeof(uint16_t));}, std::out_of_range);
	EXPECT_THROW({CtnByteRangeR(cDynArrayCtnSt, 51  * sizeof(uint64_t));}, std::out_of_range);

	//auto ctnR_vecBoolCtn = CtnByteRangeR<0, 0>(vecBoolCtn);
	//auto ctnR_listCtn = CtnByteRangeR<0, 0>(listCtn);
	//auto ctnR_vecBoolCtn = CtnByteRangeR(vecBoolCtn, 0, 0);
	//auto ctnR_listCtn = CtnByteRangeR(listCtn, 0, 0);

	auto ctnR_cArrayCtn   = CtnByteRangeR(cArrayCtn,   12 * sizeof(uint16_t));
	auto ctnR_stdArrayCtn = CtnByteRangeR(stdArrayCtn, 17 * sizeof(uint16_t));
	auto ctnR_vecCtn      = CtnByteRangeR(vecCtn,      22 * sizeof(uint16_t));
	auto ctnR_strCtn      = CtnByteRangeR(strCtn,      27 * sizeof(char));
	auto ctnR_cDynCtn     = CtnByteRangeR(cDynArrayCtnSt, 29 * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetValSize(),   sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetValSize(), sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetValSize(),      sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetValSize(),      sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetValSize(),     sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetRegionSize(),   (100 - 12) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetRegionSize(), (101 - 17) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetRegionSize(),      (50  - 22) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetRegionSize(),      (55  - 27) * sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetRegionSize(),     (50  - 29) * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.BeginPtr(),   static_cast<const void*>(&cArrayCtn[12]));
	EXPECT_EQ(ctnR_stdArrayCtn.BeginPtr(), static_cast<const void*>(&stdArrayCtn[17]));
	EXPECT_EQ(ctnR_vecCtn.BeginPtr(),      static_cast<const void*>(&vecCtn[22]));
	EXPECT_EQ(ctnR_strCtn.BeginPtr(),      static_cast<const void*>(&strCtn[27]));
	EXPECT_EQ(ctnR_cDynCtn.BeginPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 29));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.BeginBytePtr()),   static_cast<const void*>(&cArrayCtn[12]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.BeginBytePtr()), static_cast<const void*>(&stdArrayCtn[17]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.BeginBytePtr()),      static_cast<const void*>(&vecCtn[22]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.BeginBytePtr()),      static_cast<const void*>(&strCtn[27]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.BeginBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 29));

	EXPECT_EQ(ctnR_cArrayCtn.EndPtr(),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_stdArrayCtn.EndPtr(), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_vecCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_strCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(ctnR_cDynCtn.EndPtr(),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.EndBytePtr()),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.EndBytePtr()), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.EndBytePtr()),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));
}

GTEST_TEST(TestContainer, ContainerItemStaticRangeWithBothEnds)
{
	constexpr uint16_t cArrayCtn[100] = { 0 };
	constexpr std::array<uint16_t, 101> stdArrayCtn = { 0 };
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	vecCtn.resize(50);
	strCtn.resize(55);

	auto stat_vecCtn1 = [vecCtn](){CtnItemRangeR<0, 51>(vecCtn);};
	EXPECT_THROW({stat_vecCtn1();}, std::out_of_range);
	auto stat_strCtn1 = [strCtn](){CtnItemRangeR<0, 56>(strCtn);};
	EXPECT_THROW({stat_strCtn1();}, std::out_of_range);
	auto stat_cDynAr1 = [cDynArrayCtnSt](){CtnItemRangeR<0, 51>(cDynArrayCtnSt);};
	EXPECT_THROW({stat_cDynAr1();}, std::out_of_range);

	auto stat_vecCtn2 = [vecCtn](){CtnItemRangeR<51, 51>(vecCtn);};
	EXPECT_THROW({stat_vecCtn2();}, std::out_of_range);
	auto stat_strCtn2 = [strCtn](){CtnItemRangeR<56, 56>(strCtn);};
	EXPECT_THROW({stat_strCtn2();}, std::out_of_range);
	auto stat_cDynAr2 = [cDynArrayCtnSt](){CtnItemRangeR<51, 51>(cDynArrayCtnSt);};
	EXPECT_THROW({stat_cDynAr2();}, std::out_of_range);

	//auto ctnR_vecBoolCtn = CtnItemRangeR<0, 0>(vecBoolCtn);
	//auto ctnR_listCtn = CtnItemRangeR<0, 0>(listCtn);
	//auto ctnR_vecBoolCtn = CtnItemRangeR(vecBoolCtn, 0, 0);
	//auto ctnR_listCtn = CtnItemRangeR(listCtn, 0, 0);

	//auto ctnR_cArrayCtn   = CtnItemRangeR<0, 101>(cArrayCtn);
	//auto ctnR_cArrayCtn   = CtnItemRangeR<10, 5>(cArrayCtn);
	//auto ctnR_stdArrayCtn = CtnItemRangeR<0, 102>(stdArrayCtn);
	auto ctnR_cArrayCtn   = CtnItemRangeR<5 , 70>(cArrayCtn);
	auto ctnR_stdArrayCtn = CtnItemRangeR<10, 75>(stdArrayCtn);
	auto ctnR_vecCtn      = CtnItemRangeR<15, 45>(vecCtn);
	auto ctnR_strCtn      = CtnItemRangeR<20, 50>(strCtn);
	auto ctnR_cDynCtn     = CtnItemRangeR<25, 49>(cDynArrayCtnSt);

	EXPECT_EQ(ctnR_cArrayCtn.GetValSize(),   sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetValSize(), sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetValSize(),      sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetValSize(),      sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetValSize(),     sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetRegionSize(),   (70 - 5 ) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetRegionSize(), (75 - 10) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetRegionSize(),      (45 - 15) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetRegionSize(),      (50 - 20) * sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetRegionSize(),     (49 - 25) * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.BeginPtr(),   static_cast<const void*>(&cArrayCtn[5]));
	EXPECT_EQ(ctnR_stdArrayCtn.BeginPtr(), static_cast<const void*>(&stdArrayCtn[10]));
	EXPECT_EQ(ctnR_vecCtn.BeginPtr(),      static_cast<const void*>(&vecCtn[15]));
	EXPECT_EQ(ctnR_strCtn.BeginPtr(),      static_cast<const void*>(&strCtn[20]));
	EXPECT_EQ(ctnR_cDynCtn.BeginPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 25));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.BeginBytePtr()),   static_cast<const void*>(&cArrayCtn[5]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.BeginBytePtr()), static_cast<const void*>(&stdArrayCtn[10]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.BeginBytePtr()),      static_cast<const void*>(&vecCtn[15]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.BeginBytePtr()),      static_cast<const void*>(&strCtn[20]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.BeginBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 25));

	EXPECT_EQ(ctnR_cArrayCtn.EndPtr(),   static_cast<const void*>(&cArrayCtn[70]));
	EXPECT_EQ(ctnR_stdArrayCtn.EndPtr(), static_cast<const void*>(&stdArrayCtn[75]));
	EXPECT_EQ(ctnR_vecCtn.EndPtr(),      static_cast<const void*>(&vecCtn[45]));
	EXPECT_EQ(ctnR_strCtn.EndPtr(),      static_cast<const void*>(&strCtn[50]));
	EXPECT_EQ(ctnR_cDynCtn.EndPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 49));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.EndBytePtr()),   static_cast<const void*>(&cArrayCtn[70]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.EndBytePtr()), static_cast<const void*>(&stdArrayCtn[75]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.EndBytePtr()),      static_cast<const void*>(&vecCtn[45]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.EndBytePtr()),      static_cast<const void*>(&strCtn[50]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.EndBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 49));
}

GTEST_TEST(TestContainer, ContainerItemStaticRangeWithBegin)
{
	constexpr uint16_t cArrayCtn[100] = { 0 };
	constexpr std::array<uint16_t, 101> stdArrayCtn = { 0 };
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	vecCtn.resize(50);
	strCtn.resize(55);

	auto stat_vecCtn1 = [vecCtn](){CtnItemRangeR<51>(vecCtn);};
	EXPECT_THROW({stat_vecCtn1();}, std::out_of_range);
	auto stat_strCtn1 = [strCtn](){CtnItemRangeR<56>(strCtn);};
	EXPECT_THROW({stat_strCtn1();}, std::out_of_range);
	auto stat_cDynAr1 = [cDynArrayCtnSt](){CtnItemRangeR<51>(cDynArrayCtnSt);};
	EXPECT_THROW({stat_cDynAr1();}, std::out_of_range);

	//auto ctnR_vecBoolCtn = CtnItemRangeR<0, 0>(vecBoolCtn);
	//auto ctnR_listCtn = CtnItemRangeR<0, 0>(listCtn);
	//auto ctnR_vecBoolCtn = CtnItemRangeR(vecBoolCtn, 0, 0);
	//auto ctnR_listCtn = CtnItemRangeR(listCtn, 0, 0);

	//auto ctnR_cArrayCtn1    = CtnItemRangeR<101>(cArrayCtn);
	//auto ctnR_stdArrayCtn11 = CtnItemRangeR<102>(stdArrayCtn);
	auto ctnR_cArrayCtn   = CtnItemRangeR<12>(cArrayCtn);
	auto ctnR_stdArrayCtn = CtnItemRangeR<17>(stdArrayCtn);
	auto ctnR_vecCtn      = CtnItemRangeR<22>(vecCtn);
	auto ctnR_strCtn      = CtnItemRangeR<27>(strCtn);
	auto ctnR_cDynCtn     = CtnItemRangeR<29>(cDynArrayCtnSt);

	EXPECT_EQ(ctnR_cArrayCtn.GetValSize(),   sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetValSize(), sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetValSize(),      sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetValSize(),      sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetValSize(),     sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetRegionSize(),   (100 - 12) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetRegionSize(), (101 - 17) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetRegionSize(),      (50  - 22) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetRegionSize(),      (55  - 27) * sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetRegionSize(),     (50  - 29) * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.BeginPtr(),   static_cast<const void*>(&cArrayCtn[12]));
	EXPECT_EQ(ctnR_stdArrayCtn.BeginPtr(), static_cast<const void*>(&stdArrayCtn[17]));
	EXPECT_EQ(ctnR_vecCtn.BeginPtr(),      static_cast<const void*>(&vecCtn[22]));
	EXPECT_EQ(ctnR_strCtn.BeginPtr(),      static_cast<const void*>(&strCtn[27]));
	EXPECT_EQ(ctnR_cDynCtn.BeginPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 29));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.BeginBytePtr()),   static_cast<const void*>(&cArrayCtn[12]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.BeginBytePtr()), static_cast<const void*>(&stdArrayCtn[17]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.BeginBytePtr()),      static_cast<const void*>(&vecCtn[22]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.BeginBytePtr()),      static_cast<const void*>(&strCtn[27]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.BeginBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 29));

	EXPECT_EQ(ctnR_cArrayCtn.EndPtr(),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_stdArrayCtn.EndPtr(), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_vecCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_strCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(ctnR_cDynCtn.EndPtr(),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.EndBytePtr()),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.EndBytePtr()), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.EndBytePtr()),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));
}

GTEST_TEST(TestContainer, ContainerItemDynRangeWithBothEnds)
{
	constexpr uint16_t cArrayCtn[100] = { 0 };
	constexpr std::array<uint16_t, 101> stdArrayCtn = { 0 };
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	vecCtn.resize(50);
	strCtn.resize(55);

	EXPECT_THROW({CtnItemRangeR(cArrayCtn,   50, 0);}, std::invalid_argument);
	EXPECT_THROW({CtnItemRangeR(stdArrayCtn, 50, 0);}, std::invalid_argument);
	EXPECT_THROW({CtnItemRangeR(vecCtn,      50, 0);}, std::invalid_argument);
	EXPECT_THROW({CtnItemRangeR(strCtn,      50, 0);}, std::invalid_argument);
	EXPECT_THROW({CtnItemRangeR(cDynArrayCtnSt, 50, 0);}, std::invalid_argument);

	EXPECT_THROW({CtnItemRangeR(cArrayCtn,   0, 101);}, std::out_of_range);
	EXPECT_THROW({CtnItemRangeR(stdArrayCtn, 0, 102);}, std::out_of_range);
	EXPECT_THROW({CtnItemRangeR(vecCtn,      0, 51 );}, std::out_of_range);
	EXPECT_THROW({CtnItemRangeR(strCtn  ,    0, 56 );}, std::out_of_range);
	EXPECT_THROW({CtnItemRangeR(cDynArrayCtnSt, 0, 51);}, std::out_of_range);

	//auto ctnR_vecBoolCtn = CtnItemRangeR<0, 0>(vecBoolCtn);
	//auto ctnR_listCtn = CtnItemRangeR<0, 0>(listCtn);
	//auto ctnR_vecBoolCtn = CtnItemRangeR(vecBoolCtn, 0, 0);
	//auto ctnR_listCtn = CtnItemRangeR(listCtn, 0, 0);

	auto ctnR_cArrayCtn   = CtnItemRangeR(cArrayCtn,   5, 70);
	auto ctnR_stdArrayCtn = CtnItemRangeR(stdArrayCtn, 10, 75);
	auto ctnR_vecCtn      = CtnItemRangeR(vecCtn,      15, 45);
	auto ctnR_strCtn      = CtnItemRangeR(strCtn,      20, 50);
	auto ctnR_cDynCtn     = CtnItemRangeR(cDynArrayCtnSt, 25, 49);

	EXPECT_EQ(ctnR_cArrayCtn.GetValSize(),   sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetValSize(), sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetValSize(),      sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetValSize(),      sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetValSize(),     sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetRegionSize(),   (70 - 5 ) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetRegionSize(), (75 - 10) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetRegionSize(),      (45 - 15) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetRegionSize(),      (50 - 20) * sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetRegionSize(),     (49 - 25) * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.BeginPtr(),   static_cast<const void*>(&cArrayCtn[5]));
	EXPECT_EQ(ctnR_stdArrayCtn.BeginPtr(), static_cast<const void*>(&stdArrayCtn[10]));
	EXPECT_EQ(ctnR_vecCtn.BeginPtr(),      static_cast<const void*>(&vecCtn[15]));
	EXPECT_EQ(ctnR_strCtn.BeginPtr(),      static_cast<const void*>(&strCtn[20]));
	EXPECT_EQ(ctnR_cDynCtn.BeginPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 25));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.BeginBytePtr()),   static_cast<const void*>(&cArrayCtn[5]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.BeginBytePtr()), static_cast<const void*>(&stdArrayCtn[10]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.BeginBytePtr()),      static_cast<const void*>(&vecCtn[15]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.BeginBytePtr()),      static_cast<const void*>(&strCtn[20]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.BeginBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 25));

	EXPECT_EQ(ctnR_cArrayCtn.EndPtr(),   static_cast<const void*>(&cArrayCtn[70]));
	EXPECT_EQ(ctnR_stdArrayCtn.EndPtr(), static_cast<const void*>(&stdArrayCtn[75]));
	EXPECT_EQ(ctnR_vecCtn.EndPtr(),      static_cast<const void*>(&vecCtn[45]));
	EXPECT_EQ(ctnR_strCtn.EndPtr(),      static_cast<const void*>(&strCtn[50]));
	EXPECT_EQ(ctnR_cDynCtn.EndPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 49));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.EndBytePtr()),   static_cast<const void*>(&cArrayCtn[70]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.EndBytePtr()), static_cast<const void*>(&stdArrayCtn[75]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.EndBytePtr()),      static_cast<const void*>(&vecCtn[45]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.EndBytePtr()),      static_cast<const void*>(&strCtn[50]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.EndBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 49));
}

GTEST_TEST(TestContainer, ContainerItemDynRangeWithBegin)
{
	constexpr uint16_t cArrayCtn[100] = { 0 };
	constexpr std::array<uint16_t, 101> stdArrayCtn = { 0 };
	std::vector<uint16_t> vecCtn;
	std::string strCtn;
	std::unique_ptr<uint64_t[]> cDynArrayCtn = Internal::make_unique<uint64_t[]>(50);
	CDynArray<uint64_t> cDynArrayCtnSt{cDynArrayCtn.get(), 50};

	std::vector<bool> vecBoolCtn;
	std::list<uint8_t> listCtn;

	vecCtn.resize(50);
	strCtn.resize(55);

	EXPECT_THROW({CtnItemRangeR(cArrayCtn,   101);}, std::out_of_range);
	EXPECT_THROW({CtnItemRangeR(stdArrayCtn, 102);}, std::out_of_range);
	EXPECT_THROW({CtnItemRangeR(vecCtn,      51 );}, std::out_of_range);
	EXPECT_THROW({CtnItemRangeR(strCtn  ,    56 );}, std::out_of_range);
	EXPECT_THROW({CtnItemRangeR(cDynArrayCtnSt, 51);}, std::out_of_range);

	//auto ctnR_vecBoolCtn = CtnItemRangeR<0, 0>(vecBoolCtn);
	//auto ctnR_listCtn = CtnItemRangeR<0, 0>(listCtn);
	//auto ctnR_vecBoolCtn = CtnItemRangeR(vecBoolCtn, 0, 0);
	//auto ctnR_listCtn = CtnItemRangeR(listCtn, 0, 0);

	auto ctnR_cArrayCtn   = CtnItemRangeR(cArrayCtn,   12);
	auto ctnR_stdArrayCtn = CtnItemRangeR(stdArrayCtn, 17);
	auto ctnR_vecCtn      = CtnItemRangeR(vecCtn,      22);
	auto ctnR_strCtn      = CtnItemRangeR(strCtn,      27);
	auto ctnR_cDynCtn      = CtnItemRangeR(cDynArrayCtnSt, 29);

	EXPECT_EQ(ctnR_cArrayCtn.GetValSize(),   sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetValSize(), sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetValSize(),      sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetValSize(),      sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetValSize(),     sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.GetRegionSize(),   (100 - 12) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_stdArrayCtn.GetRegionSize(), (101 - 17) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_vecCtn.GetRegionSize(),      (50  - 22) * sizeof(uint16_t));
	EXPECT_EQ(ctnR_strCtn.GetRegionSize(),      (55  - 27) * sizeof(char));
	EXPECT_EQ(ctnR_cDynCtn.GetRegionSize(),     (50  - 29) * sizeof(uint64_t));

	EXPECT_EQ(ctnR_cArrayCtn.BeginPtr(),   static_cast<const void*>(&cArrayCtn[12]));
	EXPECT_EQ(ctnR_stdArrayCtn.BeginPtr(), static_cast<const void*>(&stdArrayCtn[17]));
	EXPECT_EQ(ctnR_vecCtn.BeginPtr(),      static_cast<const void*>(&vecCtn[22]));
	EXPECT_EQ(ctnR_strCtn.BeginPtr(),      static_cast<const void*>(&strCtn[27]));
	EXPECT_EQ(ctnR_cDynCtn.BeginPtr(),     static_cast<const void*>(cDynArrayCtn.get() + 29));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.BeginBytePtr()),   static_cast<const void*>(&cArrayCtn[12]));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.BeginBytePtr()), static_cast<const void*>(&stdArrayCtn[17]));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.BeginBytePtr()),      static_cast<const void*>(&vecCtn[22]));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.BeginBytePtr()),      static_cast<const void*>(&strCtn[27]));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.BeginBytePtr()),     static_cast<const void*>(cDynArrayCtn.get() + 29));

	EXPECT_EQ(ctnR_cArrayCtn.EndPtr(),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_stdArrayCtn.EndPtr(), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_vecCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(ctnR_strCtn.EndPtr(),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(ctnR_cDynCtn.EndPtr(),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));

	EXPECT_EQ(static_cast<const void*>(ctnR_cArrayCtn.EndBytePtr()),   static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&cArrayCtn[99])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_stdArrayCtn.EndBytePtr()), static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&stdArrayCtn[100])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_vecCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&vecCtn[49])) + sizeof(uint16_t)));
	EXPECT_EQ(static_cast<const void*>(ctnR_strCtn.EndBytePtr()),      static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(&strCtn[54])) + sizeof(char)));
	EXPECT_EQ(static_cast<const void*>(ctnR_cDynCtn.EndBytePtr()),     static_cast<const void*>(static_cast<const uint8_t*>(static_cast<const void*>(cDynArrayCtn.get() + 50))));
}
