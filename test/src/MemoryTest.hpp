#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/Entropy.hpp>
#include <mbedTLScpp/Internal/Memory.hpp>

#ifdef MBEDTLSCPP_MEMORY_TEST
#include <mbedTLScpp/SecretAllocator.hpp>

#	ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScppMemoryLeakNS = mbedTLScpp::Internal;
namespace mbedTLScppSecretMemoryLeakNS = mbedTLScpp;
#	else
namespace mbedTLScppMemoryLeakNS = MBEDTLSCPP_CUSTOMIZED_NAMESPACE::Internal;
namespace mbedTLScppSecretMemoryLeakNS = MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#	endif

#endif

#ifdef MBEDTLSCPP_MEMORY_TEST
#	define MEMORY_LEAK_TEST_COUNT(X)            EXPECT_EQ(mbedTLScppMemoryLeakNS::gs_allocationLeft, X)
#	define MEMORY_LEAK_TEST_INCR_COUNT(INIT, X) MEMORY_LEAK_TEST_COUNT(INIT + (X))
#	define MEMORY_LEAK_TEST_GET_COUNT(D)        {D = mbedTLScppMemoryLeakNS::gs_allocationLeft;}
#else
#	define MEMORY_LEAK_TEST_COUNT(X)
#	define MEMORY_LEAK_TEST_INCR_COUNT(INIT, X)
#	define MEMORY_LEAK_TEST_GET_COUNT(D)
#endif

#ifdef MBEDTLSCPP_MEMORY_TEST
#	define SECRET_MEMORY_LEAK_TEST_COUNT(X)            EXPECT_EQ(mbedTLScppSecretMemoryLeakNS::gs_secretAllocationLeft, X)
#	define SECRET_MEMORY_LEAK_TEST_INCR_COUNT(INIT, X) SECRET_MEMORY_LEAK_TEST_COUNT(INIT + (X))
#	define SECRET_MEMORY_LEAK_TEST_GET_COUNT(D)        {D = mbedTLScppSecretMemoryLeakNS::gs_secretAllocationLeft;}

#	define SECRET_MEMORY_LEAK_TEST_COUNT_GE(X)            EXPECT_GE(mbedTLScppSecretMemoryLeakNS::gs_secretAllocationLeft, X)
#	define SECRET_MEMORY_LEAK_TEST_INCR_COUNT_GE(INIT, X) SECRET_MEMORY_LEAK_TEST_COUNT_GE(INIT + (X))
#else
#	define SECRET_MEMORY_LEAK_TEST_COUNT(X)
#	define SECRET_MEMORY_LEAK_TEST_INCR_COUNT(INIT, X)
#	define SECRET_MEMORY_LEAK_TEST_GET_COUNT(D)

#	define SECRET_MEMORY_LEAK_TEST_COUNT_GE(X)
#	define SECRET_MEMORY_LEAK_TEST_INCR_COUNT_GE(INIT, X)
#endif

template<typename _InnerType>
struct MemTestObj
{
	_InnerType* m_data;

	MemTestObj() :
		m_data(mbedTLScppMemoryLeakNS::NewObject<_InnerType>())
	{}

	MemTestObj(const _InnerType& data) :
		m_data(mbedTLScppMemoryLeakNS::NewObject<_InnerType>(data))
	{}

	MemTestObj(_InnerType&& data) :
		m_data(mbedTLScppMemoryLeakNS::NewObject<_InnerType>(std::forward<_InnerType>(data)))
	{}

	MemTestObj(const MemTestObj& other) :
		m_data(mbedTLScppMemoryLeakNS::NewObject<_InnerType>(*other.m_data))
	{}

	MemTestObj(MemTestObj&& other) :
		m_data(other.m_data)
	{
		other.m_data = nullptr;
	}

	virtual ~MemTestObj()
	{
		mbedTLScppMemoryLeakNS::DelObject(m_data);
	}

	MemTestObj& operator=(MemTestObj&& other)
	{
		if(this != &other)
		{
			// destroy this:
			mbedTLScppMemoryLeakNS::DelObject(m_data);

			// get pointer from other
			m_data = other.m_data;

			// invalidate other.
			other.m_data = nullptr;
		}
		return *this;
	}

	MemTestObj& operator=(const MemTestObj& other)
	{
		if(this != &other)
		{
			// destroy this:
			mbedTLScppMemoryLeakNS::DelObject(m_data);

			// copy construction
			m_data = other.m_data == nullptr ? nullptr : mbedTLScppMemoryLeakNS::NewObject<_InnerType>(*other.m_data);
		}
		return *this;
	}

	_InnerType& Data() noexcept
	{
		return *m_data;
	}

	const _InnerType& Data() const noexcept
	{
		return *m_data;
	}

	bool Empty() const noexcept
	{
		return m_data == nullptr;
	}

	bool operator==(const MemTestObj& rhs) const
	{
		return m_data == nullptr || rhs.m_data == nullptr ?
			m_data == rhs.m_data :
			Data() == rhs.Data();
	}
};

inline void SettleMemTestCountOnEntropy()
{
#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
	using namespace mbedTLScpp;
#else
	using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

	EXPECT_NE(GetSharedEntropy()->GetRawPtr(), nullptr);
}
