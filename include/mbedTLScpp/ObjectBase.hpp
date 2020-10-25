#pragma once

#include "Exceptions.hpp"

#include "Internal/Memory.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{

	/**
	 * @brief The base of normal allocators
	 *
	 */
	struct DefaultAllocBase
	{
		template<typename T, class... _Args>
		static T* NewObject(_Args&&... __args)
		{
			return Internal::NewObject<T, _Args...>(std::forward<_Args>(__args)...);
		}

		template<typename T>
		static void DelObject(T* ptr) noexcept
		{
			return Internal::DelObject(ptr);
		}
	};

	/**
	 * @brief The base allocator for a type of borrowed object
	 *
	 * @tparam _CObjType The type of the mbed TLS C object.
	 */
	template<typename _CObjType>
	struct BorrowAllocBase : public DefaultAllocBase
	{
		typedef _CObjType      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{}

		static void Free(CObjType* ptr) noexcept
		{}
	};

	/**
	 * @brief The trait template, for easier defining the trait for mbed TLS cpp object.
	 *
	 * @tparam _CObjType     The type of the mbed TLS C object.
	 * @tparam _ObjAllocator The allocator for the mbed TLS C object.
	 * @tparam _isBorrower   Is the type a borrower?
	 * @tparam _isConst      Is the inner mbed TLS C object a constant?
	 */
	template<typename _ObjAllocator,
		bool _isBorrower,
		bool _isConst>
	struct ObjTraitBase
	{
		typedef _ObjAllocator  ObjAllocator;

		typedef typename ObjAllocator::CObjType     CObjType;

		static constexpr bool sk_isBorrower = _isBorrower;
		static constexpr bool sk_isConst    = _isConst;
	};

	/** @brief	An object base class for MbedTLS objects. */
	template<typename _ObjTrait>
	class ObjectBase
	{
	public: // Static members:

		using ObjTrait = _ObjTrait;
		using CObjType = typename ObjTrait::CObjType;
		using Allocator = typename ObjTrait::ObjAllocator;

	public:

		/**
		 * @brief Construct a new mbedTLS Object Base. Usually this object base
		 *        owns the object (i.e., allocate & init at begining, free at exit).
		 *
		 * @exception Unclear may throw std::bad_alloc
		 */
		template<typename _dummy_ObjTrait = ObjTrait, enable_if_t<!_dummy_ObjTrait::sk_isBorrower, int> = 0>
		ObjectBase() :
			m_ptr(Allocator::template NewObject<CObjType>())
		{
			Allocator::Init(m_ptr);
		}

		/**
		 * @brief Construct a new mbedTLS Object Base. Usually this object base
		 *        DOES NOT own the object (i.e., no allocation, init, & free).
		 *
		 * @exception None No exception thrown
		 * @param ptr The pointer to the not null mbedTLS C object.
		 */
		template<typename _dummy_ObjTrait = ObjTrait, enable_if_t<_dummy_ObjTrait::sk_isBorrower, int> = 0>
		ObjectBase(CObjType* ptr) noexcept :
			m_ptr(ptr)
		{}

		ObjectBase(const ObjectBase& other) = delete;

		/**
		 * @brief	Move constructor
		 *
		 * @exception None No exception thrown
		 * @param [in,out]	other	The other instance.
		 */
		ObjectBase(ObjectBase&& rhs) noexcept :
			m_ptr(rhs.m_ptr)
		{
			rhs.m_ptr = nullptr;
		}

		/** @brief	Destructor */
		virtual ~ObjectBase()
		{
			FreeBaseObject();
		}

		ObjectBase& operator=(const ObjectBase& other) = delete;

		/**
		 * @brief	Move assignment operator. The RHS will become empty afterwards.
		 *
		 * @param [in,out]	rhs	The right hand side.
		 *
		 * @return	A reference to this object.
		 */
		ObjectBase& operator=(ObjectBase&& rhs) noexcept
		{
			if (this != &rhs)
			{
				//Free the object to prevent memory leak.
				FreeBaseObject(); //noexcept

				m_ptr = rhs.m_ptr;

				rhs.m_ptr = nullptr;
			}
			return *this;
		}

		/**
		 * @brief	Gets the pointer to the MbedTLS object.
		 *
		 * @exception None No exception thrown
		 * @return	The pointer to the MbedTLS object.
		 */
		const CObjType* Get() const noexcept
		{
			return m_ptr;
		}

		/**
		 * @brief	Gets the pointer to the MbedTLS object.
		 *
		 * @exception None No exception thrown
		 * @return	The pointer to the MbedTLS object.
		 */
		template<typename _dummy_ObjTrait = ObjTrait, enable_if_t<!_dummy_ObjTrait::sk_isConst, int> = 0>
		CObjType* Get() noexcept
		{
			return m_ptr;
		}

		/**
		 * @brief	Releases the ownership of the MbedTLS Object, and
		 * 			return the pointer to the MbedTLS object.
		 *
		 * @exception None No exception thrown
		 * @return	The pointer to the MbedTLS object.
		 */
		template<typename _dummy_ObjTrait = ObjTrait, enable_if_t<!_dummy_ObjTrait::sk_isConst, int> = 0>
		CObjType* Release() noexcept
		{
			CObjType* tmp = m_ptr;

			m_ptr = nullptr;

			return tmp;
		}

		/**
		 * @brief	Query if this is the actual owner of MbedTLS object.
		 *
		 * @exception None No exception thrown
		 * @return	True if it's, false if not.
		 */
		virtual bool IsOwner() const noexcept
		{
			return ObjTrait::sk_isBorrower;
		}

		/**
		 * @brief	Query if c object held by this object is null
		 *
		 * @exception None No exception thrown
		 * @return	True if null, false if not.
		 */
		virtual bool IsNull() const noexcept
		{
			return m_ptr == nullptr;
		}

		/** @brief	Free the current object. */
		void FreeBaseObject() noexcept
		{
			constexpr bool isBorrower = ObjTrait::sk_isBorrower;
			if(!isBorrower)
			{
				if(m_ptr != nullptr)
				{
					Allocator::Free(m_ptr); //assume noexcept

					Allocator::DelObject(m_ptr); //noexcept

					m_ptr = nullptr;
				}
			}
			else
			{
				m_ptr = nullptr;
			}
		}

	protected:

		/**
		 * @brief	Swaps the given right hand side.
		 *
		 * @exception None No exception thrown
		 * @param [in,out]	rhs	The right hand side.
		 */
		virtual void Swap(ObjectBase& rhs) noexcept
		{
			std::swap(m_ptr, rhs.m_ptr);
		}

		/**
		 * @brief Set the pointer to the mbedTLS.
		 *
		 * @exception None No exception thrown
		 * @param ptr pointer to the mbedTLS
		 */
		void SetPtr(CObjType* ptr) noexcept
		{
			m_ptr = ptr;
		}

		/**
		 * @brief Check if the current instance is holding a null pointer for
		 *        the mbedTLS object. If so, exception will be thrown. Helper
		 *        function to be called before accessing the mbedTLS object.
		 *        NOTE: this function should called&override by the child class
		 *        to receive the child class's name.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @param objTypeName The name of the child class that inherit this base
		 *                    class.
		 */
		virtual void NullCheck(const std::string& objTypeName) const
		{
			if (IsNull())
			{
				throw InvalidObjectException(objTypeName);
			}
		}

		/**
		 * @brief	Gets the pointer to the MbedTLS object. It's used by child
		 *          class who is "const" specified by trait and knows how to protect
		 *          the inner const object, but still need to access the non-const pointer.
		 *
		 * @exception None No exception thrown
		 * @return	The pointer to the MbedTLS object.
		 */
		CObjType* InternalGet() noexcept
		{
			return m_ptr;
		}

	private:
		CObjType * m_ptr;
	};
}
