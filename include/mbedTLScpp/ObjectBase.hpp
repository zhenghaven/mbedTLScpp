#pragma once

#include "Exceptions.hpp"

#include "Internal/Memory.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/** @brief	An object base class for MbedTLS objects. */
	template<typename CObjType>
	class ObjectBase
	{
	public:

		/**
		 * @brief The type of object free function, which is usually the free function
		 *        defined in the mbedTLS.
		 *
		 */
		typedef void(*ObjectFreeFunction)(CObjType*);

		/**
		 * @brief A function receives mbedTLS C object as parameter, but do nothing.
		 *
		 * @exception None No exception thrown
		 * @param ptr mbedTLS C object
		 */
		static void DoNoting(CObjType* ptr) noexcept {}

	public:
		ObjectBase() = delete;

		ObjectBase(const ObjectBase& other) = delete;

		/**
		 * @brief	Move constructor
		 *
		 * @exception None No exception thrown
		 * @param [in,out]	other	The other instance.
		 */
		ObjectBase(ObjectBase&& rhs) noexcept :
			m_ptr(rhs.m_ptr),
			m_objFreer(rhs.m_objFreer)
		{
			rhs.m_ptr = nullptr;
			rhs.m_objFreer = nullptr;
		}

		/** @brief	Destructor */
		virtual ~ObjectBase()
		{
			FreeBaseObject();
		}

		ObjectBase& operator=(const ObjectBase& other) = delete;

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
		CObjType* Release() noexcept
		{
			CObjType* tmp = m_ptr;

			m_ptr = nullptr;
			m_objFreer = nullptr;

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
			return m_objFreer != nullptr;
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

	protected:

		/**
		 * @brief Construct a new mbedTLS Object Base. Usually this object base
		 *        owns the object, so the object free function will be called in the
		 *        destructor of this instance.
		 *
		 * @exception None No exception thrown
		 * @param ptr      The pointer to the not null mbedTLS C object.
		 * @param objFreer The object free function that will be called in the destructor
		 *                 of this instance.
		 */
		ObjectBase(ObjectFreeFunction objFreer) noexcept :
			m_ptr(Internal::NewObject<CObjType>()),
			m_objFreer(objFreer)
		{}

		/**
		 * @brief Construct a new mbedTLS Object Base. Usually this object base
		 *        DOES NOT own the object, so no free function will be called in the
		 *        destructor.
		 *
		 * @exception None No exception thrown
		 * @param ptr The pointer to the not null mbedTLS C object.
		 */
		ObjectBase(CObjType* ptr) noexcept :
			m_ptr(ptr),
			m_objFreer(nullptr)
		{}

		/**
		 * @brief	Move assignment operator. The RHS will become empty afterwards.
		 *
		 * @param [in,out]	rhs	The right hand side.
		 *
		 * @return	A reference to this object.
		 */
		ObjectBase& operator=(ObjectBase&& rhs)
		{
			if (this != &rhs)
			{
				//Free the object to prevent memory leak.
				Free();

				m_ptr = rhs.m_ptr;
				m_objFreer = rhs.m_objFreer;

				rhs.m_ptr = nullptr;
				rhs.m_objFreer = nullptr;
			}
			return *this;
		}

		/** @brief	Free the current object. */
		void Free()
		{
			FreeBaseObject();
		}

		/**
		 * @brief	Swaps the given right hand side.
		 *
		 * @exception None No exception thrown
		 * @param [in,out]	rhs	The right hand side.
		 */
		void Swap(ObjectBase& rhs) noexcept
		{
			std::swap(m_ptr, rhs.m_ptr);
			std::swap(m_objFreer, rhs.m_objFreer);
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
		 * @brief Set the Free Function for freeing the mbedTLS object.
		 *
		 * @exception None No exception thrown
		 * @param objFreer The free function
		 */
		void SetFreeFunc(ObjectFreeFunction objFreer) noexcept
		{
			m_objFreer = objFreer;
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

	private:
		CObjType * m_ptr;
		ObjectFreeFunction m_objFreer;

		void FreeBaseObject()
		{
			if(m_objFreer != nullptr)
			{
				(*m_objFreer)(m_ptr);

				Internal::DelObject(m_ptr);
			}
			m_ptr = nullptr;
			m_objFreer = nullptr;
		}
	};
}
