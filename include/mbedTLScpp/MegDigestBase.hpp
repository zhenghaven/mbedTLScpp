#pragma once

#include "ObjectBase.hpp"

#include <mbedtls/md.h>

#include "Common.hpp"
#include "Exceptions.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/** @brief	Enum that represent hash types */
	enum class HashType
	{
		SHA224,
		SHA256,
		SHA384,
		SHA512,
	};

	/**
	 * @brief Get the size (in bytes) of a given Hash type.
	 *
	 * @exception InvalidArgumentException Thrown when the given hash type is not supported.
	 * @param type The type of the hash
	 * @return constexpr uint8_t The size in bytes
	 */
	inline constexpr uint8_t GetHashByteSize(HashType type)
	{
		return (type == HashType::SHA224 ?
		           (224 / gsk_bitsPerByte) :
			   (type == HashType::SHA256 ?
			       (256 / gsk_bitsPerByte) :
			   (type == HashType::SHA384 ?
			       (384 / gsk_bitsPerByte) :
			   (type == HashType::SHA512 ?
			       (512 / gsk_bitsPerByte) :
                   throw InvalidArgumentException("Hash type given is not supported.")
			   ))));
	}
	static_assert(GetHashByteSize(HashType::SHA224) == (224 / gsk_bitsPerByte), "Programming error.");
	static_assert(GetHashByteSize(HashType::SHA256) == (256 / gsk_bitsPerByte), "Programming error.");
	static_assert(GetHashByteSize(HashType::SHA384) == (384 / gsk_bitsPerByte), "Programming error.");
	static_assert(GetHashByteSize(HashType::SHA512) == (512 / gsk_bitsPerByte), "Programming error.");

	/** @brief	Message Digest Base class. It will be further inherited by the
	 *          hash calculator and HMAC calculator.
	 */
	class MsgDigestBase : public ObjectBase<mbedtls_md_context_t>
	{
	public: // static members:

		/**
		 * @brief Get the md_info C object from mbed TLS, by using the HashType.
		 *
		 * @exception InvalidArgumentException Thrown when the given hash type is not supported.
		 * @param type The hash type
		 * @return const mbedtls_md_info_t& The reference to md_info C object from mbed TLS
		 */
		static inline const mbedtls_md_info_t& GetMdInfo(HashType type)
		{
			const mbedtls_md_info_t* res = nullptr;
			switch (type)
			{
			case HashType::SHA224:
				res = mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA224);
				break;
			case HashType::SHA256:
				res = mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256);
				break;
			case HashType::SHA384:
				res = mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA384);
				break;
			case HashType::SHA512:
				res = mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA512);
				break;
			default:
				break;
			}

			if (res != nullptr)
			{
				return *res;
			}
			throw InvalidArgumentException("Hash type given is not supported.");
		}

	public:

		/**
		 * @brief Construct a new Msgessage Digest Base object.
		 *
		 * @exception mbedTLSRuntimeError    Thrown when mbed TLS C function call failed.
		 * @param mdInfo   The md info provided by mbed TLS library.
		 * @param needHmac Is HMAC calculation needed?
		 */
		MsgDigestBase(const mbedtls_md_info_t& mdInfo, bool needHmac) :
			ObjectBase(&mbedtls_md_free)
		{
			static_assert(false == 0, "The value of false is different with the one expected in mbedTLS.");

			mbedtls_md_init(Get());

			MBEDTLSCPP_MAKE_C_FUNC_CALL(MsgDigestBase::MsgDigestBase, mbedtls_md_setup, Get(), &mdInfo, needHmac);
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other MsgDigestBase instance.
		 */
		MsgDigestBase(MsgDigestBase&& rhs) noexcept :
			ObjectBase(std::forward<ObjectBase>(rhs)) //noexcept
		{}

		MsgDigestBase(const MsgDigestBase& rhs) = delete;

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other MsgDigestBase instance.
		 * @return MsgDigestBase& A reference to this instance.
		 */
		MsgDigestBase& operator=(MsgDigestBase&& rhs) noexcept
		{
			ObjectBase::operator=(std::forward<ObjectBase>(rhs)); //noexcept

			return *this;
		}

		MsgDigestBase& operator=(const MsgDigestBase& other) = delete;

		/** @brief	Destructor */
		virtual ~MsgDigestBase()
		{}

		/**
		 * @brief Check if the current instance is holding a null pointer for
		 *        the mbedTLS object. If so, exception will be thrown. Helper
		 *        function to be called before accessing the mbedTLS object.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 */
		virtual void NullCheck() const
		{
			ObjectBase::NullCheck(typeid(MsgDigestBase).name());
		}
	};
}