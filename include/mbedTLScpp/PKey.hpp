#pragma once

#include "ObjectBase.hpp"

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pem.h>

#include "Common.hpp"
#include "Exceptions.hpp"
#include "Container.hpp"
#include "Hash.hpp"
#include "DefaultRbg.hpp"
#include "RandInterfaces.hpp"

#include "Internal/PKeyHelper.hpp"
#include "Internal/Pem.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief	Values that represent public key (asymmetric key)
	 *          algorithm categories. For now, it could be EC, or RSA.
	 */
	enum class PKeyAlgmCat
	{
		EC,
		RSA,
	};

	/**
	 * @brief	Values that represent public key (asymmetric key) types.
	 *          It's either public or private
	 */
	enum class PKeyType
	{
		Public,
		Private,
	};

	/**
	 * @brief Public Key object allocator.
	 *
	 */
	struct PKeyObjAllocator : DefaultAllocBase
	{
		typedef mbedtls_pk_context      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_pk_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_pk_free(ptr);
		}
	};

	/**
	 * @brief Public Key object trait.
	 *
	 */
	using DefaultPKeyObjTrait = ObjTraitBase<PKeyObjAllocator,
											 false,
											 false>;

	/**
	 * @brief Borrower Public Key object trait.
	 *
	 */
	using BorrowedPKeyTrait = ObjTraitBase<BorrowAllocBase<mbedtls_pk_context>,
									true,
									false>;

	template<typename _PKeyObjTrait = DefaultPKeyObjTrait,
			 enable_if_t<std::is_same<typename _PKeyObjTrait::CObjType, mbedtls_pk_context>::value, int> = 0>
	class PKeyBase : public ObjectBase<_PKeyObjTrait>
	{
	public: // static member:

		using PKObjTrait = _PKeyObjTrait;
		using _Base      = ObjectBase<PKObjTrait>;

		static void PKeyContextNullCheck(const mbedtls_pk_context & ctx)
		{
			if(ctx.pk_ctx == nullptr)
			{
				throw InvalidArgumentException("PKeyBase::PKeyContextNullCheck - The given PKey context is null.");
			}
		}

		static PKeyAlgmCat GetAlgmCat(const mbedtls_pk_context & ctx)
		{
			mbedtls_pk_type_t type = mbedtls_pk_get_type(&ctx);

			switch (type)
			{
			case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY:
			case mbedtls_pk_type_t::MBEDTLS_PK_ECKEY_DH:
			case mbedtls_pk_type_t::MBEDTLS_PK_ECDSA:
				return PKeyAlgmCat::EC;
			case mbedtls_pk_type_t::MBEDTLS_PK_RSA:
			case mbedtls_pk_type_t::MBEDTLS_PK_RSA_ALT:
			case mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS:
				return PKeyAlgmCat::RSA;
			case mbedtls_pk_type_t::MBEDTLS_PK_NONE:
				throw InvalidArgumentException("PKeyBase::GetAlgmCat - The given PKey has no type; it's empty.");
			default:
				throw InvalidArgumentException("PKeyBase::GetAlgmCat - The given PKey type isn't supported.");
			}
		}

		static bool HasPubKey(const mbedtls_ecp_keypair & ctx)
		{
			const int retVal = mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q);
			return (retVal == MBEDTLS_EXIT_SUCCESS) ?
						true :
						(
							(retVal == MBEDTLS_ERR_ECP_INVALID_KEY) ?
								false :
								throw mbedTLSRuntimeError(retVal, mbedTLSRuntimeError::ConstructWhatMsg(retVal, "PKeyBase::HasPubKey", "mbedtls_ecp_check_pubkey"))
						);
		}

		static bool HasPrvKey(const mbedtls_ecp_keypair & ctx)
		{
			const int retVal = mbedtls_ecp_check_privkey(&ctx.grp, &ctx.d);
			return (retVal == MBEDTLS_EXIT_SUCCESS) ?
						true :
						(
							(retVal == MBEDTLS_ERR_ECP_INVALID_KEY) ?
								false :
								throw mbedTLSRuntimeError(retVal, mbedTLSRuntimeError::ConstructWhatMsg(retVal, "PKeyBase::HasPrvKey", "mbedtls_ecp_check_privkey"))
						);
		}

		static bool HasPubKey(const mbedtls_rsa_context & ctx)
		{
			return mbedtls_rsa_check_pubkey(&ctx) == MBEDTLS_EXIT_SUCCESS;
		}

		static bool HasPrvKey(const mbedtls_rsa_context & ctx)
		{
			return mbedtls_rsa_check_privkey(&ctx) == MBEDTLS_EXIT_SUCCESS;
		}

		static PKeyType GetKeyType(const mbedtls_ecp_keypair & ctx)
		{
			if (HasPrvKey(ctx))
			{
				return PKeyType::Private;
			}
			else if(HasPubKey(ctx))
			{
				return PKeyType::Public;
			}
			throw InvalidArgumentException("PKeyBase::GetKeyType - The given PKey context is empty; it has no private and public key.");
		}

		static PKeyType GetKeyType(const mbedtls_rsa_context & ctx)
		{
			if (HasPrvKey(ctx))
			{
				return PKeyType::Private;
			}
			else if(HasPubKey(ctx))
			{
				return PKeyType::Public;
			}
			throw InvalidArgumentException("PKeyBase::GetKeyType - The given PKey context is empty; it has no private and public key.");
		}

		static PKeyType GetKeyType(const mbedtls_pk_context & ctx)
		{
			PKeyContextNullCheck(ctx);

			PKeyAlgmCat algmCat = GetAlgmCat(ctx);

			switch (algmCat)
			{
			case PKeyAlgmCat::EC:
			{
				const mbedtls_ecp_keypair* subCtx = mbedtls_pk_ec(ctx);
				return GetKeyType(*subCtx);
			}
			case PKeyAlgmCat::RSA:
			{
				const mbedtls_rsa_context* subCtx = mbedtls_pk_rsa(ctx);
				return GetKeyType(*subCtx);
			}
			default:
				throw UnexpectedErrorException("Program Error - PKeyBase::GetAlgmCat should not return invalid result.");
			}
		}

	public:

		/**
		 * @brief Construct a new \em empty PKeyBase object
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is not available for borrowers.
		 */
		template<typename _dummy_PKTrait = PKObjTrait,
			enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		PKeyBase() :
			_Base::ObjectBase()
		{}

		/**
		 * @brief Construct a new PKeyBase object that borrows the C object.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is only available for borrowers.
		 * @param ptr pointer to the borrowed C object.
		 */
		template<typename _dummy_ObjTrait = PKObjTrait,
			enable_if_t<_dummy_ObjTrait::sk_isBorrower, int> = 0>
		PKeyBase(mbedtls_pk_context* ptr) noexcept :
			_Base::ObjectBase(ptr)
		{}

		/**
		 * @brief Construct a PKeyBase object (private part) from a given PEM string.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is not available for borrowers.
		 * @param pem PEM string in SecretString.
		 */
		template<typename _dummy_PKTrait = PKObjTrait,
			enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		PKeyBase(const SecretString& pem) :
			PKeyBase()
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::PKeyBase, mbedtls_pk_parse_key, Get(),
				reinterpret_cast<const unsigned char*>(pem.c_str()), pem.size() + 1, nullptr, 0);
		}

		/**
		 * @brief Construct a PKeyBase object (public part) from a given PEM string.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is not available for borrowers.
		 * @param pem PEM string in std::string
		 */
		template<typename _dummy_PKTrait = PKObjTrait,
			enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		PKeyBase(const std::string& pem) :
			PKeyBase()
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::PKeyBase, mbedtls_pk_parse_public_key, Get(),
				reinterpret_cast<const unsigned char*>(pem.c_str()), pem.size() + 1);
		}

		/**
		 * @brief Construct a PKeyBase object (private part) from a given DER bytes.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is not available for borrowers.
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _dummy_PKTrait = PKObjTrait,
			typename ContainerType,
			enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		PKeyBase(const ContCtnReadOnlyRef<ContainerType, true>& der) :
			PKeyBase()
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::PKeyBase, mbedtls_pk_parse_key, Get(),
				static_cast<const unsigned char*>(der.BeginPtr()), der.GetRegionSize(), nullptr, 0);
		}

		/**
		 * @brief Construct a PKeyBase object (public part) from a given DER bytes.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is not available for borrowers.
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _dummy_PKTrait = PKObjTrait,
			typename ContainerType,
			enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		PKeyBase(const ContCtnReadOnlyRef<ContainerType, false>& der) :
			PKeyBase()
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::PKeyBase, mbedtls_pk_parse_public_key, Get(),
				static_cast<const unsigned char*>(der.BeginPtr()), der.GetRegionSize());
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other PKeyBase instance.
		 */
		PKeyBase(PKeyBase&& rhs) noexcept :
			_Base::ObjectBase(std::forward<_Base>(rhs)) //noexcept
		{}

		PKeyBase(const PKeyBase& rhs) = delete;

		virtual ~PKeyBase()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other PKeyBase instance.
		 * @return PKeyBase& A reference to this instance.
		 */
		PKeyBase& operator=(PKeyBase&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
		}

		PKeyBase& operator=(const PKeyBase& other) = delete;

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
			_Base::NullCheck(typeid(PKeyBase).name());
		}

		using _Base::NullCheck;
		using _Base::Get;
		using _Base::Swap;

		/**
		 * @brief	Gets PKey algorithm categories. For now, it could be EC, or RSA.
		 *
		 * @return	The enum value represents the PKey algorithm category.
		 */
		virtual PKeyAlgmCat GetAlgmCat() const
		{
			NullCheck();
			return GetAlgmCat(*Get());
		}

		/**
		 * @brief	Gets PKey type (either public or private).
		 *
		 * @return	The asymmetric key type.
		 */
		virtual PKeyType GetKeyType() const
		{
			NullCheck();
			return GetKeyType(*Get());
		}

		/**
		 * @brief Check if this PKey context has public part.
		 *
		 * @return true if it has, otherwise, false.
		 */
		virtual bool HasPubKey() const
		{
			NullCheck();
			switch (GetAlgmCat())
			{
			case PKeyAlgmCat::EC:
			{
				const mbedtls_ecp_keypair* subCtx = mbedtls_pk_ec(*Get());
				return HasPubKey(*subCtx);
			}
			case PKeyAlgmCat::RSA:
			default:
			{
				const mbedtls_rsa_context* subCtx = mbedtls_pk_rsa(*Get());
				return HasPubKey(*subCtx);
			}
			}
		}

		/**
		 * @brief Check if this PKey context has private part.
		 *
		 * @return true if it has, otherwise, false.
		 */
		virtual bool HasPrvKey() const
		{
			NullCheck();
			switch (GetAlgmCat())
			{
			case PKeyAlgmCat::EC:
			{
				const mbedtls_ecp_keypair* subCtx = mbedtls_pk_ec(*Get());
				return HasPrvKey(*subCtx);
			}
			case PKeyAlgmCat::RSA:
			default:
			{
				const mbedtls_rsa_context* subCtx = mbedtls_pk_rsa(*Get());
				return HasPrvKey(*subCtx);
			}
			}
		}

		std::vector<uint8_t> GetPublicDer() const
		{
			size_t bufSize = EstPublicDerSize();

			std::vector<uint8_t> der(bufSize);

			int len = mbedtls_pk_write_pubkey_der(const_cast<mbedtls_pk_context*>(Get()), der.data(), der.size());
			if (len < 0)
			{
				throw mbedTLSRuntimeError(len,
					mbedTLSRuntimeError::ConstructWhatMsg(len, "PKeyBase::GetPublicDer", "mbedtls_pk_write_pubkey_der"));
			}

			der.erase(der.begin(), der.begin() + (der.size() - len));

			return der;
		}

		SecretVector<uint8_t> GetPrivateDer() const
		{
			size_t bufSize = EstPrivateDerSize();

			SecretVector<uint8_t> der(bufSize);

			int len = mbedtls_pk_write_key_der(const_cast<mbedtls_pk_context*>(Get()), der.data(), der.size());
			if (len < 0)
			{
				throw mbedTLSRuntimeError(len,
					mbedTLSRuntimeError::ConstructWhatMsg(len, "PKeyBase::GetPrivateDer", "mbedtls_pk_write_key_der"));
			}

			der.erase(der.begin(), der.begin() + (der.size() - len));

			return der;
		}

		std::string GetPublicPem() const
		{
			std::vector<uint8_t> der = GetPublicDer();

			size_t pemLen = Internal::CalcPemBytes(der.size(), Internal::PEM_PUBLIC_HEADER_SIZE, Internal::PEM_PUBLIC_FOOTER_SIZE);
			std::string pem(pemLen, '\0');

			size_t olen = 0;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::GetPublicPem, mbedtls_pem_write_buffer,
				Internal::PEM_BEGIN_PUBLIC_KEY, Internal::PEM_END_PUBLIC_KEY,
				der.data(), der.size(),
				reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

			pem.resize(olen);

			for (; pem.size() > 0 && pem.back() == '\0'; pem.pop_back());

			return pem;
		}

		SecretString GetPrivatePem() const
		{
			SecretVector<uint8_t> der = GetPrivateDer();
			const char *header = nullptr, *footer = nullptr;
			size_t headerSize = 0, footerSize = 0;

#if defined(MBEDTLS_RSA_C)
			if (mbedtls_pk_get_type(Get()) == MBEDTLS_PK_RSA)
			{
				header = Internal::PEM_BEGIN_PRIVATE_KEY_RSA;
				footer = Internal::PEM_END_PRIVATE_KEY_RSA;
				headerSize = Internal::PEM_RSA_PRIVATE_HEADER_SIZE;
				footerSize = Internal::PEM_RSA_PRIVATE_FOOTER_SIZE;
			}
			else
#endif
#if defined(MBEDTLS_ECP_C)
			if (mbedtls_pk_get_type(Get()) == MBEDTLS_PK_ECKEY)
			{
				header = Internal::PEM_BEGIN_PRIVATE_KEY_EC;
				footer = Internal::PEM_END_PRIVATE_KEY_EC;
				headerSize = Internal::PEM_EC_PRIVATE_HEADER_SIZE;
				footerSize = Internal::PEM_EC_PRIVATE_FOOTER_SIZE;
			}
			else
#endif
				throw InvalidArgumentException("PKeyBase::GetPrivatePem - Invalid PKey type is given.");

			size_t pemLen = Internal::CalcPemBytes(der.size(), headerSize, footerSize);
			SecretString pem(pemLen, '\0');

			size_t olen = 0;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::GetPublicPem, mbedtls_pem_write_buffer,
				header, footer,
				der.data(), der.size(),
				reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

			pem.resize(olen);

			for (; pem.size() > 0 && pem.back() == '\0'; pem.pop_back());

			return pem;
		}

		template<HashType _HashTypeVal,
			typename _SignCtnType, bool _SignCtnSecrecy>
		void VerifyDerSign(const Hash<_HashTypeVal>& hash,
			const ContCtnReadOnlyRef<_SignCtnType, _SignCtnSecrecy>& sign) const
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::VerifyDerSign, mbedtls_pk_verify,
				_Base::MutableGet(), GetMbedTlsMdType(_HashTypeVal),
				hash.data(), hash.size(),
				sign.BeginBytePtr(), sign.GetRegionSize());
		}

		template<typename _HashCtnType, bool _HashCtnSecrecy,
			typename _SignCtnType, bool _SignCtnSecrecy>
		void VerifyDerSign(HashType hashType,
			const ContCtnReadOnlyRef<_HashCtnType, _HashCtnSecrecy>& hash,
			const ContCtnReadOnlyRef<_SignCtnType, _SignCtnSecrecy>& sign) const
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::VerifyDerSign, mbedtls_pk_verify,
				_Base::MutableGet(), GetMbedTlsMdType(hashType),
				hash.BeginBytePtr(), hash.GetRegionSize(),
				sign.BeginBytePtr(), sign.GetRegionSize());
		}

		template<typename _HashCtnType>
		std::vector<uint8_t> DerSign(HashType hashType,
			const ContCtnReadOnlyRef<_HashCtnType>& hash,
			std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) const
		{
			NullCheck();

			size_t olen = 0;
			std::vector<uint8_t> der(Internal::pk_write_sign_der_est_max_size(*Get(), GetHashByteSize(hashType)));
			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::DerSign, mbedtls_pk_sign,
				_Base::MutableGet(), GetMbedTlsMdType(hashType),
				hash.BeginBytePtr(), hash.GetRegionSize(),
				der.data(), &olen,
				&RbgInterface::CallBack, rand.get());

			der.resize(olen);

			return der;
		}

		template<HashType _HashTypeVal>
		std::vector<uint8_t> DerSign(const Hash<_HashTypeVal>& hash,
			std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) const
		{
			NullCheck();

			size_t olen = 0;
			std::vector<uint8_t> der(Internal::pk_write_sign_der_est_max_size(*Get(), GetHashByteSize(_HashTypeVal)));
			MBEDTLSCPP_MAKE_C_FUNC_CALL(PKeyBase::DerSign, mbedtls_pk_sign,
				_Base::MutableGet(), GetMbedTlsMdType(_HashTypeVal),
				hash.data(), hash.size(),
				der.data(), &olen,
				&RbgInterface::CallBack, rand.get());

			der.resize(olen);

			return der;
		}

	protected:

		virtual size_t EstPublicDerSize() const
		{
			NullCheck();
			return Internal::pk_write_pubkey_der_est_size(*Get());
		}

		virtual size_t EstPrivateDerSize() const
		{
			NullCheck();
			return Internal::pk_write_prvkey_der_est_size(*Get());
		}
	};
}
