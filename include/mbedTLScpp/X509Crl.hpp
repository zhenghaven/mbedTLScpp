#pragma once

#include "ObjectBase.hpp"

#include <mbedtls/x509_crl.h>
#include <mbedtls/pem.h>

#include "Common.hpp"
#include "Exceptions.hpp"
#include "Container.hpp"

#include "Internal/Pem.hpp"
#include "Internal/X509Helper.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief X509 certificate request object allocator.
	 *
	 */
	struct X509CrlObjAllocator : DefaultAllocBase
	{
		typedef mbedtls_x509_crl      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_x509_crl_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_x509_crl_free(ptr);
		}
	};

	/**
	 * @brief X509 certificate request object trait.
	 *
	 */
	using DefaultX509CrlObjTrait = ObjTraitBase<X509CrlObjAllocator,
											 false,
											 false>;

	class X509Crl : public ObjectBase<DefaultX509CrlObjTrait>
	{
	public: // Static members:

		using X509CrlTrait = DefaultX509CrlObjTrait;
		using _Base        = ObjectBase<X509CrlTrait>;

		friend class X509Cert;

		/**
		 * @brief Construct a X509 certificate revocation list from a given PEM string.
		 *
		 * @param pem PEM string in std::string
		 */
		static X509Crl FromPEM(const std::string& pem)
		{
			X509Crl crl;
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Crl::FromPEM,
				mbedtls_x509_crl_parse,
				crl.Get(),
				reinterpret_cast<const uint8_t*>(pem.c_str()), pem.size() + 1);
			return crl;
		}

		/**
		 * @brief Construct a X509 certificate revocation list from a given DER bytes.
		 *
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _SecCtnType>
		static X509Crl FromDER(const ContCtnReadOnlyRef<_SecCtnType, false>& der)
		{
			X509Crl crl;
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Crl::FromDER,
				mbedtls_x509_crl_parse_der,
				crl.Get(),
				der.BeginBytePtr(), der.GetRegionSize());
			return crl;
		}

	public:

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other X509Crl instance.
		 */
		X509Crl(X509Crl&& rhs) noexcept :
			_Base::ObjectBase(std::forward<_Base>(rhs)) //noexcept
		{}

		X509Crl(const X509Crl& rhs) = delete;

		virtual ~X509Crl()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other X509Crl instance.
		 * @return X509Crl& A reference to this instance.
		 */
		X509Crl& operator=(X509Crl&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
		}

		X509Crl& operator=(const X509Crl& other) = delete;

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
			_Base::NullCheck(typeid(X509Crl).name());
		}

		using _Base::NullCheck;
		using _Base::Get;
		using _Base::Swap;

		std::vector<uint8_t> GetDer() const
		{
			NullCheck();

			return std::vector<uint8_t>(Get()->raw.p, Get()->raw.p + Get()->raw.len);
		}

		std::string GetPem() const
		{
			NullCheck();

			size_t pemLen = Internal::CalcPemBytes(Get()->raw.len, Internal::PEM_CRL_HEADER_SIZE, Internal::PEM_CRL_FOOTER_SIZE);
			std::string pem(pemLen, '\0');

			size_t olen = 0;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Crl::GetPem, mbedtls_pem_write_buffer,
				Internal::PEM_BEGIN_CRL, Internal::PEM_END_CRL,
				Get()->raw.p, Get()->raw.len,
				reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

			pem.resize(olen);

			for (; pem.size() > 0 && pem.back() == '\0'; pem.pop_back());

			return pem;
		}

	protected:

		X509Crl() :
			_Base::ObjectBase()
		{}
	};
}
