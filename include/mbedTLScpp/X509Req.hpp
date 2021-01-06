#pragma once

#include "ObjectBase.hpp"

#include <mbedtls/x509_csr.h>
#include <mbedtls/pem.h>

#include "Common.hpp"
#include "Exceptions.hpp"
#include "Container.hpp"
#include "Hash.hpp"
#include "DefaultRbg.hpp"
#include "RandInterfaces.hpp"
#include "PKey.hpp"

#include "Internal/X509Helper.hpp"
#include "Internal/Pem.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief X509 certificate request writer object allocator.
	 *
	 */
	struct X509ReqWtrObjAllocator : DefaultAllocBase
	{
		typedef mbedtls_x509write_csr      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_x509write_csr_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_x509write_csr_free(ptr);
		}
	};

	/**
	 * @brief X509 certificate request writer object trait.
	 *
	 */
	using DefaultX509ReqWtrObjTrait = ObjTraitBase<X509ReqWtrObjAllocator,
											 false,
											 false>;

	class X509ReqWriter : public ObjectBase<DefaultX509ReqWtrObjTrait>
	{
	public: // Static members:

		using X509ReqWtrTrait = DefaultX509ReqWtrObjTrait;
		using _Base           = ObjectBase<X509ReqWtrTrait>;

	public:

		template<typename _PKObjTrait>
		X509ReqWriter(HashType hashType, const PKeyBase<_PKObjTrait> & keyPair, const std::string& subjName) :
			_Base::ObjectBase()
		{
			mbedtls_x509write_csr_set_key(Get(), keyPair.MutableGet());
			mbedtls_x509write_csr_set_md_alg(Get(), GetMbedTlsMdType(hashType));

			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509ReqWriter::X509ReqWriter,
				mbedtls_x509write_csr_set_subject_name, Get(), subjName.c_str());
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other PKeyBase instance.
		 */
		X509ReqWriter(X509ReqWriter&& rhs) noexcept :
			_Base::ObjectBase(std::forward<_Base>(rhs)) //noexcept
		{}

		X509ReqWriter(const X509ReqWriter& rhs) = delete;

		virtual ~X509ReqWriter()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other X509ReqWriter instance.
		 * @return X509ReqWriter& A reference to this instance.
		 */
		X509ReqWriter& operator=(X509ReqWriter&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
		}

		X509ReqWriter& operator=(const X509ReqWriter& other) = delete;

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
			_Base::NullCheck(typeid(X509ReqWriter).name());
		}

		using _Base::NullCheck;
		using _Base::Get;
		using _Base::Swap;

		/**
		 * @brief Generates a DER encoded X509 request.
		 *
		 * @param rand The Random Bit Generator.
		 *
		 * @return The DER encoded X509 request.
		 */
		std::vector<uint8_t> GetDer(std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>())
		{
			NullCheck();

			size_t bufSize = Internal::x509write_csr_der_est_size(*Get());

			std::vector<uint8_t> der(bufSize);

			int len = mbedtls_x509write_csr_der(Get(), der.data(), der.size(), &RbgInterface::CallBack, rand.get());
			if (len < 0)
			{
				throw mbedTLSRuntimeError(len,
					mbedTLSRuntimeError::ConstructWhatMsg(len, "X509ReqWriter::GetDer", "mbedtls_x509write_csr_der"));
			}

			der.erase(der.begin(), der.begin() + (der.size() - len));

			return der;
		}

		/**
		 * @brief Generates a PEM encoded X509 request.
		 *
		 * @param rand The Random Bit Generator.
		 *
		 * @return The PEM encoded X509 request.
		 */
		std::string GetPem(std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>())
		{
			std::vector<uint8_t> der = GetDer();

			size_t pemLen = Internal::CalcPemBytes(der.size(), Internal::PEM_CSR_HEADER_SIZE, Internal::PEM_CSR_FOOTER_SIZE);
			std::string pem(pemLen, '\0');

			size_t olen = 0;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509ReqWriter::GetPem, mbedtls_pem_write_buffer,
				Internal::PEM_BEGIN_CSR, Internal::PEM_END_CSR,
				der.data(), der.size(),
				reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

			pem.resize(olen);

			for (; pem.size() > 0 && pem.back() == '\0'; pem.pop_back());

			return pem;
		}
	};

	static_assert(IsCppObjOfCtype<X509ReqWriter, mbedtls_x509write_csr>::value == true, "Programming Error");




	/**
	 * @brief X509 certificate request object allocator.
	 *
	 */
	struct X509ReqObjAllocator : DefaultAllocBase
	{
		typedef mbedtls_x509_csr      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_x509_csr_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_x509_csr_free(ptr);
		}
	};

	/**
	 * @brief X509 certificate request object trait.
	 *
	 */
	using DefaultX509ReqObjTrait = ObjTraitBase<X509ReqObjAllocator,
											 false,
											 false>;

	class X509Req : public ObjectBase<DefaultX509ReqObjTrait>
	{
	public: // Static members:

		using X509ReqTrait = DefaultX509ReqObjTrait;
		using _Base        = ObjectBase<X509ReqTrait>;

		/**
		 * @brief Construct a X509 certificate request from a given PEM string.
		 *
		 * @param pem PEM string in std::string
		 */
		static X509Req FromPEM(const std::string& pem)
		{
			X509Req req;
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Req::FromPEM,
				mbedtls_x509_csr_parse,
				req.Get(),
				reinterpret_cast<const uint8_t*>(pem.c_str()), pem.size() + 1);
			return req;
		}

		/**
		 * @brief Construct a X509 certificate request from a given DER bytes.
		 *
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _SecCtnType>
		static X509Req FromDER(const ContCtnReadOnlyRef<_SecCtnType, false>& der)
		{
			X509Req req;
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Req::FromDER,
				mbedtls_x509_csr_parse,
				req.Get(),
				der.BeginBytePtr(), der.GetRegionSize());
			return req;
		}

	public:

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other X509Req instance.
		 */
		X509Req(X509Req&& rhs) noexcept :
			_Base::ObjectBase(std::forward<_Base>(rhs)) //noexcept
		{}

		X509Req(const X509Req& rhs) = delete;

		virtual ~X509Req()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other X509Req instance.
		 * @return X509Req& A reference to this instance.
		 */
		X509Req& operator=(X509Req&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
		}

		X509Req& operator=(const X509Req& other) = delete;

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
			_Base::NullCheck(typeid(X509Req).name());
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

			size_t pemLen = Internal::CalcPemBytes(Get()->raw.len, Internal::PEM_CSR_HEADER_SIZE, Internal::PEM_CSR_FOOTER_SIZE);
			std::string pem(pemLen, '\0');

			size_t olen = 0;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Req::GetPem, mbedtls_pem_write_buffer,
				Internal::PEM_BEGIN_CSR, Internal::PEM_END_CSR,
				Get()->raw.p, Get()->raw.len,
				reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

			pem.resize(olen);

			for (; pem.size() > 0 && pem.back() == '\0'; pem.pop_back());

			return pem;
		}

		PKeyBase<BorrowedPKeyTrait> BorrowPublicKey()
		{
			NullCheck();

			return PKeyBase<BorrowedPKeyTrait>(&Get()->pk);
		}

		template<typename PKeyType,
			enable_if_t<IsCppObjOfCtype<PKeyType, mbedtls_pk_context>::value, int> = 0>
		PKeyType GetPublicKey() const
		{
			NullCheck();

			PKeyBase<BorrowedPKeyTrait> borrowed(&MutableGet()->pk);
			std::vector<uint8_t> pubDer = borrowed.GetPublicDer();

			return PKeyType::FromDER(CtnFullR(pubDer));
		}

		HashType GetHashType() const
		{
			NullCheck();

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
			return mbedTLScpp::GetHashType(Get()->sig_md);
#else
			return MBEDTLSCPP_CUSTOMIZED_NAMESPACE::GetHashType(Get()->sig_md);
#endif
		}

		void VerifySignature()
		{
			NullCheck();

			const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(Get()->sig_md);
			const size_t mdSize = mbedtls_md_get_size(mdInfo);

			std::unique_ptr<uint8_t[]> tmpHash = Internal::make_unique<uint8_t[]>(mdSize);

			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Req::VerifySignature,
				mbedtls_md, mdInfo, Get()->cri.p, Get()->cri.len, tmpHash.get());
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Req::VerifySignature,
				mbedtls_pk_verify_ext, Get()->sig_pk, Get()->sig_opts, &Get()->pk,
				Get()->sig_md, tmpHash.get(), mdSize, Get()->sig.p, Get()->sig.len);
		}

	protected:

		X509Req() :
			_Base::ObjectBase()
		{}
	};
}
