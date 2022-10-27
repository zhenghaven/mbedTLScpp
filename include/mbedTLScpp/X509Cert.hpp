#pragma once

#include "ObjectBase.hpp"

#include <map>

#include <mbedtls/x509_crt.h>
#include <mbedtls/pem.h>

#include "Common.hpp"
#include "Exceptions.hpp"
#include "Container.hpp"
#include "Hash.hpp"
#include "DefaultRbg.hpp"
#include "RandInterfaces.hpp"
#include "PKey.hpp"
#include "BigNumber.hpp"
#include "X509Crl.hpp"

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
	struct X509CertWtrObjAllocator : DefaultAllocBase
	{
		typedef mbedtls_x509write_cert      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_x509write_crt_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_x509write_crt_free(ptr);
		}
	};

	/**
	 * @brief X509 certificate request writer object trait.
	 *
	 */
	using DefaultX509CertWtrObjTrait = ObjTraitBase<X509CertWtrObjAllocator,
											 false,
											 false>;


	/**
	 * @brief X509 certificate request object allocator.
	 *
	 */
	struct X509CertObjAllocator : DefaultAllocBase
	{
		typedef mbedtls_x509_crt      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_x509_crt_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_x509_crt_free(ptr);
		}
	};

	/**
	 * @brief X509 certificate request object trait.
	 *
	 */
	using DefaultX509CertObjTrait = ObjTraitBase<X509CertObjAllocator,
											 false,
											 false>;

	/**
	 * @brief Borrower X509 Certificate object trait.
	 *
	 */
	using BorrowedX509CertTrait =
		ObjTraitBase<BorrowAllocBase<mbedtls_x509_crt>,
									true,
									false>;

	template<typename _X509CertObjTrait,
		enable_if_t<std::is_same<typename _X509CertObjTrait::CObjType, mbedtls_x509_crt>::value, int> >
	class X509CertBase;

	class X509CertWriter : public ObjectBase<DefaultX509CertWtrObjTrait>
	{
	public: // Static members:

		using X509CertWtrTrait = DefaultX509CertWtrObjTrait;
		using _Base           = ObjectBase<X509CertWtrTrait>;

		template<typename _PKObjTrait>
		static X509CertWriter SelfSign(HashType hashType, const PKeyBase<_PKObjTrait> & prvKey, const std::string & subjName)
		{
			prvKey.NullCheck();

			X509CertWriter wrt;

			mbedtls_x509write_crt_set_version(wrt.Get(), MBEDTLS_X509_CRT_VERSION_3);

			mbedtls_x509write_crt_set_md_alg(wrt.Get(), GetMbedTlsMdType(hashType));

			mbedtls_x509write_crt_set_issuer_key(wrt.Get(), prvKey.MutableGet());
			mbedtls_x509write_crt_set_subject_key(wrt.Get(), prvKey.MutableGet());

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				X509CertWriter::SelfSign,
				mbedtls_x509write_crt_set_subject_name,
				wrt.Get(), subjName.c_str());

			Internal::Asn1DeepCopy(wrt.Get()->issuer, wrt.Get()->subject);

			return wrt;
		}

		template<typename _CaCertObjTrait,
			typename _CaPKObjTrait,
			typename _SubPKObjTrait>
		static X509CertWriter CaSign(HashType hashType,
				const X509CertBase<_CaCertObjTrait, 0> & caCert,
				const PKeyBase<_CaPKObjTrait> & caKey,
				const PKeyBase<_SubPKObjTrait> & subjKey,
				const std::string & subjName);

	public:

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other X509CertWriter instance.
		 */
		X509CertWriter(X509CertWriter&& rhs) noexcept :
			_Base::ObjectBase(std::forward<_Base>(rhs)) //noexcept
		{}

		X509CertWriter(const X509CertWriter& rhs) = delete;

		// LCOV_EXCL_START
		virtual ~X509CertWriter() = default;
		// LCOV_EXCL_STOP

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other X509CertWriter instance.
		 * @return X509CertWriter& A reference to this instance.
		 */
		X509CertWriter& operator=(X509CertWriter&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
		}

		X509CertWriter& operator=(const X509CertWriter& other) = delete;

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
			_Base::NullCheck(MBEDTLSCPP_CLASS_NAME_STR(X509CertWriter));
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

			size_t bufSize = Internal::x509write_crt_der_est_size(*Get());

			std::vector<uint8_t> der(bufSize);

			int len = mbedtls_x509write_crt_der(Get(), der.data(), der.size(), &RbgInterface::CallBack, rand.get());
			if (len < 0)
			{
				throw mbedTLSRuntimeError(len,
					mbedTLSRuntimeError::ConstructWhatMsg(len, "X509CertWriter::GetDer", "mbedtls_x509write_crt_der"));
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

			size_t pemLen = Internal::CalcPemBytes(der.size(), Internal::PEM_CRT_HEADER_SIZE, Internal::PEM_CRT_FOOTER_SIZE);
			std::string pem(pemLen, '\0');

			size_t olen = 0;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509CertWriter::GetPem, mbedtls_pem_write_buffer,
				Internal::PEM_BEGIN_CRT, Internal::PEM_END_CRT,
				der.data(), der.size(),
				reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

			pem.resize(olen);

			for (; pem.size() > 0 && pem.back() == '\0'; pem.pop_back());

			return pem;
		}

		template<typename _BigNumTrait>
		X509CertWriter& SetSerialNum(const BigNumberBase<_BigNumTrait> & serialNum)
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509CertWriter::SetSerialNum,
				mbedtls_x509write_crt_set_serial, Get(), serialNum.Get());

			return *this;
		}

		X509CertWriter& SetValidationTime(const std::string & validSince, const std::string & expireAfter)
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509CertWriter::SetValidationTime,
				mbedtls_x509write_crt_set_validity, Get(), validSince.c_str(), expireAfter.c_str());

			return *this;
		}

		X509CertWriter& SetBasicConstraints(bool isCa, int maxChainDepth)
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509CertWriter::SetBasicConstraints,
				mbedtls_x509write_crt_set_basic_constraints, Get(), isCa, maxChainDepth);

			return *this;
		}

		X509CertWriter& SetKeyUsage(unsigned int keyUsage)
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509CertWriter::SetKeyUsage,
				mbedtls_x509write_crt_set_key_usage, Get(), keyUsage);

			return *this;
		}

		X509CertWriter& SetNsType(unsigned char nsType)
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509CertWriter::SetNsType,
				mbedtls_x509write_crt_set_ns_cert_type, Get(), nsType);

			return *this;
		}

		X509CertWriter& SetV3Extensions(const std::map<std::string, std::pair<bool, std::string> >& v3ExtMap)
		{
			for (const auto& item : v3ExtMap)
			{
				MBEDTLSCPP_MAKE_C_FUNC_CALL(X509CertWriter::SetV3Extensions,
					mbedtls_x509write_crt_set_extension,
					Get(),
					item.first.data(), item.first.size(), // OID
					item.second.first,                    // Is critical?
					reinterpret_cast<const uint8_t*>(item.second.second.data()), item.second.second.size() // Data
				);
			}

			return *this;
		}

	protected:
		X509CertWriter() :
			_Base::ObjectBase()
		{}
	};

	static_assert(IsCppObjOfCtype<X509CertWriter, mbedtls_x509write_cert>::value == true, "Programming Error");





	template<typename _X509CertObjTrait = DefaultX509CertObjTrait,
			 enable_if_t<std::is_same<typename _X509CertObjTrait::CObjType, mbedtls_x509_crt>::value, int> = 0>
	class X509CertBase : public ObjectBase<_X509CertObjTrait>
	{
	public: // Static members:

		using X509CertTrait = _X509CertObjTrait;
		using _Base         = ObjectBase<X509CertTrait>;

		friend class TlsConfig;

		/**
		 * @brief Construct a X509 certificate (chain) from a given PEM string.
		 *
		 * @param pem PEM string in std::string
		 */
		static X509CertBase<DefaultX509CertObjTrait> FromPEM(const std::string& pem)
		{
			X509CertBase<DefaultX509CertObjTrait> cert;
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509CertBase::FromPEM,
				mbedtls_x509_crt_parse,
				cert.Get(),
				reinterpret_cast<const uint8_t*>(pem.c_str()), pem.size() + 1);
			return cert;
		}

		/**
		 * @brief Construct a X509 certificate from a given DER bytes.
		 *
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _SecCtnType>
		static X509CertBase<DefaultX509CertObjTrait>
			FromDER(const ContCtnReadOnlyRef<_SecCtnType, false>& der)
		{
			X509CertBase<DefaultX509CertObjTrait> cert;
			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Cert::FromDER,
				mbedtls_x509_crt_parse,
				cert.Get(),
				der.BeginBytePtr(), der.GetRegionSize());
			return cert;
		}

		/**
		 * @brief Defines an alias representing the VerifyFunc used for
		 *        certificate chain verification.
		 */
		typedef int(*VerifyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *);

		static std::vector<uint8_t> GetDer(
			typename std::add_lvalue_reference<
				typename std::add_const<
					typename _Base::CObjType>::type>::type cert)
		{
			return std::vector<uint8_t>(cert.raw.p, cert.raw.p + cert.raw.len);
		}

		static std::string GetPem(
			typename std::add_lvalue_reference<
				typename std::add_const<
					typename _Base::CObjType>::type>::type cert)
		{
			size_t pemLen = Internal::CalcPemBytes(cert.raw.len, Internal::PEM_CRT_HEADER_SIZE, Internal::PEM_CRT_FOOTER_SIZE);
			std::string pem(pemLen, '\0');

			size_t olen = 0;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(X509Req::GetPem, mbedtls_pem_write_buffer,
				Internal::PEM_BEGIN_CRT, Internal::PEM_END_CRT,
				cert.raw.p, cert.raw.len,
				reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen);

			pem.resize(olen);

			for (; pem.size() > 0 && pem.back() == '\0'; pem.pop_back());

			return pem;
		}

	public:

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception Unclear Depends on \c std::vector .
		 * @param rhs The other X509CertBase instance.
		 */
		X509CertBase(X509CertBase&& rhs) :
			_Base::ObjectBase(std::forward<_Base>(rhs)), //noexcept
			m_certStack(std::move(rhs.m_certStack)),
			m_currPtr(rhs.m_currPtr)
		{
			rhs.m_currPtr = nullptr;
		}

		/**
		 * @brief Construct a new X509CertBase object that borrows the C object.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is only available for borrowers.
		 * @param ptr pointer to the borrowed C object.
		 */
		template<typename _dummy_ObjTrait = X509CertTrait,
			enable_if_t<_dummy_ObjTrait::sk_isBorrower, int> = 0>
		X509CertBase(mbedtls_x509_crt* ptr) :
			_Base::ObjectBase(ptr),
			m_certStack(1, NonVirtualGet()),
			m_currPtr(NonVirtualGet())
		{}

		X509CertBase(const X509CertBase& rhs) = delete;

		// LCOV_EXCL_START
		virtual ~X509CertBase() = default;
		// LCOV_EXCL_STOP

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @exception Unclear Depends on \c std::vector .
		 * @param rhs The other X509CertBase instance.
		 * @return X509CertBase& A reference to this instance.
		 */
		X509CertBase& operator=(X509CertBase&& rhs)
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			if(this != &rhs)
			{
				m_certStack = std::move(rhs.m_certStack);
				m_currPtr = rhs.m_currPtr;

				rhs.m_currPtr = nullptr;
			}

			return *this;
		}

		X509CertBase& operator=(const X509CertBase& other) = delete;

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
			_Base::NullCheck(MBEDTLSCPP_CLASS_NAME_STR(X509CertBase));
		}

		virtual bool IsNull() const noexcept override
		{
			return _Base::IsNull() || (m_currPtr == nullptr);
		}

		using _Base::NullCheck;
		using _Base::Get;
		using _Base::NonVirtualGet;
		using _Base::Swap;

		/**
		 * @brief	Gets the pointer to the current certificate in the chain.
		 *
		 * @exception None No exception thrown
		 * @return	The pointer to the current certificate.
		 */
		const typename _Base::CObjType* GetCurr() const noexcept
		{
			return m_currPtr;
		}

		/**
		 * @brief	Gets the pointer to the current certificate in the chain.
		 *
		 * @exception None No exception thrown
		 * @return	The pointer to the current certificate.
		 */
		typename _Base::CObjType* GetCurr() noexcept
		{
			return m_currPtr;
		}

		bool HasNext() const
		{
			NullCheck();
			return HasNextNoCheck();
		}

		void NextCert()
		{
			if (HasNext())
			{
				NextCertNoCheck();
			}
			else
			{
				throw RuntimeException("There is no next certificate in the chain.");
			}
		}

		void PrevCert()
		{
			if (m_certStack.size() > 1)
			{
				m_certStack.pop_back();
				m_currPtr = m_certStack.back();
			}
			else
			{
				throw RuntimeException("There is no previous certificate in the chain.");
			}
		}

		void GoToFirstCert()
		{
			m_certStack.resize(1);
			m_currPtr = m_certStack.back();
		}

		void GoToLastCert()
		{
			NullCheck();

			while (HasNextNoCheck())
			{
				NextCertNoCheck();
			}
		}

		std::vector<uint8_t> GetDer() const
		{
			NullCheck();

			return GetDer(*m_currPtr);
		}

		std::string GetPem() const
		{
			NullCheck();

			return GetPem(*m_currPtr);
		}

		template<typename _PKeyType = PKeyBase<BorrowedPKeyTrait>,
			typename _dummy_CertTrait = X509CertTrait,
			enable_if_t<!_dummy_CertTrait::sk_isConst, int> = 0,
			enable_if_t<IsCppObjOfCtype<_PKeyType, mbedtls_pk_context>::value, int> = 0>
		_PKeyType BorrowPublicKey()
		{
			NullCheck();

			return _PKeyType(&m_currPtr->pk);
		}

		template<typename _PKeyType = PKeyBase<BorrowedPKeyTrait>,
			enable_if_t<IsCppObjOfCtype<_PKeyType, mbedtls_pk_context>::value, int> = 0>
		const _PKeyType BorrowPublicKey() const
		{
			NullCheck();

			return _PKeyType(&m_currPtr->pk);
		}

		template<typename _PKeyType = PKeyBase<>,
			enable_if_t<IsCppObjOfCtype<_PKeyType, mbedtls_pk_context>::value, int> = 0>
		_PKeyType GetPublicKey() const
		{
			std::vector<uint8_t> pubDer = BorrowPublicKey().GetPublicDer();

			return _PKeyType::FromDER(CtnFullR(pubDer));
		}

		HashType GetHashType() const
		{
			NullCheck();

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
			return mbedTLScpp::GetHashType(m_currPtr->sig_md);
#else
			return MBEDTLSCPP_CUSTOMIZED_NAMESPACE::GetHashType(m_currPtr->sig_md);
#endif
		}

		std::string GetPemChain() const
		{
			NullCheck();

			std::string pemChain;

			const mbedtls_x509_crt* curr = NonVirtualGet();

			while (curr != nullptr)
			{
				pemChain += GetPem(*curr);
				curr = curr->next;
			}

			return pemChain;
		}

		std::string GetCommonName() const
		{
			NullCheck();

			const mbedtls_asn1_named_data& cnData =
				Internal::Asn1GetNamedDataFromList(&m_currPtr->subject, MBEDTLS_OID_AT_CN);

			return std::string(reinterpret_cast<const char*>(cnData.val.p),
				cnData.val.len);
		}

		template<typename _PKObjTrait>
		void VerifySignature(const PKeyBase<_PKObjTrait> & pubKey) const
		{
			NullCheck();
			pubKey.NullCheck();

			auto mdInfo = mbedtls_md_info_from_type(m_currPtr->sig_md);

			size_t hashLen = mbedtls_md_get_size(mdInfo);

			std::unique_ptr<uint8_t[]> hash = Internal::make_unique<uint8_t[]>(hashLen);

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				X509CertBase::VerifySignature,
				mbedtls_md, mdInfo, m_currPtr->tbs.p, m_currPtr->tbs.len, hash.get());

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				X509CertBase::VerifySignature,
				mbedtls_pk_verify_ext, m_currPtr->sig_pk, m_currPtr->sig_opts, pubKey.MutableGet(),
				m_currPtr->sig_md, hash.get(), hashLen, m_currPtr->sig.p, m_currPtr->sig.len);
		}

		void VerifySignature() const
		{
			NullCheck();

			auto mdInfo = mbedtls_md_info_from_type(m_currPtr->sig_md);

			size_t hashLen = mbedtls_md_get_size(mdInfo);

			std::unique_ptr<uint8_t[]> hash = Internal::make_unique<uint8_t[]>(hashLen);

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				X509CertBase::VerifySignature,
				mbedtls_md, mdInfo, m_currPtr->tbs.p, m_currPtr->tbs.len, hash.get());

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				X509CertBase::VerifySignature,
				mbedtls_pk_verify_ext, m_currPtr->sig_pk, m_currPtr->sig_opts, &m_currPtr->pk,
				m_currPtr->sig_md, hash.get(), hashLen, m_currPtr->sig.p, m_currPtr->sig.len);
		}

		std::map<std::string, std::pair<bool, std::string> > GetV3Extensions() const
		{
			NullCheck();

			std::map<std::string, std::pair<bool, std::string> > extMap;

			int mbedRet = 0;
			int is_critical = 0;
			size_t len = 0;

			unsigned char *end_ext_data = nullptr;
			unsigned char *end_ext_octet = nullptr;

			unsigned char *begin = m_currPtr->v3_ext.p;
			const unsigned char *end = m_currPtr->v3_ext.p + m_currPtr->v3_ext.len;

			unsigned char **p = &begin;

			char* oidPtr = nullptr;
			size_t oidSize = 0;

			char* extDataPtr = nullptr;
			size_t extDataSize = 0;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				X509CertBase::GetV3Extensions,
				mbedtls_asn1_get_tag, p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
			if (*p + len != end)
			{
				throw RuntimeException("mbedTLScpp::X509CertBase::GetV3Extensions - Invalid length returned by ASN1.");
			}

			while (*p < end)
			{
				is_critical = 0; /* DEFAULT FALSE */

				MBEDTLSCPP_MAKE_C_FUNC_CALL(
					X509CertBase::GetV3Extensions,
					mbedtls_asn1_get_tag, p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

				end_ext_data = *p + len;

				/* Get extension ID */
				MBEDTLSCPP_MAKE_C_FUNC_CALL(
					X509CertBase::GetV3Extensions,
					mbedtls_asn1_get_tag, p, end_ext_data, &len, MBEDTLS_ASN1_OID);

				oidPtr = reinterpret_cast<char*>(*p);
				oidSize = len;

				*p += len;

				/* Get optional critical */
				mbedRet = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical);
				if (mbedRet != MBEDTLS_EXIT_SUCCESS && mbedRet != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
				{
					throw RuntimeException("mbedTLScpp::X509CertBase::GetV3Extensions - Invalid tag returned by ASN1.");
				}

				/* Data should be octet string type */
				MBEDTLSCPP_MAKE_C_FUNC_CALL(
					X509CertBase::GetV3Extensions,
					mbedtls_asn1_get_tag, p, end_ext_data, &len, MBEDTLS_ASN1_OCTET_STRING);

				extDataPtr = reinterpret_cast<char*>(*p);
				extDataSize = len;

				end_ext_octet = *p + len;

				if (end_ext_octet != end_ext_data)
				{
					throw RuntimeException("mbedTLScpp::X509CertBase::GetV3Extensions - Invalid length returned by ASN1.");
				}

				//Insert into the map.
				extMap.insert(
					std::make_pair(std::string(oidPtr, oidSize),
						std::make_pair(is_critical != 0, std::string(extDataPtr, extDataSize))));

				*p = end_ext_octet;
			}

			return extMap;
		}

		std::pair<bool, std::string> GetV3Extension(const std::string & oid) const
		{
			NullCheck();

			int mbedRet = 0;
			int is_critical = 0;
			size_t len = 0;

			unsigned char *end_ext_data = nullptr;
			unsigned char *end_ext_octet = nullptr;

			unsigned char *begin = m_currPtr->v3_ext.p;
			const unsigned char *end = m_currPtr->v3_ext.p + m_currPtr->v3_ext.len;

			unsigned char **p = &begin;

			char* oidPtr = nullptr;
			size_t oidSize = 0;

			char* extDataPtr = nullptr;
			size_t extDataSize = 0;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				X509CertBase::GetV3Extension,
				mbedtls_asn1_get_tag, p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
			if (*p + len != end)
			{
				throw RuntimeException("mbedTLScpp::X509CertBase::GetV3Extension - Invalid length returned by ASN1.");
			}

			while (*p < end)
			{
				is_critical = 0; /* DEFAULT FALSE */

				MBEDTLSCPP_MAKE_C_FUNC_CALL(
					X509CertBase::GetV3Extension,
					mbedtls_asn1_get_tag, p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

				end_ext_data = *p + len;

				/* Get extension ID */
				MBEDTLSCPP_MAKE_C_FUNC_CALL(
					X509CertBase::GetV3Extension,
					mbedtls_asn1_get_tag, p, end_ext_data, &len, MBEDTLS_ASN1_OID);

				oidPtr = reinterpret_cast<char*>(*p);
				oidSize = len;

				if (oidSize == oid.size() &&
					std::memcmp(oidPtr, oid.c_str(), oid.size()) == 0)
				{
					// The extension with given OID is found.

					*p += len;

					/* Get optional critical */
					mbedRet = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical);
					if (mbedRet != MBEDTLS_EXIT_SUCCESS && mbedRet != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
					{
						throw RuntimeException("mbedTLScpp::X509CertBase::GetV3Extension - Invalid tag returned by ASN1.");
					}

					/* Data should be octet string type */
					MBEDTLSCPP_MAKE_C_FUNC_CALL(
						X509CertBase::GetV3Extension,
						mbedtls_asn1_get_tag, p, end_ext_data, &len, MBEDTLS_ASN1_OCTET_STRING);

					extDataPtr = reinterpret_cast<char*>(*p);
					extDataSize = len;

					end_ext_octet = *p + len;

					if (end_ext_octet != end_ext_data)
					{
						throw RuntimeException("mbedTLScpp::X509CertBase::GetV3Extension - Invalid length returned by ASN1.");
					}

					return std::make_pair(is_critical != 0, std::string(extDataPtr, extDataSize));
				}

				*p = end_ext_data;
			}

			throw RuntimeException("The given OID is not found in the extension list.");
		}

		template<typename _CaObjTrait>
		void VerifyChainWithCa(
			const X509CertBase<_CaObjTrait> & ca,
			const X509Crl* crl,
			const char * cn, uint32_t & flags,
			const mbedtls_x509_crt_profile & prof,
			VerifyFunc vrfyFunc, void * vrfyParam) const
		{
			NullCheck();
			mbedtls_x509_crl* crlPtr = nullptr;

			if(crl != nullptr)
			{
				crl->NullCheck();
				crlPtr = crl->MutableGet();
			}

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				X509CertBase::VerifyChainWithCa,
				mbedtls_x509_crt_verify_with_profile,
				MutableGet(), ca.MutableGet(),
				crlPtr,
				&prof, cn, &flags,
				vrfyFunc, vrfyParam);
		}

		template<typename _CaObjTrait,
			typename _dummy_CertTrait = X509CertTrait,
			enable_if_t<!_dummy_CertTrait::sk_isConst, int> = 0>
		void ShrinkChain(const X509CertBase<_CaObjTrait> & ca)
		{
			NullCheck();
			ca.NullCheck();

			mbedtls_x509_crt* prev = nullptr;
			mbedtls_x509_crt* curr = NonVirtualGet();

			bool found = false;

			while (curr != nullptr)
			{
				const mbedtls_x509_crt* currCa = ca.Get();
				while (currCa != nullptr && !found)
				{
					if (curr->raw.len == currCa->raw.len &&
						std::memcmp(curr->raw.p, currCa->raw.p, currCa->raw.len) == 0)
					{
						// Found
						found = true;
					}

					currCa = currCa->next;
				}

				if (found)
				{
					// The current one is duplicated. Free it.

					mbedtls_x509_crt* toBeFree = curr;

					if (prev == nullptr)
					{
						// This is the first one on chain.

						SetPtr(curr->next);
						m_certStack[0] = curr->next;
						curr->next = nullptr;

						// Set the current to the next one, so the search can continue.
						curr = NonVirtualGet();
					}
					else
					{
						prev->next = curr->next;
						curr->next = nullptr;

						// Set the current to the next one, so the search can continue.
						curr = prev->next;
					}

					mbedtls_x509_crt_free(toBeFree);
					found = false;
				}
				else
				{
					prev = curr;
					curr = curr->next;
				}
			}

			GoToFirstCert();
		}

	protected:

		using _Base::MutableGet;
		using _Base::SetPtr;

		template<typename _dummy_CertTrait = X509CertTrait,
			enable_if_t<!_dummy_CertTrait::sk_isBorrower, int> = 0>
		X509CertBase() :
			_Base::ObjectBase(),
			m_certStack(1, NonVirtualGet()),
			m_currPtr(NonVirtualGet())
		{}

		bool HasNextNoCheck() const noexcept
		{
			return m_currPtr->next != nullptr;
		}

		void NextCertNoCheck()
		{
			m_certStack.push_back(m_currPtr->next);
			m_currPtr = m_currPtr->next;
		}

	private:
		std::vector<typename std::add_pointer<typename _Base::CObjType>::type> m_certStack;
		typename std::add_pointer<typename _Base::CObjType>::type m_currPtr; // For noexcept
	};

	using X509Cert = X509CertBase<>;

	template<typename _CaCertObjTrait,
		typename _CaPKObjTrait,
		typename _SubPKObjTrait>
	inline X509CertWriter X509CertWriter::CaSign(
			HashType hashType,
			const X509CertBase<_CaCertObjTrait> & caCert,
			const PKeyBase<_CaPKObjTrait> & caKey,
			const PKeyBase<_SubPKObjTrait> & subjKey,
			const std::string & subjName)
	{
		caCert.NullCheck();
		caKey.NullCheck();
		subjKey.NullCheck();

		X509CertWriter wrt;

		mbedtls_x509write_crt_set_version(wrt.Get(), MBEDTLS_X509_CRT_VERSION_3);

		mbedtls_x509write_crt_set_md_alg(wrt.Get(), GetMbedTlsMdType(hashType));

		mbedtls_x509write_crt_set_issuer_key(wrt.Get(), caKey.MutableGet());
		mbedtls_x509write_crt_set_subject_key(wrt.Get(), subjKey.MutableGet());

		MBEDTLSCPP_MAKE_C_FUNC_CALL(
			X509CertWriter::CaSign,
			mbedtls_x509write_crt_set_subject_name,
			wrt.Get(), subjName.c_str());

		Internal::Asn1DeepCopy(wrt.Get()->issuer, &caCert.Get()->subject);
		Internal::Asn1ReverseNamedDataList(wrt.Get()->issuer);

		return wrt;
	}
}
