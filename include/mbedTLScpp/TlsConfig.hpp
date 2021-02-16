#pragma once

#include "ObjectBase.hpp"

#include <mbedtls/ssl.h>

#include "Common.hpp"
#include "Exceptions.hpp"
#include "DefaultRbg.hpp"
#include "X509Cert.hpp"
#include "X509Crl.hpp"
#include "TlsSessTktMgrIntf.hpp"
#include "PKey.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief TLS Config object allocator.
	 *
	 */
	struct TlsConfObjAllocator : DefaultAllocBase
	{
		typedef mbedtls_ssl_config      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_ssl_config_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_ssl_config_free(ptr);
		}
	};

	/**
	 * @brief TLS Config object trait.
	 *
	 */
	using DefaultTlsConfObjTrait = ObjTraitBase<TlsConfObjAllocator,
											 false,
											 false>;

	class TlsConfig : public ObjectBase<DefaultTlsConfObjTrait>
	{
	public: // Static members:

		using TlsConfObjTrait = DefaultTlsConfObjTrait;
		using _Base           = ObjectBase<TlsConfObjTrait>;

		/**
		 * @brief	Certificate verify call back function that is given to the mbed TLS's certificate
		 * 			verification function call.
		 *
		 * @param [in,out]	inst 	The pointer to 'this instance'. Must be not null.
		 * @param [in,out]	cert 	The pointer to MbedTLS's certificate. Must be not null.
		 * @param 		  	depth	The depth of current verification along the certificate chain.
		 * @param [in,out]	flag 	The flag of verification result. Please refer to MbedTLS's API for details.
		 *
		 * @return	The verification error code return.
		 */
		static int CertVerifyCallBack(void* inst, mbedtls_x509_crt* cert, int depth, uint32_t* flag) noexcept
		{
			if (inst == nullptr ||
				cert == nullptr ||
				flag == nullptr)
			{
				return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
			}

			try
			{
				return static_cast<TlsConfig*>(inst)->CustomVerifyCert(*cert, depth, *flag);
			}
			catch (const mbedTLSRuntimeError& e)
			{
				return e.GetErrorCode();
			}
			catch (...)
			{
				return MBEDTLS_ERR_X509_FATAL_ERROR;
			}
		}

	public:

		/**
		 * \brief Default constructor that will create and initialize an TLS
		 *        configuration.
		 *
		 * \param isStream   True if transport layer is stream (TLS), false
		 *                   if not (DTLS).
		 * \param isServer   Is this the server side?
		 * \param vrfyPeer   Do we want to verify the peer?
		 * \param preset     The preset. Please refer to mbedTLS
		 *                   mbedtls_ssl_config_defaults.
		 * \param ca         The CA. Can be \c nullptr if we don't verify peer.
		 * \param crl        Certificate Revocation List (Optional).
		 * \param cert       The certificate of this side (Optional). If it's
		 *                   not nullptr, the private key will be required.
		 * \param prvKey     The private key of this side. Required if cert is
		 *                   not \c nullptr .
		 * \param ticketMgr  Manager for TLS ticket (Optional).
		 * \param rand       The Random Bit Generator.
		 */
		TlsConfig(
			bool isStream, bool isServer, bool vrfyPeer,
			int preset,
			std::shared_ptr<const X509Cert> ca,
			std::shared_ptr<const X509Crl>  crl,
			std::shared_ptr<const X509Cert> cert,
			std::shared_ptr<const PKeyBase<> > prvKey,
			std::shared_ptr<TlsSessTktMgrIntf > ticketMgr,
			std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) :
			_Base::ObjectBase(),
			m_ca(ca),
			m_crl(crl),
			m_cert(cert),
			m_prvKey(prvKey),
			m_ticketMgr(ticketMgr),
			m_rand(std::move(rand))
		{
			mbedtls_ssl_conf_rng(NonVirtualGet(), &RbgInterface::CallBack, m_rand.get());
			mbedtls_ssl_conf_verify(NonVirtualGet(), &TlsConfig::CertVerifyCallBack, this);

			mbedtls_ssl_conf_session_tickets(NonVirtualGet(), MBEDTLS_SSL_SESSION_TICKETS_ENABLED);

			if (m_ticketMgr != nullptr)
			{
				mbedtls_ssl_conf_session_tickets_cb(NonVirtualGet(),
					&TlsSessTktMgrIntf::Write,
					&TlsSessTktMgrIntf::Parse,
					m_ticketMgr.get());
			}

			int endpoint = isServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				TlsConfig::TlsConfig,
				mbedtls_ssl_config_defaults,
				NonVirtualGet(), endpoint,
				isStream ? MBEDTLS_SSL_TRANSPORT_STREAM : MBEDTLS_SSL_TRANSPORT_DATAGRAM,
				preset
			);

			if (m_cert != nullptr)
			{
				if (m_prvKey == nullptr)
				{
					throw InvalidArgumentException("TlsConfig::TlsConfig - Private key or is required for this TLS config.");
				}
				m_prvKey->NullCheck();
				m_cert->NullCheck();

				MBEDTLSCPP_MAKE_C_FUNC_CALL(
					TlsConfig::TlsConfig,
					mbedtls_ssl_conf_own_cert,
					NonVirtualGet(),
					m_cert->MutableGet(),
					m_prvKey->MutableGet()
				);
			}

			if (vrfyPeer)
			{
				if (m_ca == nullptr)
				{
					throw InvalidArgumentException("TlsConfig::TlsConfig - CA's certificate is required for this TLS config.");
				}
				m_ca->NullCheck();
				mbedtls_x509_crl* crlPtr = nullptr;
				if (m_crl != nullptr)
				{
					m_crl->NullCheck();
					crlPtr = m_crl->MutableGet();
				}
				mbedtls_ssl_conf_ca_chain(NonVirtualGet(), m_ca->MutableGet(), crlPtr);
				mbedtls_ssl_conf_authmode(NonVirtualGet(), MBEDTLS_SSL_VERIFY_REQUIRED);
			}
			else
			{
				mbedtls_ssl_conf_authmode(NonVirtualGet(), MBEDTLS_SSL_VERIFY_NONE);
			}
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other TlsConfig instance.
		 */
		TlsConfig(TlsConfig&& rhs) noexcept :
			_Base::ObjectBase(std::forward<_Base>(rhs)), //noexcept
			m_rand(std::move(rhs.m_rand)),          //noexcept
			m_ca(std::move(rhs.m_ca)),              //noexcept
			m_crl(std::move(rhs.m_crl)),            //noexcept
			m_cert(std::move(rhs.m_cert)),          //noexcept
			m_prvKey(std::move(rhs.m_prvKey)),      //noexcept
			m_ticketMgr(std::move(rhs.m_ticketMgr)) //noexcept
		{
			if (NonVirtualGet() != nullptr)
			{
				mbedtls_ssl_conf_verify(NonVirtualGet(), &TlsConfig::CertVerifyCallBack, this);
			}
		}

		TlsConfig(const TlsConfig& rhs) = delete;

		virtual ~TlsConfig()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other TlsConfig instance.
		 * @return TlsConfig& A reference to this instance.
		 */
		TlsConfig& operator=(TlsConfig&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			if (this != &rhs)
			{
				m_rand      = std::move(rhs.m_rand);      //noexcept
				m_ca        = std::move(rhs.m_ca);        //noexcept
				m_crl       = std::move(rhs.m_crl);       //noexcept
				m_cert      = std::move(rhs.m_cert);      //noexcept
				m_prvKey    = std::move(rhs.m_prvKey);    //noexcept
				m_ticketMgr = std::move(rhs.m_ticketMgr); //noexcept

				if (Get() != nullptr)
				{
					mbedtls_ssl_conf_verify(Get(), &TlsConfig::CertVerifyCallBack, this);
				}
			}

			return *this;
		}

		TlsConfig& operator=(const TlsConfig& other) = delete;

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
			_Base::NullCheck(MBEDTLSCPP_CLASS_NAME_STR(TlsConfig));
		}

		virtual bool IsNull() const noexcept override
		{
			return _Base::IsNull() ||
				(m_rand == nullptr) ||
				(m_prvKey == nullptr);
		}

		using _Base::NullCheck;
		using _Base::Get;
		using _Base::NonVirtualGet;
		using _Base::Swap;

		/**
		 * \brief	Verify the certificate with customized verification process.
		 *          The certificate should already be verified by the standard process,
		 *          and then call this function.
		 *          Usually this is called by mbed TLS's callback.
		 *          Note: this function and any underlying calls may throw
		 *          exceptions, but, they will be caught by the static callback
		 *          function (i.e. CertVerifyCallBack), and return an error code
		 * 			instead.
		 *
		 * \param [in,out]	cert 	The certificate.
		 * \param 		  	depth	The depth of current verification along the certificate chain.
		 * \param [in,out]	flag 	The flag of verification result. Please refer to MbedTLS's API for
		 * 							details.
		 *
		 * \return	The verification error code return.
		 */
		virtual int CustomVerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const
		{
			// The default behavior is to keep the flag untouched and directly return success.
			return MBEDTLS_EXIT_SUCCESS;
		}

		private:
			std::unique_ptr<RbgInterface> m_rand;
			std::shared_ptr<const X509Cert> m_ca;
			std::shared_ptr<const X509Crl>  m_crl;
			std::shared_ptr<const X509Cert> m_cert;
			std::shared_ptr<const PKeyBase<> > m_prvKey;
			std::shared_ptr<TlsSessTktMgrIntf > m_ticketMgr;
	};
}
