#pragma once

#include "ObjectBase.hpp"

#include <mbedtls/ssl.h>

#include "Common.hpp"
#include "Exceptions.hpp"
#include "DefaultRbg.hpp"
#include "X509Cert.hpp"
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

		enum class Mode
		{
			ServerVerifyPeer,   //This is server side, and it is required to verify peer's certificate.
			ServerNoVerifyPeer, //This is server side, and there is no need to verify peer's certificate.
			ClientHasCert,      //This is client side, and a certificate, which is required during TLS handshake, is possessed by the client.
			ClientNoCert,       //This is client side, and there is no certificate possessed by the client.
		};

	public:

		/**
		 * \brief Default constructor that will create and initialize an TLS configuration. Both DRBG
		 *        and verification callback function are set here.
		 *
		 * \param isStream   True if transport layer is stream (TLS), false if not (DTLS).
		 * \param cntMode    The connection mode.
		 * \param preset     The preset. Please refer to mbedTLS mbedtls_ssl_config_defaults.
		 * \param ca         The CA.
		 * \param cert       The certificate.
		 * \param prvKey     The private key.
		 * \param ticketMgr  Manager for TLS ticket.
		 * \param rand       The Random Bit Generator.
		 */
		TlsConfig(bool isStream, Mode cntMode, int preset,
			std::shared_ptr<const X509Cert> ca,
			std::shared_ptr<const X509Cert> cert,
			std::shared_ptr<const PKeyBase<> > prvKey,
			std::shared_ptr<TlsSessTktMgrIntf > ticketMgr,
			std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) :
			_Base::ObjectBase(),
			m_ca(ca),
			m_cert(cert),
			m_prvKey(prvKey),
			m_ticketMgr(ticketMgr),
			m_rand(std::move(rand))
		{
			mbedtls_ssl_conf_rng(NonVirtualGet(), &RbgInterface::CallBack, m_rand.get());
			mbedtls_ssl_conf_verify(NonVirtualGet(), &TlsConfig::CertVerifyCallBack, this);

			mbedtls_ssl_conf_session_tickets(NonVirtualGet(), MBEDTLS_SSL_SESSION_TICKETS_ENABLED);

			if (m_ticketMgr)
			{
				mbedtls_ssl_conf_session_tickets_cb(NonVirtualGet(),
					&TlsSessTktMgrIntf::Write,
					&TlsSessTktMgrIntf::Parse,
					m_ticketMgr.get());
			}

			int endpoint = 0;
			switch (cntMode)
			{
			case Mode::ServerVerifyPeer:
			case Mode::ServerNoVerifyPeer:
				endpoint = MBEDTLS_SSL_IS_SERVER;

				break;
			case Mode::ClientHasCert:
			case Mode::ClientNoCert:
				endpoint = MBEDTLS_SSL_IS_CLIENT;

				break;
			default:
				throw RuntimeException("TlsConfig::TlsConfig - The given TLS connection mode is invalid.");
			}

			MBEDTLSCPP_MAKE_C_FUNC_CALL(
				TlsConfig::TlsConfig,
				mbedtls_ssl_config_defaults,
				NonVirtualGet(), endpoint,
				isStream ? MBEDTLS_SSL_TRANSPORT_STREAM : MBEDTLS_SSL_TRANSPORT_DATAGRAM,
				preset
			);

			switch (cntMode)
			{
			case Mode::ServerVerifyPeer: //Usually server always has certificate & key.
			case Mode::ServerNoVerifyPeer:
			case Mode::ClientHasCert:
				if (!m_prvKey || !m_cert)
				{
					throw RuntimeException("TlsConfig::TlsConfig - Key or certificate is required for this TLS config.");
				}
				MBEDTLSCPP_MAKE_C_FUNC_CALL(
					TlsConfig::TlsConfig,
					mbedtls_ssl_conf_own_cert,
					NonVirtualGet(),
					m_cert->MutableGet(),
					m_prvKey->MutableGet()
				);

				break;
			case Mode::ClientNoCert:
			default:
				break;
			}

			switch (cntMode)
			{
			case Mode::ServerNoVerifyPeer:
				mbedtls_ssl_conf_authmode(NonVirtualGet(), MBEDTLS_SSL_VERIFY_NONE);

				break;
			case Mode::ServerVerifyPeer:
			case Mode::ClientHasCert: //Usually in Decent RA, client side always verify server side.
			case Mode::ClientNoCert:
				if (!m_ca)
				{
					throw RuntimeException("TlsConfig::TlsConfig - CA's certificate is required for this TLS config.");
				}
				mbedtls_ssl_conf_ca_chain(NonVirtualGet(), m_ca->MutableGet(), nullptr);
				mbedtls_ssl_conf_authmode(NonVirtualGet(), MBEDTLS_SSL_VERIFY_REQUIRED);

				break;
			default:
				break;
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
			_Base::NullCheck(typeid(TlsConfig).name());
		}

		virtual bool IsNull() const noexcept override
		{
			return _Base::IsNull() ||
				(m_rand == nullptr) ||
				(m_ca == nullptr) ||
				(m_cert == nullptr) ||
				(m_prvKey == nullptr) ||
				(m_ticketMgr == nullptr);
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
			std::shared_ptr<const X509Cert> m_cert;
			std::shared_ptr<const PKeyBase<> > m_prvKey;
			std::shared_ptr<TlsSessTktMgrIntf > m_ticketMgr;
	};
}
