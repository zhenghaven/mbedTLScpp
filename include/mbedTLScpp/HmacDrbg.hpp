#pragma once

#include "ObjectBase.hpp"
#include "RandInterfaces.hpp"

#include "Common.hpp"
#include "Entropy.hpp"
#include "MsgDigestBase.hpp"

#include <mbedtls/hmac_drbg.h>

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{

	/**
	 * @brief Hmac-DRBG allocator.
	 *
	 */
	struct HmacDrbgAllocator : DefaultAllocBase
	{
		typedef mbedtls_hmac_drbg_context      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_hmac_drbg_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_hmac_drbg_free(ptr);
		}
	};

	/**
	 * @brief Hmac-DRBG Trait.
	 *
	 */
	using DefaultHmacDrbgTrait = ObjTraitBase<HmacDrbgAllocator,
									false,
									false>;

	/**
	 * @brief Class for Hmac-DRBG
	 *
	 * @tparam _PredResist   Turns prediction resistance on or off
	 *                       (default to \c true )
	 * @tparam _HashType     The type of hash to use
	 *                       (default to \c HashType::SHA256 )
	 * @tparam _ReseedInterv The reseed interval
	 *                       (default to \c MBEDTLS_HMAC_DRBG_RESEED_INTERVAL )
	 */
	template<bool    _PredResist = true,
			HashType _HashType = HashType::SHA256,
			int      _ReseedInterv = MBEDTLS_HMAC_DRBG_RESEED_INTERVAL>
	class HmacDrbg : public ObjectBase<DefaultHmacDrbgTrait>, public RbgInterface
	{
	public:

		/**
		 * @brief Construct a new Hmac-Drbg object with a shared entropy object
		 *
		 */
		HmacDrbg() :
			HmacDrbg(GetSharedEntropy())
		{}

		/**
		 * @brief Construct a new Hmac-Drbg object with the given entropy
		 *
		 * @param entropy The entropy given to use
		 */
		HmacDrbg(std::unique_ptr<EntropyInterface> entropy) :
			ObjectBase<DefaultHmacDrbgTrait>::ObjectBase(),
			m_entropy(std::move(entropy))
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(HmacDrbg::HmacDrbg, mbedtls_hmac_drbg_seed, Get(), &GetMdInfo(_HashType), &EntropyInterface::CallBack, m_entropy.get(), nullptr, 0);

			mbedtls_hmac_drbg_set_prediction_resistance(Get(), _PredResist ? MBEDTLS_HMAC_DRBG_PR_ON : MBEDTLS_HMAC_DRBG_PR_OFF);
			mbedtls_hmac_drbg_set_reseed_interval(Get(), _ReseedInterv);
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other HmacDrbg instance.
		 */
		HmacDrbg(HmacDrbg&& rhs) noexcept :
			ObjectBase<DefaultHmacDrbgTrait>::ObjectBase(std::forward<ObjectBase<DefaultHmacDrbgTrait> >(rhs)),
			m_entropy(std::move(rhs.m_entropy))
		{}

		HmacDrbg(const HmacDrbg& rhs) = delete;

		/** @brief	Destructor */
		virtual ~HmacDrbg()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other HmacDrbg instance.
		 * @return HmacDrbg& A reference to this instance.
		 */
		HmacDrbg& operator=(HmacDrbg&& rhs) noexcept
		{
			ObjectBase<DefaultHmacDrbgTrait>::operator=(std::forward<ObjectBase<DefaultHmacDrbgTrait> >(rhs));
			m_entropy = std::move(rhs.m_entropy);

			return *this;
		}

		HmacDrbg& operator=(const HmacDrbg& other) = delete;

		/**
		 * @brief Fill random bits into the given memory region.
		 *
		 * @param buf  The pointer to the beginning of the memory region.
		 * @param size The size of the memory region.
		 */
		virtual void Rand(void* buf, const size_t size) const override
		{
			NullCheck();
			MBEDTLSCPP_MAKE_C_FUNC_CALL(HmacDrbg::Rand, mbedtls_hmac_drbg_random, MutableGet(), static_cast<unsigned char *>(buf), size);
		}

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
			ObjectBase<DefaultHmacDrbgTrait>::NullCheck(typeid(HmacDrbg).name());
		}

	private:

		std::unique_ptr<EntropyInterface> m_entropy;
	};
}
