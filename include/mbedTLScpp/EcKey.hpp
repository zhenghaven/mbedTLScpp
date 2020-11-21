#pragma once

#include <tuple>

#include "PKey.hpp"

#include "BigNumber.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	/**
	 * @brief Elliptic Curve types
	 *
	 */
	enum class EcType
	{
		SECP192R1,
		SECP224R1,
		SECP256R1,
		SECP384R1,
		SECP521R1,

		BrPo256R1,
		BrPo384R1,
		BrPo512R1,

		SECP192K1,
		SECP224K1,
		SECP256K1,

		CURVE25519,
		CURVE448,
	};

	/**
	 * @brief	Gets Elliptic Curve size in Byte
	 *
	 * @exception	RuntimeException	Thrown when Invalid Elliptic Curve type is given.
	 *
	 * @param	type	The curve type.
	 *
	 * @return	The size in Byte.
	 */
	inline constexpr size_t GetCurveByteSize(EcType type)
	{
		return
			(type == EcType::SECP192R1 ? 24UL :
			(type == EcType::SECP192K1 ? 24UL :

			(type == EcType::SECP224R1 ? 28UL :
			(type == EcType::SECP224K1 ? 28UL :

			(type == EcType::SECP256R1 ? 32UL :
			(type == EcType::SECP256K1 ? 32UL :
			(type == EcType::BrPo256R1 ? 32UL :

			(type == EcType::SECP384R1 ? 48UL :
			(type == EcType::BrPo384R1 ? 48UL :

			(type == EcType::BrPo512R1 ? 64UL :

			(type == EcType::SECP521R1 ? 66UL :

			(type == EcType::CURVE25519? 32UL :
			//(type == EcType::CURVE448  ? 56UL :

			(throw InvalidArgumentException("Invalid Elliptic Curve type is given."))

			//)
			))))))))))));
	}

	/**
	 * @brief	Gets Elliptic Curve size, in Byte, that can fit in the array of mbedtls_mpi_uint.
	 *
	 * @exception	RuntimeException	Thrown when Invalid Elliptic Curve type is given.
	 *
	 * @param	type	The curve type.
	 *
	 * @return	The size in Byte.
	 */
	inline constexpr size_t GetCurveByteSizeFitsMpi(EcType type)
	{
		return ((GetCurveByteSize(type) + (sizeof(mbedtls_mpi_uint) - 1)) / sizeof(mbedtls_mpi_uint)) * sizeof(mbedtls_mpi_uint);
	}
	static_assert(GetCurveByteSizeFitsMpi(EcType::SECP192R1) == 24UL, "Programming Error");
	static_assert(GetCurveByteSizeFitsMpi(EcType::SECP224R1) == 32UL, "Programming Error");
	static_assert(GetCurveByteSizeFitsMpi(EcType::SECP256R1) == 32UL, "Programming Error");
	static_assert(GetCurveByteSizeFitsMpi(EcType::SECP384R1) == 48UL, "Programming Error");
	static_assert(GetCurveByteSizeFitsMpi(EcType::BrPo512R1) == 64UL, "Programming Error");
	static_assert(GetCurveByteSizeFitsMpi(EcType::SECP521R1) == 72UL, "Programming Error");

	/**
	 * @brief Translate the EcKey type to the mbed TLS EC group ID.
	 *
	 * @param type The curve type.
	 * @return constexpr mbedtls_ecp_group_id The mbed TLS EC group ID.
	 */
	inline constexpr mbedtls_ecp_group_id ToEcGroupId(EcType type)
	{
		return
			(type == EcType::SECP192R1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP192R1 :
			(type == EcType::SECP224R1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP224R1 :
			(type == EcType::SECP256R1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1 :
			(type == EcType::SECP384R1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP384R1 :
			(type == EcType::SECP521R1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP521R1 :

			(type == EcType::BrPo256R1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP256R1 :
			(type == EcType::BrPo384R1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP384R1 :
			(type == EcType::BrPo512R1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP512R1 :

			(type == EcType::SECP192K1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP192K1 :
			(type == EcType::SECP224K1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP224K1 :
			(type == EcType::SECP256K1 ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256K1 :

			(type == EcType::CURVE25519? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_CURVE25519:
			//(type == EcType::CURVE448  ? mbedtls_ecp_group_id::MBEDTLS_ECP_DP_CURVE448  :

			(throw InvalidArgumentException("Invalid Elliptic Curve type is given."))

			//)
			))))))))))));
	}

	/**
	 * @brief Translate the mbed TLS EC group ID to the EcKey type.
	 *
	 * @param type The mbed TLS EC group ID.
	 * @return constexpr mbedtls_ecp_group_id The curve type.
	 */
	inline constexpr EcType ToEcType(mbedtls_ecp_group_id type)
	{
		return
			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP192R1 ? EcType::SECP192R1 :
			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP224R1 ? EcType::SECP224R1 :
			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1 ? EcType::SECP256R1 :
			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP384R1 ? EcType::SECP384R1 :
			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP521R1 ? EcType::SECP521R1 :

			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP256R1 ? EcType::BrPo256R1 :
			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP384R1 ? EcType::BrPo384R1 :
			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_BP512R1 ? EcType::BrPo512R1 :

			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP192K1 ? EcType::SECP192K1 :
			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP224K1 ? EcType::SECP224K1 :
			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256K1 ? EcType::SECP256K1 :

			(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_CURVE25519? EcType::CURVE25519:
			//(type == mbedtls_ecp_group_id::MBEDTLS_ECP_DP_CURVE448 ? EcType::CURVE448   :

			(throw InvalidArgumentException("Invalid Elliptic Curve type is given."))

			//)
			))))))))))));
	}

	/**
	 * @brief Normal EC group allocator.
	 *
	 */
	struct EcGroupAllocator : DefaultAllocBase
	{
		typedef mbedtls_ecp_group      CObjType;

		using DefaultAllocBase::NewObject;
		using DefaultAllocBase::DelObject;

		static void Init(CObjType* ptr)
		{
			return mbedtls_ecp_group_init(ptr);
		}

		static void Free(CObjType* ptr) noexcept
		{
			return mbedtls_ecp_group_free(ptr);
		}
	};

	/**
	 * @brief Normal EC Group Trait.
	 *
	 */
	using DefaultEcGroupObjTrait = ObjTraitBase<EcGroupAllocator,
									false,
									false>;

	/**
	 * @brief Borrower EC Group Trait.
	 *
	 */
	using BorrowedEcGroupTrait = ObjTraitBase<BorrowAllocBase<mbedtls_ecp_group>,
									true,
									false>;

	template<typename _ObjTraits = DefaultEcGroupObjTrait,
			 enable_if_t<std::is_same<typename _ObjTraits::CObjType, mbedtls_ecp_group>::value, int> = 0>
	class EcGroup : public ObjectBase<_ObjTraits>
	{
	public: // static member:

		using _Base = ObjectBase<_ObjTraits>;

	public:

		template<// automated parts:
				typename _dummy_ObjTrait = _ObjTraits,
				enable_if_t<!_dummy_ObjTrait::sk_isBorrower && !_dummy_ObjTrait::sk_isConst, int> = 0>
		EcGroup(EcType type) :
			_Base::ObjectBase()
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcGroup::EcGroup,
				mbedtls_ecp_group_load, Get(), ToEcGroupId(type));
		}

		template<// automated parts:
				typename _rhs_ObjTrait,
				typename _dummy_ObjTrait = _ObjTraits,
				enable_if_t<!_dummy_ObjTrait::sk_isBorrower && !_dummy_ObjTrait::sk_isConst, int> = 0>
		EcGroup(const EcGroup<_rhs_ObjTrait>& other) :
			_Base::ObjectBase()
		{
			if(other.IsNull())
			{
				_Base::FreeBaseObject();
			}
			else
			{
				MBEDTLSCPP_MAKE_C_FUNC_CALL(EcGroup::EcGroup,
					mbedtls_ecp_group_copy, Get(), other.Get());
			}
		}

		EcGroup(EcGroup&& rhs) noexcept :
			_Base::ObjectBase(std::forward<_Base>(rhs)) //noexcept
		{}

		template<// automated parts:
				typename _dummy_ObjTrait = _ObjTraits,
				enable_if_t<!_dummy_ObjTrait::sk_isBorrower && !_dummy_ObjTrait::sk_isConst, int> = 0>
		EcGroup(const mbedtls_ecp_group& other) :
			_Base::ObjectBase()
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcGroup::EcGroup,
				mbedtls_ecp_group_copy, Get(), &other);
		}

		template<// automated parts:
				typename _dummy_ObjTrait = _ObjTraits,
				enable_if_t<_dummy_ObjTrait::sk_isBorrower, int> = 0>
		EcGroup(mbedtls_ecp_group& other) :
			_Base::ObjectBase(&other)
		{}

		virtual ~EcGroup()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other EcGroup instance.
		 * @return EcGroup& A reference to this instance.
		 */
		EcGroup& operator=(EcGroup&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
		}

		template<// automated parts:
				typename _dummy_ObjTrait = _ObjTraits,
				enable_if_t<_dummy_ObjTrait::sk_isConst, int> = 0>
		EcGroup& operator=(const EcGroup& rhs) = delete;

		template<// automated parts:
				typename _rhs_ObjTrait,
				typename _dummy_ObjTrait = _ObjTraits,
				enable_if_t<!_dummy_ObjTrait::sk_isConst, int> = 0>
		EcGroup& operator=(const EcGroup<_rhs_ObjTrait>& rhs)
		{
			if(rhs.IsNull())
			{
				_Base::FreeBaseObject();
			}
			else
			{
				MBEDTLSCPP_MAKE_C_FUNC_CALL(EcGroup::operator=,
					mbedtls_ecp_group_copy, Get(), rhs.Get());
			}
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
			_Base::NullCheck(typeid(EcGroup).name());
		}

		using _Base::Get;
		using _Base::Swap;

		void Load(EcType type)
		{
			NullCheck();
			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcGroup::Load,
				mbedtls_ecp_group_load, Get(), ToEcGroupId(type));
		}
	};

	template<typename _PKObjTrait = DefaultPKeyObjTrait,
			 enable_if_t<std::is_same<typename _PKObjTrait::CObjType, mbedtls_pk_context>::value, int> = 0>
	class EcPublicKeyBase : public PKeyBase<_PKObjTrait>
	{
	public: // Types:

		using _Base = PKeyBase<_PKObjTrait>;

	public: // Static members, and methods will be used in constructors:

		using _Base::Get;

		/**
		 * @brief	Move constructor that moves a general PKeyBase object to EC
		 *          Key pair. If it failed, the \c other will remain the same.
		 *
		 * @exception InvalidArgumentException Thrown when the given object is
		 *                                     not a EC private key.
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	other	The PKeyBase instance to convert.
		 */
		static EcPublicKeyBase Convert(PKeyBase<_PKObjTrait>&& other)
		{
			return EcPublicKeyBase(std::forward<PKeyBase<_PKObjTrait> >(other), (const void*)nullptr);
		}

		/**
		 * @brief Construct a EcPublicKeyBase object (public part) from a given PEM string.
		 *
		 * @param pem PEM string in std::string
		 */
		static EcPublicKeyBase FromPEM(const std::string& pem)
		{
			return EcPublicKeyBase(pem, (const void*)nullptr);
		}

		/**
		 * @brief Construct a EcPublicKeyBase object (public part) from a given DER bytes.
		 *
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _SecCtnType>
		static EcPublicKeyBase FromDER(const ContCtnReadOnlyRef<_SecCtnType, false>& der)
		{
			return EcPublicKeyBase(der, (const void*)nullptr);
		}

	protected: // methods will be used in constructors:

		mbedtls_ecp_keypair& GetEcContextNoNullCheck()
		{
			return *mbedtls_pk_ec(*Get());
		}

		const mbedtls_ecp_keypair& GetEcContextNoNullCheck() const
		{
			return *mbedtls_pk_ec(*Get());
		}

	public:

		/**
		 * @brief Construct a new EcPublicKeyBase object that borrows the C object.
		 *
		 * @tparam _dummy_Trait A dummy template parameter used to make sure
		 *                      the constructor is only available for borrowers.
		 * @param ptr pointer to the borrowed C object.
		 */
		template<typename _dummy_Trait = _PKObjTrait,
				 enable_if_t<_dummy_Trait::sk_isBorrower, int> = 0>
		EcPublicKeyBase(mbedtls_pk_context* ptr) :
			_Base::PKeyBase(ptr)
		{
			if (_Base::GetAlgmCat(*Get()) != PKeyAlgmCat::EC)
			{
				throw InvalidArgumentException("EcPublicKeyBase::EcPublicKeyBase - The given PK context is not a EC Key.");
			}
			if(!_Base::HasPubKey(GetEcContextNoNullCheck()))
			{
				throw InvalidArgumentException("EcPublicKeyBase::EcPublicKeyBase - The given PK context contains no public key.");
			}
		}

		/**
		 * @brief	Constructor from public key's X, Y and Z values. Z is default to 1.
		 *
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	type	The type of Elliptic Curve.
		 * @param	x	  	Elliptic Curve public key's X value.
		 * @param	y	  	Elliptic Curve public key's Y value.
		 * @param	z	  	Elliptic Curve public key's Z value.
		 */
		EcPublicKeyBase(EcType type,
						BigNum x, BigNum y, BigNum z = BigNum(1)) :
			EcPublicKeyBase(type)
		{
			auto& ecCtx = GetEcContextNoNullCheck();

			BigNum tmpX(std::move(x));
			BigNum tmpY(std::move(y));
			BigNum tmpZ(std::move(z));
			tmpX.SwapContent(ecCtx.Q.X);
			tmpY.SwapContent(ecCtx.Q.Y);
			tmpZ.SwapContent(ecCtx.Q.Z);

			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcPublicKeyBase::EcPublicKeyBase,
				mbedtls_ecp_check_pubkey, &(ecCtx.grp), &(ecCtx.Q));
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other EC public key instance.
		 */
		EcPublicKeyBase(EcPublicKeyBase&& rhs) noexcept :
			_Base::PKeyBase(std::forward<_Base>(rhs)) //noexcept
		{}

		/**
		 * @brief Copy Constructor.
		 *
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @tparam _dummy_Trait A dummy template parameter used to make sure
		 *                      the constructor is not available for borrowers.
		 * @param rhs The other EC public key instance.
		 */
		template<typename _other_Trait,
				 typename _dummy_Trait = _PKObjTrait,
				 enable_if_t<!_dummy_Trait::sk_isBorrower, int> = 0>
		EcPublicKeyBase(const EcPublicKeyBase<_other_Trait>& rhs, const void* = nullptr) :
			_Base::PKeyBase()
		{
			if(rhs.Get() == nullptr)
			{
				_Base::FreeBaseObject();
				return;
			}

			if(rhs.Get()->pk_ctx != nullptr)
			{
				MBEDTLSCPP_MAKE_C_FUNC_CALL(EcPublicKeyBase::EcPublicKeyBase,
					mbedtls_pk_setup, Get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY));

				const auto& rhsEcCtx = rhs.GetEcContext();
				auto& ecCtx = GetEcContextNoNullCheck();

				MBEDTLSCPP_MAKE_C_FUNC_CALL(EcPublicKeyBase::EcPublicKeyBase,
					mbedtls_ecp_group_copy, &ecCtx.grp, &rhsEcCtx.grp);
				MBEDTLSCPP_MAKE_C_FUNC_CALL(EcPublicKeyBase::EcPublicKeyBase,
					mbedtls_ecp_copy, &ecCtx.Q, &rhsEcCtx.Q);
			}
		}

		EcPublicKeyBase(const EcPublicKeyBase& rhs) :
			EcPublicKeyBase(rhs, (const void*)nullptr)
		{}

		virtual ~EcPublicKeyBase()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other EcPublicKeyBase instance.
		 * @return EcPublicKeyBase& A reference to this instance.
		 */
		EcPublicKeyBase& operator=(EcPublicKeyBase&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
		}

		/**
		 * @brief Copy assignment.
		 *
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param rhs The other EcPublicKeyBase instance.
		 * @return EcPublicKeyBase& A reference to this instance.
		 */
		template<typename _rhs_Trait,
				 typename _dummy_Trait = _PKObjTrait,
				 enable_if_t<!_dummy_Trait::sk_isBorrower, int> = 0>
		EcPublicKeyBase& operator=(const EcPublicKeyBase<_rhs_Trait>& rhs)
		{
			if (static_cast<const void*>(this) != static_cast<const void*>(&rhs))
			{
				_Base::FreeBaseObject();
				if (rhs.Get() != nullptr)
				{
					_Base::InitBaseObject();
					if (rhs.Get()->pk_ctx != nullptr)
					{
						MBEDTLSCPP_MAKE_C_FUNC_CALL(EcPublicKeyBase::EcPublicKeyBase,
							mbedtls_pk_setup, Get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY));

						const auto& rhsEcCtx = rhs.GetEcContext();
						auto& ecCtx = GetEcContextNoNullCheck();

						MBEDTLSCPP_MAKE_C_FUNC_CALL(EcPublicKeyBase::EcPublicKeyBase,
							mbedtls_ecp_group_copy, &ecCtx.grp, &rhsEcCtx.grp);
						MBEDTLSCPP_MAKE_C_FUNC_CALL(EcPublicKeyBase::EcPublicKeyBase,
							mbedtls_ecp_copy, &ecCtx.Q, &rhsEcCtx.Q);
					}
				}
			}
			return *this;
		}

		EcPublicKeyBase& operator=(const EcPublicKeyBase& rhs)
		{
			return operator=<_PKObjTrait>(rhs);
		}

		using _Base::NullCheck;
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
			_Base::NullCheck(typeid(EcPublicKeyBase).name());
		}

		/**
		 * @brief	Gets mbed TLS's EC key pair context.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 *
		 * @return	The mbed TLS's EC key pair context.
		 */
		mbedtls_ecp_keypair& GetEcContext()
		{
			NullCheck();
			_Base::PKeyContextNullCheck(*Get());
			return GetEcContextNoNullCheck();
		}

		/**
		 * @brief	Gets mbed TLS's EC key pair context.
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 *
		 * @return	The mbed TLS's EC key pair context.
		 */
		const mbedtls_ecp_keypair& GetEcContext() const
		{
			NullCheck();
			_Base::PKeyContextNullCheck(*Get());
			return GetEcContextNoNullCheck();
		}

		/**
		 * @brief	Gets PKey algorithm type.
		 *
		 * @return	The PKey algorithm type.
		 */
		virtual PKeyAlgmCat GetAlgmCat() const override
		{
			return PKeyAlgmCat::EC;
		}

		/**
		 * @brief	Gets PKey type (either public or private).
		 *
		 * @return	The PKey type.
		 */
		virtual PKeyType GetKeyType() const override
		{
			return PKeyType::Public;
		}

		/**
		 * @brief	Gets Elliptic Curve type
		 *
		 * @return	The Elliptic Curve type.
		 */
		virtual EcType GetEcType() const
		{
			return ToEcType(GetEcContext().grp.id);
		}

		/**
		 * @brief	Verify signature.
		 *
		 * @tparam	containerType	Type of the container for the hash.
		 * @param	hash	The hash.
		 * @param	r   	Elliptic Curve signature's R value.
		 * @param	s   	Elliptic Curve signature's S value.
		 */
		template<typename _HashCtnType, bool _HashSecrecy,
				 typename _r_Trait, typename _s_Trait>
		void VerifySign(const ContCtnReadOnlyRef<_HashCtnType, _HashSecrecy>& hash,
						const BigNumberBase<_r_Trait>& r, const BigNumberBase<_s_Trait>& s) const
		{
			const auto& ecCtx = GetEcContext();

			EcGroup<> ecGrp = ecCtx.grp;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcPublicKeyBase::VerifySign,
				mbedtls_ecdsa_verify, ecGrp.Get(),
				static_cast<const unsigned char*>(hash.BeginPtr()), hash.GetRegionSize(),
				&(ecCtx.Q), r.Get(), s.Get());
		}

		template<typename _HashCtnType, bool _HashSecrecy,
				 typename _SRCtnType,   bool _SRSecrecy>
		void VerifySign(const ContCtnReadOnlyRef<_HashCtnType, _HashSecrecy>& hash,
						const ContCtnReadOnlyRef<_SRCtnType,   _SRSecrecy>& r,
						const ContCtnReadOnlyRef<_SRCtnType,   _SRSecrecy>& s) const
		{
			if (ConstBigNumber::CanMemRegFit(r.GetRegionSize()) && ConstBigNumber::CanMemRegFit(s.GetRegionSize()))
			{
				return VerifySign(hash, ConstBigNumber(r), ConstBigNumber(s));
			}
			else if (ConstBigNumber::CanMemRegFit(r.GetRegionSize()))
			{
				return VerifySign(hash, ConstBigNumber(r), BigNum(s, true, true));
			}
			else if (ConstBigNumber::CanMemRegFit(s.GetRegionSize()))
			{
				return VerifySign(hash, BigNum(r, true, true), ConstBigNumber(s));
			}
			else
			{
				return VerifySign(hash, BigNum(r, true, true), BigNum(s, true, true));
			}
		}

		using _Base::GetPublicDer;
		using _Base::GetPublicPem;

	protected:

		EcPublicKeyBase() :
			_Base::PKeyBase()
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcPublicKeyBase::EcPublicKeyBase,
				mbedtls_pk_setup, Get(), mbedtls_pk_info_from_type(mbedtls_pk_type_t::MBEDTLS_PK_ECKEY));
		}

		EcPublicKeyBase(EcType type) :
			EcPublicKeyBase()
		{
			auto& ecCtx = GetEcContextNoNullCheck();

			EcGroup<BorrowedEcGroupTrait> ecGrp(ecCtx.grp);
			ecGrp.Load(type);
		}

		/**
		 * @brief Construct a EcPublicKeyBase object (public part) from a given PEM string.
		 *
		 * @tparam _dummy_Trait A dummy template parameter used to make sure
		 *                      the constructor is not available for borrowers.
		 * @param pem PEM string in std::string
		 */
		template<typename _dummy_Trait = _PKObjTrait,
				 enable_if_t<!_dummy_Trait::sk_isBorrower, int> = 0>
		EcPublicKeyBase(const std::string& pem, const void*) :
			_Base::PKeyBase(pem)
		{
			if (_Base::GetAlgmCat(*Get()) != PKeyAlgmCat::EC)
			{
				throw InvalidArgumentException("EcPublicKeyBase::EcPublicKeyBase - The given PK context is not a EC Key.");
			}
		}

		/**
		 * @brief Construct a EcPublicKeyBase object (public part) from a given DER bytes.
		 *
		 * @tparam _dummy_Trait A dummy template parameter used to make sure
		 *                      the constructor is not available for borrowers.
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _dummy_Trait = _PKObjTrait,
				 typename ContainerType,
				 enable_if_t<!_dummy_Trait::sk_isBorrower, int> = 0>
		EcPublicKeyBase(const ContCtnReadOnlyRef<ContainerType, false>& der, const void*) :
			_Base::PKeyBase(der)
		{
			if (_Base::GetAlgmCat(*Get()) != PKeyAlgmCat::EC)
			{
				throw InvalidArgumentException("EcPublicKeyBase::EcPublicKeyBase - The given PK context is not a EC Key.");
			}
		}

		/**
		 * @brief Construct a EcPublicKeyBase object (private part) from a given PEM string.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is not available for borrowers.
		 * @param pem PEM string in SecretString.
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
			enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcPublicKeyBase(const SecretString& pem, const void*) :
			_Base::PKeyBase(pem)
		{
			if (_Base::GetAlgmCat(*Get()) != PKeyAlgmCat::EC)
			{
				throw InvalidArgumentException("EcPublicKeyBase::EcPublicKeyBase - The given PK context is not a EC Key.");
			}
		}

		/**
		 * @brief Construct a EcPublicKeyBase object (private part) from a given DER bytes.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is not available for borrowers.
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
			typename ContainerType,
			enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcPublicKeyBase(const ContCtnReadOnlyRef<ContainerType, true>& der, const void*) :
			_Base::PKeyBase(der)
		{
			if (_Base::GetAlgmCat(*Get()) != PKeyAlgmCat::EC)
			{
				throw InvalidArgumentException("EcPublicKeyBase::EcPublicKeyBase - The given PK context is not a EC Key.");
			}
		}

		/**
		 * @brief	Move constructor that moves a general PKeyBase object to EC
		 *          Key pair. If it failed, the \c other will remain the same.
		 *
		 * @exception InvalidArgumentException Thrown when the given object is
		 *                                     not a EC private key.
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	other	The PKeyBase instance to convert.
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		explicit EcPublicKeyBase(PKeyBase<_PKObjTrait>&& other, const void*) :
			_Base::PKeyBase(std::forward<_Base>(other)) //noexcept
		{
			try
			{
				// Is EC Key?
				if (_Base::GetAlgmCat(*Get()) != PKeyAlgmCat::EC)
				{
					throw InvalidArgumentException("EcPublicKeyBase::EcPublicKeyBase - The given PK context is not a EC Key.");
				}

				// Has public key?
				if(!_Base::HasPubKey(GetEcContextNoNullCheck()))
				{
					throw InvalidArgumentException("EcPublicKeyBase::EcPublicKeyBase - The given PK context contains no public key.");
				}
			}
			catch(...)
			{
				_Base::SwapBaseObject(other);
				throw;
			}
		}

		using _Base::GetPrivateDer;
		using _Base::GetPrivatePem;
	};


	template<typename _PKObjTrait = DefaultPKeyObjTrait,
			 enable_if_t<std::is_same<typename _PKObjTrait::CObjType, mbedtls_pk_context>::value, int> = 0>
	class EcKeyPairBase : public EcPublicKeyBase<_PKObjTrait>
	{
	public: // Types:

		using _Base = EcPublicKeyBase<_PKObjTrait>;

	public: // Static members:

		static void CompletePublicKey(mbedtls_ecp_keypair & ctx,
			std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>())
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcKeyPairBase::CompletePublicKey,
				mbedtls_ecp_mul,
				&ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G,
				&RbgInterface::CallBack, rand.get());
		}

		/**
		 * @brief	Constructs a new EC key pair, based on the given random source
		 *
		 * @param	type	Type of the ec.
		 * @param	rand   	The Random Bit Generator.
		 */
		static EcKeyPairBase Generate(EcType type, std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>())
		{
			return EcKeyPairBase(type, std::move(rand), (const void*)nullptr);
		}

		/**
		 * @brief	Move constructor that moves a general PKeyBase object to EC
		 *          Key pair. If it failed, the \c other will remain the same.
		 *
		 * @exception InvalidArgumentException Thrown when the given object is
		 *                                     not a EC private key.
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	other	The PKeyBase instance to convert.
		 */
		static EcKeyPairBase Convert(PKeyBase<_PKObjTrait>&& other)
		{
			return EcKeyPairBase(std::forward<PKeyBase<_PKObjTrait> >(other), (const void*)nullptr);
		}

		/**
		 * @brief Construct a EcKeyPairBase object (private part) from a given PEM string.
		 *
		 * @param pem PEM string in SecretString.
		 */
		static EcKeyPairBase FromPEM(const SecretString& pem)
		{
			return EcKeyPairBase(pem, (const void*)nullptr);
		}

		/**
		 * @brief Construct a EcKeyPairBase object (private part) from a given DER bytes.
		 *
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _SecCtnType>
		static EcKeyPairBase FromDER(const ContCtnReadOnlyRef<_SecCtnType, true>& der)
		{
			return EcKeyPairBase(der, (const void*)nullptr);
		}

	public:

		/**
		 * @brief Construct a new EcKeyPairBase object that borrows the C object.
		 *
		 * @tparam _dummy_Trait A dummy template parameter used to make sure
		 *                      the constructor is only available for borrowers.
		 * @param ptr pointer to the borrowed C object.
		 */
		template<typename _dummy_Trait = _PKObjTrait,
				 enable_if_t<_dummy_Trait::sk_isBorrower, int> = 0>
		EcKeyPairBase(mbedtls_pk_context* ptr) :
			_Base::EcPublicKeyBase(ptr)
		{
			if(!_Base::HasPrvKey(_Base::GetEcContextNoNullCheck()))
			{
				throw InvalidArgumentException("EcKeyPairBase::EcKeyPairBase - The given PK context contains no private key.");
			}
		}

		/**
		 * @brief	Move constructor
		 *
		 * @param	rhs	The right hand side.
		 */
		EcKeyPairBase(EcKeyPairBase&& rhs) noexcept :
			_Base::EcPublicKeyBase(std::forward<_Base>(rhs)) //noexcept
		{}

		/**
		 * @brief	Copy constructor
		 *
		 * @param	rhs	The right hand side.
		 */
		template<typename _rhs_Trait,
				 typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPairBase(const EcKeyPairBase<_rhs_Trait>& rhs, const void* = nullptr) :
			_Base::EcPublicKeyBase(rhs)
		{
			if(_Base::Get() != nullptr && _Base::Get()->pk_ctx != nullptr)
			{
				const auto& rhsEcCtx = rhs.GetEcContext();
				auto& ecCtx = _Base::GetEcContextNoNullCheck();

				MBEDTLSCPP_MAKE_C_FUNC_CALL(EcKeyPairBase::EcKeyPairBase,
					mbedtls_mpi_copy, &ecCtx.d, &rhsEcCtx.d);
			}
		}

		EcKeyPairBase(const EcKeyPairBase& rhs) :
			EcKeyPairBase(rhs, nullptr)
		{}

		/**
		 * @brief	Constructor from private key's R value.
		 *
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	type	The type of Elliptic Curve.
		 * @param	r	  	Elliptic Curve private key's R value.
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPairBase(EcType type, BigNum r,
				std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) :
			_Base::EcPublicKeyBase(type)
		{
			auto& ecCtx = _Base::GetEcContextNoNullCheck();
			BigNum tmpR(std::move(r));
			tmpR.SwapContent(ecCtx.d);

			CompletePublicKey(ecCtx, std::move(rand));
		}

		/**
		 * @brief	Constructor from private key's R value and public key's X, Y
		 *          and Z values (Z is default to 1).
		 * 			NOTE: this constructor does not check if the private and
		 *          public parts are matched!
		 *
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	type	The type of Elliptic Curve.
		 * @param	r	  	Elliptic Curve private key's R value.
		 * @param	x	  	Elliptic Curve public key's X value.
		 * @param	y	  	Elliptic Curve public key's Y value.
		 * @param	z	  	Elliptic Curve public key's Z value.
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPairBase(EcType type,
				BigNum r,
				BigNum x, BigNum y, BigNum z = BigNum(1)) :
			_Base::EcPublicKeyBase(type, std::move(x), std::move(y), std::move(z))
		{
			//NOTE: x, y, and z are invalid at this point.
			auto& ecCtx = _Base::GetEcContextNoNullCheck();
			BigNum tmpR(std::move(r));
			tmpR.SwapContent(ecCtx.d);

			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcKeyPairBase::EcKeyPairBase,
				mbedtls_ecp_check_privkey, &(ecCtx.grp), &(ecCtx.d));
		}

		virtual ~EcKeyPairBase()
		{}

		/**
		 * @brief	Copy assignment operator
		 *
		 * @tparam	_rhs_Trait	The object trait used by the right hand side.
		 * @param	rhs	The right hand side.
		 *
		 * @return	A reference to this object.
		 */
		template<typename _rhs_Trait,
				 typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPairBase& operator=(const EcKeyPairBase<_rhs_Trait>& rhs)
		{
			_Base::operator=(rhs);
			if (static_cast<const void*>(this) != static_cast<const void*>(&rhs))
			{
				if(_Base::Get() != nullptr && _Base::Get()->pk_ctx != nullptr)
				{
					const auto& rhsEcCtx = rhs.GetEcContext();
					auto& ecCtx = _Base::GetEcContextNoNullCheck();

					MBEDTLSCPP_MAKE_C_FUNC_CALL(EcKeyPairBase::EcKeyPairBase,
						mbedtls_mpi_copy, &ecCtx.d, &rhsEcCtx.d);
				}
			}
			return *this;
		}

		EcKeyPairBase& operator=(const EcKeyPairBase& rhs)
		{
			return operator=<_PKObjTrait>(rhs);
		}

		/**
		 * @brief	Move assignment operator
		 *
		 * @param	rhs	The right hand side.
		 *
		 * @return	A reference to this object.
		 */
		EcKeyPairBase& operator=(EcKeyPairBase&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
		}

		/**
		 * @brief	Gets PKey type (either public or private).
		 *
		 * @return	The PKey type.
		 */
		virtual PKeyType GetKeyType() const override
		{
			return PKeyType::Private;
		}

		/**
		 * @brief	Derive shared key
		 *
		 * @param  	pubKey	The public key.
		 * @param	rand   	The random bit generator.
		 *
		 * @return The share key in BigNum
		 */
		template<typename _pub_Trait>
		BigNum DeriveSharedKeyInBigNum(const EcPublicKeyBase<_pub_Trait>& pubKey,
				std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) const
		{
			const auto& ecCtx    = _Base::GetEcContext();
			const auto& pubEcCtx = pubKey.GetEcContext();
			EcGroup<> ecGrp = ecCtx.grp;
			BigNum res;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcKeyPairBase::DeriveSharedKeyInBigNum,
				mbedtls_ecdh_compute_shared, ecGrp.Get(), res.Get(),
				&(pubEcCtx.Q), &ecCtx.d,
				&RbgInterface::CallBack, rand.get());

			return res;
		}

		/**
		 * @brief	Derive shared key
		 *
		 * @param	pubKey	The public key.
		 * @param	rand	The random bit generator.
		 *
		 * @return The share key in bytes
		 */
		template<typename _pub_Trait>
		SecretVector<uint8_t> DeriveSharedKey(const EcPublicKeyBase<_pub_Trait>& pubKey,
				std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) const
		{
			BigNum skBigNum = DeriveSharedKeyInBigNum(pubKey, std::move(rand));

			return skBigNum.SecretBytes();
		}

		/**
		 * @brief	Make a signature.
		 *
		 * @tparam	_HashCtnType	Type of the container for the hash.
		 * @tparam	_HashSecrecy	Secrecy of the container for the hash.
		 * @param	hashType	The type of hash.
		 * @param	hash		The hash.
		 * @param	rand		The random bit generator.
		 * @return	A tuple of BigNum's. It's in the order of R and S value.
		 */
		template<typename _HashCtnType, bool _HashSecrecy>
		std::tuple<BigNum /* r */, BigNum /* s */> SignInBigNum(HashType hashType,
				const ContCtnReadOnlyRef<_HashCtnType, _HashSecrecy>& hash,
				std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) const
		{
			auto& ecCtx = _Base::GetEcContext();
			EcGroup<> ecGrp = ecCtx.grp;
			BigNum r;
			BigNum s;

#ifdef MBEDTLS_ECDSA_DETERMINISTIC
			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcKeyPairBase::SignInBigNum,
				mbedtls_ecdsa_sign_det, ecGrp.Get(), r.Get(), s.Get(), &ecCtx.d,
				static_cast<const unsigned char*>(hash.BeginPtr()), hash.GetRegionSize(),
				GetMbedTlsMdType(hashType));
#else
			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcKeyPairBase::SignInBigNum,
				mbedtls_ecdsa_sign, ecGrp.Get(), r.Get(), s.Get(), &ecCtx.d,
				static_cast<const unsigned char*>(hash.BeginPtr()), hash.GetRegionSize(),
				&RbgInterface::CallBack, rand.get());
#endif
			return std::make_tuple(r, s);
		}

		/**
		 * @brief	Make a signature.
		 *
		 * @tparam	_HashCtnType	Type of the container for the hash.
		 * @tparam	_HashSecrecy	Secrecy of the container for the hash.
		 * @param	hashType	The type of hash.
		 * @param	hash		The hash.
		 * @param	rand		The random bit generator.
		 * @return	A tuple of std::vector's. It's in the order of R and S value.
		 */
		template<typename _HashCtnType, bool _HashSecrecy>
		std::tuple<std::vector<uint8_t> /* r */, std::vector<uint8_t> /* s */> Sign(HashType hashType,
				const ContCtnReadOnlyRef<_HashCtnType, _HashSecrecy>& hash,
				std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) const
		{
			auto& ecCtx = _Base::GetEcContext();
			BigNum rBN;
			BigNum sBN;

			std::tie(rBN, sBN) = SignInBigNum(hashType, hash, std::move(rand));

			return std::make_tuple(rBN.Bytes(), sBN.Bytes());
		}

		using _Base::GetPublicDer;
		using _Base::GetPublicPem;
		using _Base::GetPrivateDer;
		using _Base::GetPrivatePem;

	protected:

		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPairBase(EcType type, std::unique_ptr<RbgInterface> rand, const void*) :
			_Base::EcPublicKeyBase()
		{
			mbedtls_ecp_keypair& ctx = _Base::GetEcContextNoNullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(EcKeyPairBase::EcKeyPairBase,
				mbedtls_ecp_gen_key, ToEcGroupId(type), &ctx, &RbgInterface::CallBack, rand.get());
		}

		/**
		 * @brief Construct a EcKeyPairBase object (private part) from a given PEM string.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is not available for borrowers.
		 * @param pem PEM string in SecretString.
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPairBase(const SecretString& pem, const void*) :
			_Base::EcPublicKeyBase(pem, nullptr)
		{}

		/**
		 * @brief Construct a EcKeyPairBase object (private part) from a given DER bytes.
		 *
		 * @tparam _dummy_PKTrait A dummy template parameter used to make sure
		 *                        the constructor is not available for borrowers.
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
				 typename ContainerType,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPairBase(const ContCtnReadOnlyRef<ContainerType, true>& der, const void*) :
			_Base::EcPublicKeyBase(der, nullptr)
		{}

		/**
		 * @brief	Move constructor that moves a general PKeyBase object to EC
		 *          Key pair. If it failed, the \c other will remain the same.
		 *
		 * @exception InvalidArgumentException Thrown when the given object is
		 *                                     not a EC private key.
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	other	The PKeyBase instance to convert.
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		explicit EcKeyPairBase(PKeyBase<_PKObjTrait>&& other, const void*) :
			_Base::EcPublicKeyBase(std::forward<PKeyBase<_PKObjTrait> >(other), (const void*)nullptr)
		{
			try
			{
				// Has private key?
				if(!_Base::HasPrvKey(_Base::GetEcContextNoNullCheck()))
				{
					throw InvalidArgumentException("EcKeyPairBase::EcKeyPairBase - The given PK context contains no private key.");
				}
			}
			catch(...)
			{
				_Base::SwapBaseObject(other);
				throw;
			}
		}
	};

	template<EcType _ecType, typename _PKObjTrait = DefaultPKeyObjTrait,
			 enable_if_t<std::is_same<typename _PKObjTrait::CObjType, mbedtls_pk_context>::value, int> = 0>
	class EcPublicKey : public EcPublicKeyBase<_PKObjTrait>
	{
	public: // Types and static members:

		using _Base = EcPublicKeyBase<_PKObjTrait>;

		/**
		 * @brief The EC type used by this class.
		 *
		 */
		static constexpr EcType sk_ecType = _ecType;

		/**
		 * @brief The size of the key in Bytes.
		 *
		 */
		static constexpr size_t sk_kSize = GetCurveByteSize(sk_ecType);

		/**
		 * @brief The size of the key in Bytes that fits the MPI array.
		 *
		 */
		static constexpr size_t sk_kSizeFitsMpi = GetCurveByteSizeFitsMpi(sk_ecType);

		/**
		 * @brief The type of array used to store the EC Key components (key,
		 *        signature, and shared secret).
		 *
		 */
		using KArray = std::array<uint8_t, sk_kSize>;

		/**
		 * @brief The type of array used to store the EC Key components (key,
		 *        signature, and shared secret).
		 *
		 */
		using KArrayFitsMPI = std::array<uint8_t, sk_kSizeFitsMpi>;

		/**
		 * @brief	Move constructor that moves a general PKeyBase object to EC
		 *          Key pair. If it failed, the \c other will remain the same.
		 *
		 * @exception InvalidArgumentException Thrown when the given object is
		 *                                     not a EC private key.
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	other	The PKeyBase instance to convert.
		 */
		static EcPublicKey Convert(PKeyBase<_PKObjTrait>&& other)
		{
			return EcPublicKey(std::forward<PKeyBase<_PKObjTrait> >(other), nullptr);
		}

		/**
		 * @brief Construct a EcPublicKey object (public part) from a given PEM string.
		 *
		 * @param pem PEM string in std::string
		 */
		static EcPublicKey FromPEM(const std::string& pem)
		{
			return EcPublicKey(pem, (const void*)nullptr);
		}

		/**
		 * @brief Construct a EcPublicKey object (public part) from a given DER bytes.
		 *
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _SecCtnType>
		static EcPublicKey FromDER(const ContCtnReadOnlyRef<_SecCtnType, false>& der)
		{
			return EcPublicKey(der, (const void*)nullptr);
		}

		/**
		 * @brief	Constructor from public key's X, Y and Z values. Z is default to 1.
		 *
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	x	Elliptic Curve public key's X value.
		 * @param	y	Elliptic Curve public key's Y value.
		 * @param	z	Elliptic Curve public key's Z value.
		 */
		static EcPublicKey FromBigNums(BigNum x, BigNum y, BigNum z = BigNum(1))
		{
			return EcPublicKey(std::move(x), std::move(y), std::move(z), (const void*)nullptr);
		}

		template<typename _CtnType>
		static EcPublicKey FromBytes(const ContCtnReadOnlyRef<_CtnType, false>& x,
					const ContCtnReadOnlyRef<_CtnType, false>& y,
					const ContCtnReadOnlyRef<_CtnType, false>& z)
		{
			return FromBigNums(BigNum(x, true, true), BigNum(y, true, true), BigNum(z, true, true));
		}

		template<typename _CtnType>
		static EcPublicKey FromBytes(const ContCtnReadOnlyRef<_CtnType, false>& x,
					const ContCtnReadOnlyRef<_CtnType, false>& y)
		{
			return FromBigNums(BigNum(x, true, true), BigNum(y, true, true));
		}

		static EcPublicKey FromBytes(const KArray& x, const KArray& y, const KArray& z)
		{
			return FromBytes(CtnFullR(x), CtnFullR(y), CtnFullR(z));
		}

		static EcPublicKey FromBytes(const KArray& x, const KArray& y)
		{
			return FromBytes(CtnFullR(x), CtnFullR(y));
		}

		static EcPublicKey FromBytes(const uint8_t(&x)[sk_kSize],
					const uint8_t(&y)[sk_kSize],
					const uint8_t(&z)[sk_kSize])
		{
			return FromBytes(CtnFullR(x), CtnFullR(y), CtnFullR(z));
		}

		static EcPublicKey FromBytes(const uint8_t(&x)[sk_kSize],
					const uint8_t(&y)[sk_kSize])
		{
			return FromBytes(CtnFullR(x), CtnFullR(y));
		}

	public:

		/**
		 * @brief Construct a new EcPublicKey object that borrows the C object.
		 *
		 * @tparam _dummy_Trait A dummy template parameter used to make sure
		 *                      the constructor is only available for borrowers.
		 * @param ptr pointer to the borrowed C object.
		 */
		template<typename _dummy_Trait = _PKObjTrait,
				 enable_if_t<_dummy_Trait::sk_isBorrower, int> = 0>
		EcPublicKey(mbedtls_pk_context* ptr) :
			_Base::EcPublicKeyBase(ptr)
		{
			if (ToEcType(_Base::GetEcContextNoNullCheck().grp.id) != sk_ecType)
			{
				throw InvalidArgumentException("EcPublicKey::EcPublicKey - The given EC Key context is not in the specified EC type.");
			}
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @exception None No exception thrown
		 * @param rhs The other EC public key instance.
		 */
		EcPublicKey(EcPublicKey&& rhs) noexcept :
			_Base::EcPublicKeyBase(std::forward<_Base>(rhs)) //noexcept
		{}

		/**
		 * @brief Copy Constructor.
		 *
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @tparam _dummy_Trait A dummy template parameter used to make sure
		 *                      the constructor is not available for borrowers.
		 * @param rhs The other EC public key instance.
		 */
		template<typename _other_Trait,
				 typename _dummy_Trait = _PKObjTrait,
				 enable_if_t<!_dummy_Trait::sk_isBorrower, int> = 0>
		EcPublicKey(const EcPublicKey<sk_ecType, _other_Trait>& rhs, const void* = nullptr) :
			_Base::EcPublicKeyBase(rhs, (const void*)nullptr)
		{}

		EcPublicKey(const EcPublicKey& rhs) :
			EcPublicKey(rhs, (const void*)nullptr)
		{}

		virtual ~EcPublicKey()
		{}

		/**
		 * @brief	Copy assignment operator
		 *
		 * @tparam	_rhs_Trait	The object trait used by the right hand side.
		 * @param	rhs	The right hand side.
		 *
		 * @return	A reference to this object.
		 */
		template<typename _rhs_Trait,
				 typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcPublicKey& operator=(const EcPublicKey<sk_ecType, _rhs_Trait>& rhs)
		{
			_Base::template operator=<_rhs_Trait>(rhs);
			return *this;
		}

		EcPublicKey& operator=(const EcPublicKey& rhs)
		{
			return operator=<_PKObjTrait>(rhs);
		}

		/**
		 * @brief	Move assignment operator
		 *
		 * @param	rhs	The right hand side.
		 *
		 * @return	A reference to this object.
		 */
		EcPublicKey& operator=(EcPublicKey&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
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
			_Base::NullCheck(typeid(EcPublicKey).name());
		}

		/**
		 * @brief	Gets Elliptic Curve type
		 *
		 * @return	The Elliptic Curve type.
		 */
		virtual EcType GetEcType() const
		{
			return sk_ecType;
		}

		using _Base::VerifySign;

		template<HashType _HashT>
		void VerifySign(const Hash<_HashT>& hash,
						const KArrayFitsMPI& r, const KArrayFitsMPI& s) const
		{
			return _Base::VerifySign(CtnFullR(hash), ConstBigNumber(CtnFullR(r)), ConstBigNumber(CtnFullR(s)));
		}

		template<// automated parts:
				 HashType _HashT,
				 typename _dummy_KArray = KArray,
				 enable_if_t<!std::is_same<KArrayFitsMPI, _dummy_KArray>::value, int> = 0>
		void VerifySign(const Hash<_HashT>& hash,
						const KArray& r, const KArray& s) const
		{
			return _Base::VerifySign(CtnFullR(hash), BigNum(CtnFullR(r)), BigNum(CtnFullR(s)));
		}

		std::tuple<KArray /*x*/, KArray /*y*/, KArray /*z*/>
			GetPublicBytes() const
		{
			NullCheck();
			_Base::PKeyContextNullCheck(*_Base::Get());

			const BigNumber<BorrowerBigNumTrait> xBN(&mbedtls_pk_ec(*_Base::MutableGet())->Q.X);
			const BigNumber<BorrowerBigNumTrait> yBN(&mbedtls_pk_ec(*_Base::MutableGet())->Q.Y);
			const BigNumber<BorrowerBigNumTrait> zBN(&mbedtls_pk_ec(*_Base::MutableGet())->Q.Z);

			KArray x{};
			KArray y{};
			KArray z{};

			std::memcpy(x.data(), xBN.Get()->p, xBN.GetSize());
			std::memcpy(y.data(), yBN.Get()->p, yBN.GetSize());
			std::memcpy(z.data(), zBN.Get()->p, zBN.GetSize());

			return std::make_tuple(x, y, z);
		}

	protected:

		template<typename _dummy_Trait = _PKObjTrait,
				 enable_if_t<!_dummy_Trait::sk_isBorrower, int> = 0>
		EcPublicKey(const std::string& pem, const void*) :
			_Base::EcPublicKeyBase(pem, (const void*)nullptr)
		{
			if (ToEcType(_Base::GetEcContextNoNullCheck().grp.id) != sk_ecType)
			{
				throw InvalidArgumentException("EcPublicKey::EcPublicKey - The given EC Key context is not in the specified EC type.");
			}
		}

		template<typename _dummy_Trait = _PKObjTrait,
				 typename ContainerType,
				 enable_if_t<!_dummy_Trait::sk_isBorrower, int> = 0>
		EcPublicKey(const ContCtnReadOnlyRef<ContainerType, false>& der, const void*) :
			_Base::EcPublicKeyBase(der, (const void*)nullptr)
		{
			if (ToEcType(_Base::GetEcContextNoNullCheck().grp.id) != sk_ecType)
			{
				throw InvalidArgumentException("EcPublicKey::EcPublicKey - The given EC Key context is not in the specified EC type.");
			}
		}

		/**
		 * @brief	Move constructor that moves a general PKeyBase object to EC
		 *          Key pair. If it failed, the \c other will remain the same.
		 *
		 * @exception InvalidArgumentException Thrown when the given object is
		 *                                     not a EC private key.
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	other	The PKeyBase instance to convert.
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		explicit EcPublicKey(PKeyBase<_PKObjTrait>&& other, const void*) :
			_Base::EcPublicKeyBase(std::forward<PKeyBase<_PKObjTrait> >(other), (const void*)nullptr) //noexcept
		{
			try
			{
				if (ToEcType(_Base::GetEcContextNoNullCheck().grp.id) != sk_ecType)
				{
					throw InvalidArgumentException("EcPublicKey::EcPublicKey - The given EC Key context is not in the specified EC type.");
				}
			}
			catch(...)
			{
				_Base::SwapBaseObject(other);
				throw;
			}
		}

		EcPublicKey(BigNum x, BigNum y, BigNum z, const void*) :
			_Base::EcPublicKeyBase(sk_ecType, std::move(x), std::move(y), std::move(z))
		{}

	};

	template<EcType _ecType, typename _PKObjTrait = DefaultPKeyObjTrait,
			 enable_if_t<std::is_same<typename _PKObjTrait::CObjType, mbedtls_pk_context>::value, int> = 0>
	class EcKeyPair : public EcKeyPairBase<_PKObjTrait>
	{
	public: // Types and static members:

		using _Base = EcKeyPairBase<_PKObjTrait>;

		/**
		 * @brief The EC type used by this class.
		 *
		 */
		static constexpr EcType sk_ecType = _ecType;

		/**
		 * @brief The size of the key in Bytes.
		 *
		 */
		static constexpr size_t sk_kSize = GetCurveByteSize(sk_ecType);

		/**
		 * @brief The size of the key in Bytes that fits the MPI array.
		 *
		 */
		static constexpr size_t sk_kSizeFitsMpi = GetCurveByteSizeFitsMpi(sk_ecType);

		/**
		 * @brief The type of array used to store the EC Key components (key,
		 *        signature, and shared secret).
		 *
		 */
		using KArray = std::array<uint8_t, sk_kSize>;

		/**
		 * @brief The type of array used to store the EC Key components (key,
		 *        signature, and shared secret).
		 *
		 */
		using KArrayFitsMPI = std::array<uint8_t, sk_kSizeFitsMpi>;

		/**
		 * @brief The type of array used to store the EC Key secret components (key,
		 *        signature, and shared secret).
		 *
		 */
		using KSecArray = SecretArray<uint8_t, sk_kSize>;

		static EcKeyPair Generate(std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>())
		{
			return EcKeyPair(std::move(rand));
		}

		/**
		 * @brief Construct a EcKeyPair object (private part) from a given PEM string.
		 *
		 * @param pem PEM string in SecretString.
		 */
		static EcKeyPair FromPEM(const SecretString& pem)
		{
			return EcKeyPair(pem, (const void*)nullptr);
		}

		/**
		 * @brief Construct a EcKeyPair object (private part) from a given DER bytes.
		 *
		 * @param der DER bytes referenced by ContCtnReadOnlyRef
		 */
		template<typename _SecCtnType>
		static EcKeyPair FromDER(const ContCtnReadOnlyRef<_SecCtnType, true>& der)
		{
			return EcKeyPair(der, (const void*)nullptr);
		}

		static EcKeyPair Convert(PKeyBase<_PKObjTrait>&& other)
		{
			return EcKeyPair(std::forward<PKeyBase<_PKObjTrait> >(other), (const void*)nullptr);
		}

		/**
		 * @brief	Constructor from private key's R value.
		 *
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	r		Elliptic Curve private key's R value.
		 * @param	rand	The random bit generator.
		 */
		static EcKeyPair FromBigNums(BigNum r,
				std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>())
		{
			return EcKeyPair(std::move(r), std::move(rand), (const void*)nullptr);
		}

		/**
		 * @brief	Constructor from private key's R value and public key's X, Y
		 *          and Z values (Z is default to 1).
		 * 			NOTE: this constructor does not check if the private and
		 *          public parts are matched!
		 *
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	r	  	Elliptic Curve private key's R value.
		 * @param	x	  	Elliptic Curve public key's X value.
		 * @param	y	  	Elliptic Curve public key's Y value.
		 * @param	z	  	Elliptic Curve public key's Z value.
		 */
		static EcKeyPair FromBigNums(BigNum r,
				BigNum x, BigNum y, BigNum z = BigNum(1))
		{
			return EcKeyPair(std::move(r), std::move(x), std::move(y), std::move(z), (const void*)nullptr);
		}

		template<typename _CtnType>
		static EcKeyPair FromBytes(const ContCtnReadOnlyRef<_CtnType, true>& r,
					std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>())
		{
			return FromBigNums(BigNum(r, true, true), std::move(rand));
		}

		static EcKeyPair FromBytes(const KSecArray& r,
					std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>())
		{
			return FromBytes(CtnFullR(r), std::move(rand));
		}

		template<typename _CtnType,
				 typename _SecCtnType>
		static EcKeyPair FromBytes(const ContCtnReadOnlyRef<_SecCtnType, true>& r,
					const ContCtnReadOnlyRef<_CtnType, false>& x,
					const ContCtnReadOnlyRef<_CtnType, false>& y,
					const ContCtnReadOnlyRef<_CtnType, false>& z)
		{
			return FromBigNums(BigNum(r, true, true),
				BigNum(x, true, true), BigNum(y, true, true), BigNum(z, true, true));
		}

		template<typename _CtnType,
				 typename _SecCtnType>
		static EcKeyPair FromBytes(const ContCtnReadOnlyRef<_SecCtnType, true>& r,
					const ContCtnReadOnlyRef<_CtnType, false>& x,
					const ContCtnReadOnlyRef<_CtnType, false>& y)
		{
			return FromBigNums(BigNum(r, true, true),
				BigNum(x, true, true), BigNum(y, true, true));
		}

		static EcKeyPair FromBytes(const KSecArray& r,
					const KArray& x, const KArray& y, const KArray& z)
		{
			return FromBytes(CtnFullR(r), CtnFullR(x), CtnFullR(y), CtnFullR(z));
		}

		static EcKeyPair FromBytes(const KSecArray& r,
					const KArray& x, const KArray& y)
		{
			return FromBytes(CtnFullR(r), CtnFullR(x), CtnFullR(y));
		}

	public:

		/**
		 * @brief Construct a new EcKeyPair object that borrows the C object.
		 *
		 * @tparam _dummy_Trait A dummy template parameter used to make sure
		 *                      the constructor is only available for borrowers.
		 * @param ptr pointer to the borrowed C object.
		 */
		template<typename _dummy_Trait = _PKObjTrait,
				 enable_if_t<_dummy_Trait::sk_isBorrower, int> = 0>
		EcKeyPair(mbedtls_pk_context* ptr) :
			_Base::EcKeyPairBase(ptr)
		{
			if (ToEcType(_Base::GetEcContextNoNullCheck().grp.id) != sk_ecType)
			{
				throw InvalidArgumentException("EcKeyPair::EcKeyPair - The given EC Key context is not in the specified EC type.");
			}
		}

		/**
		 * @brief	Move constructor
		 *
		 * @param	rhs	The right hand side.
		 */
		EcKeyPair(EcKeyPair&& rhs) noexcept :
			_Base::EcKeyPairBase(std::forward<_Base>(rhs)) //noexcept
		{}

		/**
		 * @brief	Copy constructor
		 *
		 * @param	rhs	The right hand side.
		 */
		template<typename _rhs_Trait,
				 typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPair(const EcKeyPair<sk_ecType, _rhs_Trait>& rhs, const void* = nullptr) :
			_Base::EcKeyPairBase(rhs, (const void*)nullptr)
		{}

		EcKeyPair(const EcKeyPair& rhs) :
			EcKeyPair(rhs, nullptr)
		{}

		virtual ~EcKeyPair()
		{}

		/**
		 * @brief	Copy assignment operator
		 *
		 * @tparam	_rhs_Trait	The object trait used by the right hand side.
		 * @param	rhs	The right hand side.
		 *
		 * @return	A reference to this object.
		 */
		template<typename _rhs_Trait,
				 typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPair& operator=(const EcKeyPair<sk_ecType, _rhs_Trait>& rhs)
		{
			_Base::template operator=<_rhs_Trait>(rhs);
			return *this;
		}

		EcKeyPair& operator=(const EcKeyPair& rhs)
		{
			return operator=<_PKObjTrait>(rhs);
		}

		/**
		 * @brief	Move assignment operator
		 *
		 * @param	rhs	The right hand side.
		 *
		 * @return	A reference to this object.
		 */
		EcKeyPair& operator=(EcKeyPair&& rhs) noexcept
		{
			_Base::operator=(std::forward<_Base>(rhs)); //noexcept

			return *this;
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
			_Base::NullCheck(typeid(EcKeyPair).name());
		}

		/**
		 * @brief	Gets Elliptic Curve type
		 *
		 * @return	The Elliptic Curve type.
		 */
		virtual EcType GetEcType() const
		{
			return sk_ecType;
		}

		using _Base::VerifySign;
		using _Base::GetPublicDer;
		using _Base::GetPublicPem;
		using _Base::GetPrivateDer;
		using _Base::GetPrivatePem;

		template<HashType _HashT>
		void VerifySign(const Hash<_HashT>& hash,
						const KArrayFitsMPI& r, const KArrayFitsMPI& s) const
		{
			return _Base::VerifySign(CtnFullR(hash), ConstBigNumber(CtnFullR(r)), ConstBigNumber(CtnFullR(s)));
		}

		template<// automated parts:
				 HashType _HashT,
				 typename _dummy_KArray = KArray,
				 enable_if_t<!std::is_same<KArrayFitsMPI, _dummy_KArray>::value, int> = 0>
		void VerifySign(const Hash<_HashT>& hash,
						const KArray& r, const KArray& s) const
		{
			return _Base::VerifySign(CtnFullR(hash), BigNum(CtnFullR(r)), BigNum(CtnFullR(s)));
		}

		/**
		 * @brief	Derive shared key
		 *
		 * @param	pubKey	The public key.
		 * @param	rand	The random bit generator.
		 *
		 * @return The share key in bytes
		 */
		template<typename _pub_Trait>
		KSecArray DeriveSharedKey(const EcPublicKeyBase<_pub_Trait>& pubKey,
				std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) const
		{
			BigNum skBigNum = _Base::DeriveSharedKeyInBigNum(pubKey, std::move(rand));

			KSecArray key;
			std::memcpy(key.data(), skBigNum.Get()->p, skBigNum.GetSize());
			return key;
		}

		/**
		 * @brief	Make a signature.
		 *
		 * @tparam	_HashT	The type of hash.
		 * @param	hash	The hash.
		 * @param	rand	The random bit generator.
		 * @return	A tuple of std::array's. It's in the order of R and S value.
		 */
		template<HashType _HashT>
		std::tuple<KArray /* r */, KArray /* s */> Sign(const Hash<_HashT>& hash,
				std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) const
		{
			auto& ecCtx = _Base::GetEcContext();
			BigNum rBN;
			BigNum sBN;

			std::tie(rBN, sBN) = _Base::SignInBigNum(_HashT, CtnFullR(hash), std::move(rand));

			KArray r{}; // initialize to zeros
			KArray s{};
			std::memcpy(r.data(), rBN.Get()->p, rBN.GetSize());
			std::memcpy(s.data(), sBN.Get()->p, sBN.GetSize());

			return std::make_tuple(r, s);
		}

		/**
		 * @brief	Make a signature.
		 *
		 * @tparam	_HashT	The type of hash.
		 * @param	hash	The hash.
		 * @param	rand	The random bit generator.
		 * @return	A tuple of std::array's. It's in the order of R and S value.
		 */
		template<HashType _HashT>
		std::tuple<KArrayFitsMPI /* r */, KArrayFitsMPI /* s */> SignFitsMPI(const Hash<_HashT>& hash,
				std::unique_ptr<RbgInterface> rand = Internal::make_unique<DefaultRbg>()) const
		{
			auto& ecCtx = _Base::GetEcContext();
			BigNum rBN;
			BigNum sBN;

			std::tie(rBN, sBN) = _Base::SignInBigNum(_HashT, CtnFullR(hash), std::move(rand));

			KArrayFitsMPI r{}; // initialize to zeros
			KArrayFitsMPI s{};
			std::memcpy(r.data(), rBN.Get()->p, rBN.GetSize());
			std::memcpy(s.data(), sBN.Get()->p, sBN.GetSize());

			return std::make_tuple(r, s);
		}

		std::tuple<KArray /*x*/, KArray /*y*/, KArray /*z*/>
			GetPublicBytes() const
		{
			NullCheck();
			_Base::PKeyContextNullCheck(*_Base::Get());

			const BigNumber<BorrowerBigNumTrait> xBN(&mbedtls_pk_ec(*_Base::MutableGet())->Q.X);
			const BigNumber<BorrowerBigNumTrait> yBN(&mbedtls_pk_ec(*_Base::MutableGet())->Q.Y);
			const BigNumber<BorrowerBigNumTrait> zBN(&mbedtls_pk_ec(*_Base::MutableGet())->Q.Z);

			KArray x{};
			KArray y{};
			KArray z{};

			std::memcpy(x.data(), xBN.Get()->p, xBN.GetSize());
			std::memcpy(y.data(), yBN.Get()->p, yBN.GetSize());
			std::memcpy(z.data(), zBN.Get()->p, zBN.GetSize());

			return std::make_tuple(x, y, z);
		}

		KSecArray GetPrivateBytes() const
		{
			NullCheck();
			_Base::PKeyContextNullCheck(*_Base::Get());

			const BigNumber<BorrowerBigNumTrait> rBN(&mbedtls_pk_ec(*_Base::MutableGet())->d);

			KSecArray r;

			std::memcpy(r.data(), rBN.Get()->p, rBN.GetSize());

			return r;
		}

	protected:

		/**
		 * @brief	Constructs a new EC key pair, based on the given random source
		 *
		 * @param	type	Type of the ec.
		 * @param	rand   	The Random Bit Generator.
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPair(std::unique_ptr<RbgInterface> rand) :
			_Base::EcKeyPairBase(sk_ecType, std::move(rand), (const void*)nullptr)
		{}

		/**
		 * @brief	Move constructor that moves a general PKeyBase object to EC
		 *          Key pair. If it failed, the \c other will remain the same.
		 *
		 * @exception InvalidArgumentException Thrown when the given object is
		 *                                     not a EC private key.
		 * @exception mbedTLSRuntimeError Thrown when mbed TLS C function call failed.
		 *
		 * @param	other	The PKeyBase instance to convert.
		 */
		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		explicit EcKeyPair(PKeyBase<_PKObjTrait>&& other, const void*) :
			_Base::EcKeyPairBase(std::forward<PKeyBase<_PKObjTrait> >(other), (const void*)nullptr) //noexcept
		{
			try
			{
				if (ToEcType(_Base::GetEcContextNoNullCheck().grp.id) != sk_ecType)
				{
					throw InvalidArgumentException("EcKeyPair::EcKeyPair - The given EC Key context is not in the specified EC type.");
				}
			}
			catch(...)
			{
				_Base::SwapBaseObject(other);
				throw;
			}
		}

		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPair(const SecretString& pem, const void*) :
			_Base::EcKeyPairBase(pem, (const void*)nullptr)
		{
			if (ToEcType(_Base::GetEcContextNoNullCheck().grp.id) != sk_ecType)
			{
				throw InvalidArgumentException("EcKeyPair::EcKeyPair - The given EC Key context is not in the specified EC type.");
			}
		}

		template<typename _dummy_PKTrait = _PKObjTrait,
				 typename ContainerType,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		EcKeyPair(const ContCtnReadOnlyRef<ContainerType, true>& der, const void*) :
			_Base::EcKeyPairBase(der, (const void*)nullptr)
		{
			if (ToEcType(_Base::GetEcContextNoNullCheck().grp.id) != sk_ecType)
			{
				throw InvalidArgumentException("EcKeyPair::EcKeyPair - The given EC Key context is not in the specified EC type.");
			}
		}

		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		explicit EcKeyPair(BigNum r, std::unique_ptr<RbgInterface> rand, const void*) :
			_Base::EcKeyPairBase(sk_ecType, std::move(r), std::move(rand))
		{}

		template<typename _dummy_PKTrait = _PKObjTrait,
				 enable_if_t<!_dummy_PKTrait::sk_isBorrower, int> = 0>
		explicit EcKeyPair(BigNum r, BigNum x, BigNum y, BigNum z, const void*) :
			_Base::EcKeyPairBase(sk_ecType, std::move(r), std::move(x), std::move(y), std::move(z))
		{}

	};
}
