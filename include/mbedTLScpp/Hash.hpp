#pragma once

#include "ObjectBase.hpp"

#include <mbedtls/md.h>

#include "Common.hpp"
#include "Container.hpp"
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
	 * @param type The type of the hash
	 * @return constexpr uint8_t The size in bytes
	 */
	inline constexpr uint8_t GetHashByteSize(HashType type)
	{
		switch (type)
		{
		case HashType::SHA224:
			return (224 / gsk_bitsPerByte);
		case HashType::SHA256:
			return (256 / gsk_bitsPerByte);
		case HashType::SHA384:
			return (384 / gsk_bitsPerByte);
		case HashType::SHA512:
			return (512 / gsk_bitsPerByte);
		default:
			throw InvalidArgumentException("Hash type given is not supported.");
		}
	}

	/**
	 * @brief The container type used to store the hash result (for a known hash type).
	 *
	 * @tparam _HashTypeValue The type of the hash.
	 */
	template<HashType _HashTypeValue>
	using Hash = std::array<uint8_t, GetHashByteSize(_HashTypeValue)>;

	/** @brief	Message Digest Base class. It will be further inherited by the
	 *          hash calculator and HMAC calculator.
	 */
	class MsgDigestBase : public ObjectBase<mbedtls_md_context_t>
	{
	public: // static members:
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
		MsgDigestBase(MsgDigestBase&& rhs) :
			ObjectBase(std::forward<ObjectBase>(rhs))
		{}

		MsgDigestBase(const MsgDigestBase& rhs) = delete;

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other MsgDigestBase instance.
		 * @return MsgDigestBase& A reference to this instance.
		 */
		MsgDigestBase& operator=(MsgDigestBase&& rhs)
		{
			ObjectBase::operator=(std::forward<ObjectBase>(rhs));

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

	class HasherBase : public MsgDigestBase
	{
	public:

		HasherBase() = delete;

		/**
		 * @brief	Constructor. mbedtls_md_starts is called here.
		 *
		 * @param	mdInfo	Information describing the md.
		 */
		HasherBase(const mbedtls_md_info_t& mdInfo)  :
			MsgDigestBase(mdInfo, false)
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::HasherBase, mbedtls_md_starts, Get());
		}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other HasherBase instance.
		 */
		HasherBase(HasherBase&& rhs) :
			MsgDigestBase(std::forward<MsgDigestBase>(rhs))
		{}

		HasherBase(const HasherBase& rhs) = delete;

		/** @brief	Destructor */
		virtual ~HasherBase()
		{}

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other HasherBase instance.
		 * @return HasherBase& A reference to this instance.
		 */
		HasherBase& operator=(HasherBase&& rhs)
		{
			MsgDigestBase::operator=(std::forward<MsgDigestBase>(rhs));

			return *this;
		}

		HasherBase& operator=(const HasherBase& other) = delete;

		/**
		 * @brief Updates the calculation with the given data.
		 *
		 *
		 * @exception InvalidObjectException Thrown when the current instance is
		 *                                   holding a null pointer for the C mbed TLS
		 *                                   object.
		 * @tparam ContainerType The type of the container that stores the data.
		 * @param data The data to be hashed.
		 */
		template<typename ContainerType>
		void Update(ContCtnReadOnlyRef<ContainerType> data)
		{
			NullCheck();

			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::Update, mbedtls_md_update,
				Get(),
				static_cast<const unsigned char*>(data.BeginPtr()),
				data.GetRegionSize());
		}

		/**
		 * @brief Finishes the hash calculation and get the hash result.
		 *
		 * @return std::vector<uint8_t> The hash result.
		 */
		std::vector<uint8_t> Finish()
		{
			NullCheck();

			const size_t size = mbedtls_md_get_size(Get()->md_info);
			std::vector<uint8_t> hash(size);

			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::Finish, mbedtls_md_finish,
				Get(),
				static_cast<unsigned char*>(hash.data()));

			return hash;
		}

		/**
		 * @brief Restart the hash calculation, so that the previous hash state
		 *        will be wiped out. It's useful if you want to reuse the same
		 *        hasher instance.
		 *
		 */
		void Restart()
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::HasherBase, mbedtls_md_starts, Get());
		}

	protected:

		void Update(const void* data, size_t size)
		{
			MBEDTLSCPP_MAKE_C_FUNC_CALL(HasherBase::Update, mbedtls_md_update,
				Get(),
				static_cast<const unsigned char*>(data),
				size);
		}
	};


	template<HashType _HashTypeValue>
	class Hasher : public HasherBase
	{
	public: //static members:
		static constexpr size_t sk_hashByteSize = GetHashByteSize(_HashTypeValue);

	public:

		/**
		 * @brief Construct a new Hasher object
		 *
		 */
		Hasher() :
			HasherBase(MsgDigestBase::GetMdInfo(_HashTypeValue))
		{}

		/**
		 * @brief Destroy the Hasher object
		 *
		 */
		virtual ~Hasher()
		{}

		/**
		 * @brief Move Constructor. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other Hasher instance.
		 */
		Hasher(Hasher&& rhs) :
			HasherBase(std::forward<HasherBase>(rhs))
		{}

		Hasher(const Hasher& rhs) = delete;

		/**
		 * @brief Move assignment. The `rhs` will be empty/null afterwards.
		 *
		 * @param rhs The other Hasher instance.
		 * @return Hasher& A reference to this instance.
		 */
		Hasher& operator=(Hasher&& rhs)
		{
			HasherBase::operator=(std::forward<HasherBase>(rhs));

			return *this;
		}

		Hasher& operator=(const Hasher& other) = delete;

		/**
		 * @brief Finishes the hash calculation and get the hash result.
		 *
		 * @return Hash<_HashTypeValue> The hash result.
		 */
		Hash<_HashTypeValue> Finish()
		{
			NullCheck();

			return FinishNoCheck();
		}

		/**
		 * @brief Update the hash calculation with a list of Input Data Items.
		 *        NOTE: This function will not clean the previous state, thus,
		 *        it will update the calculation state based on the existing state;
		 *        Thus, you may need to call restart first.
		 *
		 * @tparam ListLen The length of the list.
		 * @param list The list of Input Data Items.
		 * @return Hash<_HashTypeValue> The hash result.
		 */
		template<size_t ListLen>
		Hash<_HashTypeValue> CalcList(const InDataList<ListLen>& list)
		{
			NullCheck();

			for(auto it = list.begin(); it != list.end(); ++it)
			{
				Update(it->m_data, it->m_size);
			}

			return FinishNoCheck();
		}

		/**
		 * @brief Update the hash calculation with a sequence of containers wrapped
		 *        by ContCtnReadOnlyRef. The sequence of containers can be in any
		 *        length.
		 *        NOTE: This function will not clean the previous state, thus,
		 *        it will update the calculation state based on the existing state;
		 *        Thus, you may need to call restart first.
		 *
		 * @tparam Args The type of the container wrapped by ContCtnReadOnlyRef
		 * @param args The container.
		 * @return Hash<_HashTypeValue> The hash result.
		 */
		template<class... Args>
		Hash<_HashTypeValue> Calc(ContCtnReadOnlyRef<Args>... args)
		{
			return CalcList(ConstructInDataList(args...));
		}

	private:

		Hash<_HashTypeValue> FinishNoCheck()
		{
			Hash<_HashTypeValue> hash;

			MBEDTLSCPP_MAKE_C_FUNC_CALL(Hasher::Finish, mbedtls_md_finish,
				Get(),
				static_cast<unsigned char*>(hash.data()));

			return hash;
		}
	};
}
