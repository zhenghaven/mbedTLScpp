#pragma once

#include <gtest/gtest.h>

#include <mbedTLScpp/PKey.hpp>

#include "MemoryTest.hpp"

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
using namespace mbedTLScpp;
#else
using namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE;
#endif

constexpr char const gsk_testRsaPrvKeyPem[] =
"-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEA2FiPF+t37wkwYtCBOCw6kSkNUhjUVabYHfymnw6tlRnL1f9A\n\
adUOepU6l8l89ggZOk39ITV42eGPQITSkJTeQX5Yu9AyiabDA1zw4852mzSeupfG\n\
btt8kOGptEhJiR8DJ0iqzQtpf8F235waTSPpQJpj3tpV27rEHCrH1XLUkakNdyqe\n\
q/iJfShkEGDvz1YstwvqPAnJ+7hGEQjjPqSwi+PAW/luRmB0oCctgGCMCcex2Q4u\n\
l8metcrSFxX/Qnn40GXtJg9cditlI9VBW7qh7AHC12tX60QQ3eSymzMSAkZ9Tx32\n\
oXroYbLpx5RsisqMDRHjn5zpL1zVXPD2h8A2GQIDAQABAoIBAEmvN+VMtId8WLd/\n\
DlPEdJoWIkxQ2pjlf3wPHezUgfhjVdJn4ldpUkob413pKR9euMDr6QfTf3qt4S13\n\
T4Qgv+YMk0o8acoKOyc9E2pzWmAYNuuUX+hH5xAtW7BkYm9KWbeaf1ngxijWCpe0\n\
Qhz92ya+rr8rG8z/umVhiLhBKPcGvWe7I7FpITJuUMPZS5yIc8vP5ijBJ8Th+tgA\n\
4J6Ca8S+ZRnkmxw2ke0XBOV4+jw+nlZLHmm8CalF2rDLO5B5Y7bknamBCtafpM9V\n\
FVMOwD3nEgAbu11T0BP20Sf1LwYDKNsrQk7W2VMzbHD77r9RUaEkPC39UNPm8n5J\n\
HyNr7CUCgYEA9y8Bccx3wYoCzN+yk1wZlHREXU1wAgszs/L6verZutt9jp766eJK\n\
W2+knfEAbGgEelL6Fvdzn+CdXQqHZA13eC8j+I37ulTmtdMVJfqRg6Cf3A+65tiE\n\
GueE5YIRojLmzqUVR4p25NMakcTA6VMNEgrENrNVq61+Cn1qT1vyNHMCgYEA4A/6\n\
tZykBLTLnSb0ZaxXGIzfc8jRchT+AgVUzJ8ZEnCkGxhZKxKCxvjUGw1XV3XlLnPo\n\
BSyhmyzCtDl1itgZiqOd0ODOHZv4RfMnKPf9JIavZhWIVEA74++HRrH/Th+QI/FQ\n\
BAoxByVwQ3/v/kQXbcE60RULgv7fq8oYRTJOlEMCgYALab41VO2KoCa08vc52pzL\n\
v/qQHE05qu6+Nk/hiQB4oj3P4gNP3UT1p9f/+uq8FqluRHqLqO1LyoE5lIzfz8de\n\
Yz7T8SpYVic46gAl+sXRQA9hh9BnbEPdQideuXy68oK5s+GhpgELW7v0UxNdMpp9\n\
5MVeiTVBcgdJ0LSh6WrrhQKBgCR6tYjH/fQ+M0BczUGYc32twduqAF+gh1Jw58OA\n\
y6Yy7KT0q9/VXbFjZbUZ0PSOX0fW2xmskIshGHobOMXoNRBbXyBY2XX8pMlOszt6\n\
VJ6Txw7Jxq5g3t9XaiDabgScIu2XJj3iIuVU9RgoRjyRfXcDFL5hvMQRFv1zI8xw\n\
SlbdAoGBAOnDJyQRfDM9eOhTNO3bgguUD9CTJWFQJzlp4qHp5Yea0HTFPbr0Z1dO\n\
r0KEC9t8KA+yoMeifY6uyd1UEfKmrKY7AM1VppyXGlpufNGOgspVRw52VIZhCyS+\n\
fgSawAz3GzVc/BcnNFluEYrOceknXKvsYddO9+TQYsevcc9DuaqB\n\
-----END RSA PRIVATE KEY-----";

constexpr char const gsk_testRsaPubKeyPem[] =
"-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2FiPF+t37wkwYtCBOCw6\n\
kSkNUhjUVabYHfymnw6tlRnL1f9AadUOepU6l8l89ggZOk39ITV42eGPQITSkJTe\n\
QX5Yu9AyiabDA1zw4852mzSeupfGbtt8kOGptEhJiR8DJ0iqzQtpf8F235waTSPp\n\
QJpj3tpV27rEHCrH1XLUkakNdyqeq/iJfShkEGDvz1YstwvqPAnJ+7hGEQjjPqSw\n\
i+PAW/luRmB0oCctgGCMCcex2Q4ul8metcrSFxX/Qnn40GXtJg9cditlI9VBW7qh\n\
7AHC12tX60QQ3eSymzMSAkZ9Tx32oXroYbLpx5RsisqMDRHjn5zpL1zVXPD2h8A2\n\
GQIDAQAB\n\
-----END PUBLIC KEY-----";

constexpr char const gsk_testEcPrvKeyPem[] =
"-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEII9EZBewDxmA897ermQ6CpJCOBHCCeuaXq84lKOvtdsioAoGCCqGSM49\n\
AwEHoUQDQgAEC9Q2XVZB4d72yiB/niSHfDus6eyi0u+dkh7pehMIj9qAF3v7Gui1\n\
vw97xFXyvab2u/JOD6cTcgLYwqMCwC05hg==\n\
-----END EC PRIVATE KEY-----";

constexpr char const gsk_testEcPubKeyPem[] =
"-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC9Q2XVZB4d72yiB/niSHfDus6eyi\n\
0u+dkh7pehMIj9qAF3v7Gui1vw97xFXyvab2u/JOD6cTcgLYwqMCwC05hg==\n\
-----END PUBLIC KEY-----";


GTEST_TEST(TestPKey, PKeyBaseClass)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrvPem1 = SecretString(gsk_testRsaPrvKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> rsaPrvPem2 = SecretString(gsk_testRsaPrvKeyPem);

		// after successful initialization, we should have its allocation remains.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		rsaPrvPem1 = std::move(rsaPrvPem1);

		// Nothing moved, allocation should stay the same.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		rsaPrvPem1 = std::move(rsaPrvPem2);

		// Moved, allocation should reduce.
		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		// Moved to initialize new one, allocation should remain the same.
		PKeyBase<> rsaPrvPem3(std::move(rsaPrvPem1));

		// This should success.
		rsaPrvPem3.NullCheck();

		//mdBase1.NullCheck();
		EXPECT_THROW(rsaPrvPem1.NullCheck(), InvalidObjectException);
		EXPECT_THROW(rsaPrvPem2.NullCheck(), InvalidObjectException);
	}

	// Finally, all allocation should be cleaned after exit.
	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestPKey, PemParse)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrvPem1 = SecretString(gsk_testRsaPrvKeyPem);

		EXPECT_EQ(rsaPrvPem1.GetAlgmCat(), PKeyAlgmCat::RSA);
		EXPECT_EQ(rsaPrvPem1.GetKeyType(), PKeyType::Private);
		EXPECT_TRUE(rsaPrvPem1.HasPrvKey());
		EXPECT_TRUE(rsaPrvPem1.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> rsaPubPem1 = std::string(gsk_testRsaPubKeyPem);

		EXPECT_EQ(rsaPubPem1.GetAlgmCat(), PKeyAlgmCat::RSA);
		EXPECT_EQ(rsaPubPem1.GetKeyType(), PKeyType::Public);
		EXPECT_FALSE(rsaPubPem1.HasPrvKey());
		EXPECT_TRUE(rsaPubPem1.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPrvPem1 = SecretString(gsk_testEcPrvKeyPem);

		EXPECT_EQ(ecPrvPem1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ecPrvPem1.GetKeyType(), PKeyType::Private);
		EXPECT_TRUE(ecPrvPem1.HasPrvKey());
		EXPECT_TRUE(ecPrvPem1.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 3);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPubPem1 = std::string(gsk_testEcPubKeyPem);

		EXPECT_EQ(ecPubPem1.GetAlgmCat(), PKeyAlgmCat::EC);
		EXPECT_EQ(ecPubPem1.GetKeyType(), PKeyType::Public);
		EXPECT_FALSE(ecPubPem1.HasPrvKey());
		EXPECT_TRUE(ecPubPem1.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestPKey, DerGeneration)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrv1 = SecretString(gsk_testRsaPrvKeyPem);
		PKeyBase<> rsaPrv2 = CtnFullR(rsaPrv1.GetPrivateDer());

		EXPECT_EQ(rsaPrv1.GetAlgmCat(), rsaPrv2.GetAlgmCat());
		EXPECT_EQ(rsaPrv1.GetKeyType(), rsaPrv2.GetKeyType());
		EXPECT_EQ(rsaPrv1.HasPrvKey(),  rsaPrv2.HasPrvKey());
		EXPECT_EQ(rsaPrv1.HasPubKey(),  rsaPrv2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> rsaPub1 = std::string(gsk_testRsaPubKeyPem);
		PKeyBase<> rsaPub2 = CtnFullR(rsaPub1.GetPublicDer());
		EXPECT_THROW(rsaPub1.GetPrivateDer();, mbedTLSRuntimeError);

		EXPECT_EQ(rsaPub1.GetAlgmCat(), rsaPub2.GetAlgmCat());
		EXPECT_EQ(rsaPub1.GetKeyType(), rsaPub2.GetKeyType());
		EXPECT_EQ(rsaPub1.HasPrvKey(),  rsaPub2.HasPrvKey());
		EXPECT_EQ(rsaPub1.HasPubKey(),  rsaPub2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPrv1 = SecretString(gsk_testEcPrvKeyPem);
		PKeyBase<> ecPrv2 = CtnFullR(ecPrv1.GetPrivateDer());

		EXPECT_EQ(ecPrv1.GetAlgmCat(), ecPrv2.GetAlgmCat());
		EXPECT_EQ(ecPrv1.GetKeyType(), ecPrv2.GetKeyType());
		EXPECT_EQ(ecPrv1.HasPrvKey(),  ecPrv2.HasPrvKey());
		EXPECT_EQ(ecPrv1.HasPubKey(),  ecPrv2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 6);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPub1 = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> ecPub2 = CtnFullR(ecPub1.GetPublicDer());
		EXPECT_THROW(ecPub1.GetPrivateDer();, mbedTLSRuntimeError);

		EXPECT_EQ(ecPub1.GetAlgmCat(), ecPub2.GetAlgmCat());
		EXPECT_EQ(ecPub1.GetKeyType(), ecPub2.GetKeyType());
		EXPECT_EQ(ecPub1.HasPrvKey(),  ecPub2.HasPrvKey());
		EXPECT_EQ(ecPub1.HasPubKey(),  ecPub2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 8);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestPKey, PemGeneration)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;
	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrv1 = SecretString(gsk_testRsaPrvKeyPem);
		PKeyBase<> rsaPrv2 = rsaPrv1.GetPrivatePem();

		EXPECT_EQ(rsaPrv1.GetAlgmCat(), rsaPrv2.GetAlgmCat());
		EXPECT_EQ(rsaPrv1.GetKeyType(), rsaPrv2.GetKeyType());
		EXPECT_EQ(rsaPrv1.HasPrvKey(),  rsaPrv2.HasPrvKey());
		EXPECT_EQ(rsaPrv1.HasPubKey(),  rsaPrv2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> rsaPub1 = std::string(gsk_testRsaPubKeyPem);
		PKeyBase<> rsaPub2 = rsaPub1.GetPublicPem();
		EXPECT_THROW(rsaPub1.GetPrivatePem();, mbedTLSRuntimeError);

		EXPECT_EQ(rsaPub1.GetAlgmCat(), rsaPub2.GetAlgmCat());
		EXPECT_EQ(rsaPub1.GetKeyType(), rsaPub2.GetKeyType());
		EXPECT_EQ(rsaPub1.HasPrvKey(),  rsaPub2.HasPrvKey());
		EXPECT_EQ(rsaPub1.HasPubKey(),  rsaPub2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPrv1 = SecretString(gsk_testEcPrvKeyPem);
		PKeyBase<> ecPrv2 = ecPrv1.GetPrivatePem();

		EXPECT_EQ(ecPrv1.GetAlgmCat(), ecPrv2.GetAlgmCat());
		EXPECT_EQ(ecPrv1.GetKeyType(), ecPrv2.GetKeyType());
		EXPECT_EQ(ecPrv1.HasPrvKey(),  ecPrv2.HasPrvKey());
		EXPECT_EQ(ecPrv1.HasPubKey(),  ecPrv2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 6);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		PKeyBase<> ecPub1 = std::string(gsk_testEcPubKeyPem);
		PKeyBase<> ecPub2 = ecPub1.GetPublicPem();
		EXPECT_THROW(ecPub1.GetPrivatePem();, mbedTLSRuntimeError);

		EXPECT_EQ(ecPub1.GetAlgmCat(), ecPub2.GetAlgmCat());
		EXPECT_EQ(ecPub1.GetKeyType(), ecPub2.GetKeyType());
		EXPECT_EQ(ecPub1.HasPrvKey(),  ecPub2.HasPrvKey());
		EXPECT_EQ(ecPub1.HasPubKey(),  ecPub2.HasPubKey());

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 8);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}

GTEST_TEST(TestPKey, SignAndVerifySign)
{
	int64_t initCount = 0;
	int64_t initSecCount = 0;

	Hash<HashType::SHA256> testHash = Hasher<HashType::SHA256>().Calc(CtnFullR("TestString"));

	MEMORY_LEAK_TEST_GET_COUNT(initCount);
	SECRET_MEMORY_LEAK_TEST_GET_COUNT(initSecCount);

	{
		PKeyBase<> rsaPrv1 = SecretString(gsk_testRsaPrvKeyPem);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 1);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		auto rsaSign1 = rsaPrv1.DerSign<HashType::SHA256>(testHash);
		auto rsaSign2 = rsaPrv1.DerSign(HashType::SHA256, CtnFullR(testHash));
		rsaPrv1.VerifyDerSign<HashType::SHA256>(testHash, CtnFullR(rsaSign1));
		rsaPrv1.VerifyDerSign(HashType::SHA256, CtnFullR(testHash), CtnFullR(rsaSign2));

		PKeyBase<> rsaPub1 = std::string(gsk_testRsaPubKeyPem);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 2);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_THROW(rsaPub1.DerSign<HashType::SHA256>(testHash);, mbedTLSRuntimeError);
		EXPECT_THROW(rsaPub1.DerSign(HashType::SHA256, CtnFullR(testHash));, mbedTLSRuntimeError);
		rsaPub1.VerifyDerSign<HashType::SHA256>(testHash, CtnFullR(rsaSign1));
		rsaPub1.VerifyDerSign(HashType::SHA256, CtnFullR(testHash), CtnFullR(rsaSign2));

		PKeyBase<> ecPrv1 = SecretString(gsk_testEcPrvKeyPem);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 3);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		auto ecSign1 = ecPrv1.DerSign<HashType::SHA256>(testHash);
		auto ecSign2 = ecPrv1.DerSign(HashType::SHA256, CtnFullR(testHash));
		ecPrv1.VerifyDerSign<HashType::SHA256>(testHash, CtnFullR(ecSign1));
		ecPrv1.VerifyDerSign(HashType::SHA256, CtnFullR(testHash), CtnFullR(ecSign2));

		PKeyBase<> ecPub1 = std::string(gsk_testEcPubKeyPem);

		MEMORY_LEAK_TEST_INCR_COUNT(initCount, 4);
		SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);

		EXPECT_THROW(ecPub1.DerSign<HashType::SHA256>(testHash);, mbedTLSRuntimeError);
		EXPECT_THROW(ecPub1.DerSign(HashType::SHA256, CtnFullR(testHash));, mbedTLSRuntimeError);
		ecPub1.VerifyDerSign<HashType::SHA256>(testHash, CtnFullR(ecSign1));
		ecPub1.VerifyDerSign(HashType::SHA256, CtnFullR(testHash), CtnFullR(ecSign2));
	}

	MEMORY_LEAK_TEST_INCR_COUNT(initCount, 0);
	SECRET_MEMORY_LEAK_TEST_INCR_COUNT(initSecCount, 0);
}
