/*
 * Copyright (c) 2023 Remy van Elst
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include "gtest/gtest.h"
#include <filesystem>

#define private public
#include "OpenSSL.h"
#undef private

namespace fs = std::filesystem;

struct OpenSSLTestSuite : public ::testing::Test
{
    fs::path dataPath = fs::path(__FILE__).parent_path() / "data/";
    OpenSSLTestSuite() = default;
    ~OpenSSLTestSuite() override = default;

   static std::string readFile(const fs::path& filename) {
       if(!fs::exists(filename))
           return "";

       std::ifstream in(filename);
       std::string out((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
       return out;
   }
};


struct OpenSSLWrappersTestSuite : public OpenSSLTestSuite
{
/* Tests related to the modern C++ wrappers,
 * unique_ptrs, TYPE_dup(), STACK_OF(), etc. */
};

struct OpenSSLChainTestSuite : public OpenSSLTestSuite
{
/* Tests related to methods that validate a single
 * certificate against a chain containing multiple
 * intermediate certificates. */
};

struct CustomVerifyCallBacksTestSuite : public OpenSSLChainTestSuite
{
/* Tests related to custom verify callbacks */
};

struct CustomParametersTestSuite : public OpenSSLChainTestSuite
{
/* Tests related to validation with custom parameters */
};

struct OpenSSLOneIntermediateTestSuite : public OpenSSLTestSuite
{
/* Tests related to the methods that validate a single
 * certificate against a single issuer */
};

struct OpenSSLDGSTSuite : public OpenSSLTestSuite
{
/* Tests related to methods that sign / verify */
};


struct OpenSSLDataGatheringTestSuite : public OpenSSLTestSuite
{
/* Tests related to certificate data parsing, like subject,
 * issuer, subjectAlternativeNames. */
};

TEST_F(OpenSSLDataGatheringTestSuite, certSubjectMatches) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_subject(cert_x509.get());

    //assert
    EXPECT_EQ(result, "CN=raymii.org");
}

TEST_F(OpenSSLDataGatheringTestSuite, certSubjectEmptyOnNonExistingFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "notexist.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_subject(cert_x509.get());

    //assert
    EXPECT_EQ(result, "");
}

TEST_F(OpenSSLDataGatheringTestSuite, certSubjectEmptyOnGarbageFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "gibberish.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_subject(cert_x509.get());

    //assert
    EXPECT_EQ(result, "");
}

TEST_F(OpenSSLWrappersTestSuite, pointerEmptyOnNotExistingFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "notexist.pem");
    X509_uptr empty{nullptr};

    //act
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //assert
    EXPECT_EQ(cert_x509, empty);
}


TEST_F(OpenSSLWrappersTestSuite, stackOfX509CorrectCountAndData) {
    //arrange
    auto cert_pem = readFile(dataPath / "Chain-Sectigo_UserTRUST_RSA.pem");
    int expectedSize = 2;
    testing::internal::CaptureStderr();

    //act
    auto stack_of_x509_certs = OpenSSL::certs_to_stack_of_x509(cert_pem);

    int actualSize = sk_X509_num(stack_of_x509_certs.get());
    for (int i = 0; i < actualSize; i++) {
        X509* si = sk_X509_value(stack_of_x509_certs.get(), i);
        std::cerr << "i: " << i << "; subject: " << OpenSSL::x509_subject(si) << std::endl;
        std::cerr << "i: " << i << "; issuer : " << OpenSSL::x509_issuer(si)<< std::endl;
    }

    //assert
    EXPECT_EQ(actualSize, expectedSize);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "i: 0; subject: C=GB,ST=Greater Manchester,L=Salford,O=Sectigo Limited,CN=Sectigo RSA Domain Validation Secure Server CA\ni: 0; issuer : C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority\ni: 1; subject: C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority\ni: 1; issuer : C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority\n");
}

TEST_F(OpenSSLWrappersTestSuite, ErrorIfEmpty) {
    //arrange
    auto cert_pem = readFile(dataPath / "notexist.pem");
    int expectedSize = -1;

    //act
    auto stack_of_x509_certs = OpenSSL::certs_to_stack_of_x509(cert_pem);
    int actualSize = sk_X509_num(stack_of_x509_certs.get());

    //assert
    EXPECT_EQ(actualSize, expectedSize);
}

TEST_F(OpenSSLWrappersTestSuite, pointerEmptyOnGarbageFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "gibberish.pem");
    X509_uptr empty{nullptr};

    //act
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //assert
    EXPECT_EQ(cert_x509, empty);
}

TEST_F(OpenSSLDataGatheringTestSuite, certIssuerMatches) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_issuer(cert_x509.get());

    //assert
    EXPECT_EQ(result, "C=GB,ST=Greater Manchester,L=Salford,O=Sectigo Limited,CN=Sectigo RSA Domain Validation Secure Server CA");
}


TEST_F(OpenSSLDataGatheringTestSuite, certIssuerEmptyOnNonExistingFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "notexist.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_issuer(cert_x509.get());

    //assert
    EXPECT_EQ(result, "");
}

TEST_F(OpenSSLDataGatheringTestSuite, certIssuerEmptyOnGarbageFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "gibberish.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_issuer(cert_x509.get());

    //assert
    EXPECT_EQ(result, "");
}


TEST_F(OpenSSLOneIntermediateTestSuite, certSignedByIssuer) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(cert_pem, issuer_pem);
    
    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(OpenSSLOneIntermediateTestSuite, issuerSignedByRoot) {
    //arrange
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");
    auto root_pem = readFile(dataPath / "USERTrust_RSA_Certification_Authority.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(issuer_pem, root_pem);

    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(OpenSSLOneIntermediateTestSuite, nonExistingClientResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "notexist.pem");
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLOneIntermediateTestSuite, garbageFileResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "gibberish.pem");
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLOneIntermediateTestSuite, garbageIssuerFileResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto issuer_pem = readFile(dataPath / "garbage.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLOneIntermediateTestSuite, nonExistingIssuerResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");
    auto issuer_pem = readFile(dataPath / "notexist.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}


TEST_F(OpenSSLOneIntermediateTestSuite, issuerNotSignedByFakeRootWithSameSubject) {
    //arrange
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");
    auto root_pem = readFile(dataPath / "FAKE_USERTrust_RSA_Certification_Authority.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(issuer_pem, root_pem);

    //assert
    EXPECT_EQ(result, 0);
}


TEST_F(OpenSSLOneIntermediateTestSuite, clientNotSignedByRoot) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto root_pem = readFile(dataPath / "USERTrust_RSA_Certification_Authority.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(cert_pem, root_pem);

    //assert
    EXPECT_EQ(result, 0);
}

TEST_F(OpenSSLChainTestSuite, certSignedByChain) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "Chain-Sectigo_UserTRUST_RSA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, 1);
}


TEST_F(OpenSSLChainTestSuite, emptyCertResultsInError) {
    //arrange
    auto cert_pem = readFile(dataPath / "notexist.pem");
    auto chain_pem = readFile(dataPath / "Chain-Sectigo_UserTRUST_RSA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLWrappersTestSuite, certChainHasMultipleSubjects) {
    //arrange
    auto chain_pem = readFile(dataPath / "Chain-Sectigo_UserTRUST_RSA.pem");
    auto chain = OpenSSL::certs_to_x509(chain_pem);

    //act & assert
    ASSERT_EQ(chain.size(), 2u);
    EXPECT_EQ(OpenSSL::x509_subject(chain[0].get()), "C=GB,ST=Greater Manchester,L=Salford,O=Sectigo Limited,CN=Sectigo RSA Domain Validation Secure Server CA");
    EXPECT_EQ(OpenSSL::x509_subject(chain[1].get()), "C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority");
}

TEST_F(OpenSSLWrappersTestSuite, invalidIntermidiateInChainFails) {
    //arrange
    auto chain_pem = readFile(dataPath / "chain-with-gibberish-intermidiate.pem");
    auto chain = OpenSSL::certs_to_x509(chain_pem);

    //act & assert
    ASSERT_EQ(chain.size(), 0u);
}


TEST_F(OpenSSLWrappersTestSuite, invalidRootInChainSkipsInvalidCertificate) {
    //arrange
    auto chain_pem = readFile(dataPath / "chain-with-gibberish-root.pem");
    auto chain = OpenSSL::certs_to_x509(chain_pem);

    //act & assert
    ASSERT_EQ(chain.size(), 1u);
    EXPECT_EQ(OpenSSL::x509_subject(chain[0].get()), "C=GB,ST=Greater Manchester,L=Salford,O=Sectigo Limited,CN=Sectigo RSA Domain Validation Secure Server CA");
}


TEST_F(OpenSSLWrappersTestSuite, emptyPEMResultsInEmptyString) {
    //arrange
    auto chain = OpenSSL::certs_to_x509("");

    //act & assert
    ASSERT_TRUE(chain.empty());
}

TEST_F(OpenSSLChainTestSuite, certNotSignedByWrongChain) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "Chain-Staat_der_Nederlanden_Organisatie.pem");
    testing::internal::CaptureStderr();


    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, 0);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "unable to get local issuer certificate; ");
}

TEST_F(OpenSSLChainTestSuite, certNotSignedByEmptyChain) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = "";

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLChainTestSuite, certNotSignedByChainWithGibberishIntermidiate) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "chain-with-gibberish-intermidiate.pem");
    testing::internal::CaptureStderr();

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, 0);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "unable to get local issuer certificate; ");
}

TEST_F(OpenSSLChainTestSuite, certSignedCheckFailsWhenChainWithGibberishRootProvided) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "chain-with-gibberish-root.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, 0);
}

TEST_F(OpenSSLChainTestSuite, otherCertSignedOtherChain) {
    //arrange
    auto cert_pem = readFile(dataPath / "Digidentity_BV_PKIoverheid_Organisatie_Persoon_CA_G3.pem");
    auto chain_pem = readFile(dataPath / "Chain-Staat_der_Nederlanden_Organisatie.pem");
    testing::internal::CaptureStderr();
    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, 1);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "");
}


TEST_F(CustomParametersTestSuite, expiredCertValidDueToParams) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired-rsa-dv-ssl-com.pem");
    auto chain_pem = readFile(dataPath / "expired-rsa-dv-ssl-com-chain.pem");

    X509_VERIFY_PARAM_uptr param(X509_VERIFY_PARAM_new());
    X509_VERIFY_PARAM_set_flags(param.get(), X509_V_FLAG_NO_CHECK_TIME);

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem,
                                                      chain_pem,
                                                      param.get());

    //assert
    EXPECT_EQ(result, 1);
};

TEST_F(OpenSSLChainTestSuite, expiredBadSSLCertInvalid) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired.baddssl.com.cert.pem");
    auto chain_pem = readFile(dataPath / "expired.baddssl.com.chain.pem");
    testing::internal::CaptureStderr();

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem,
                                                      chain_pem);

    //assert
    EXPECT_EQ(result, 0);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "certificate has expired; ");
}

TEST_F(CustomParametersTestSuite, expiredBadSSLWithExpiredChainCertValidDueToParams) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired.baddssl.com.cert.pem");
    auto chain_pem = readFile(dataPath / "expired.baddssl.com.chain.pem");

    X509_VERIFY_PARAM_uptr param(X509_VERIFY_PARAM_new());
    X509_VERIFY_PARAM_set_flags(param.get(), X509_V_FLAG_NO_CHECK_TIME);

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem,
                                                      param.get());

    //assert
    EXPECT_EQ(result, 1);
}


TEST_F(CustomParametersTestSuite, signedByPartialChainAllowed) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "Incomplete-Chain-Sectigo_UserTRUST_RSA.pem");

    //    https://github.com/openssl/openssl/issues/7871
    //    https://github.com/curl/curl/pull/4655
    X509_VERIFY_PARAM_uptr param(X509_VERIFY_PARAM_new());
    X509_VERIFY_PARAM_set_flags(param.get(), X509_V_FLAG_PARTIAL_CHAIN);

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem,
                                                      param.get());

    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(OpenSSLChainTestSuite, expiredCertInvalid) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired-rsa-dv-ssl-com.pem");
    auto chain_pem = readFile(dataPath / "expired-rsa-dv-ssl-com-chain.pem");
    testing::internal::CaptureStderr();

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem,chain_pem);

    //assert
    EXPECT_EQ(result, 0);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "certificate has expired; ");
}

TEST_F(CustomVerifyCallBacksTestSuite, expiredCertValidDueToCustomVerifyCallback) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired-rsa-dv-ssl-com.pem");
    auto chain_pem = readFile(dataPath / "expired-rsa-dv-ssl-com-chain.pem");
    testing::internal::CaptureStderr();

    auto verify_callback_accept_exipred = [](int ok, X509_STORE_CTX *ctx) {
        /* Tolerate certificate expiration */
        if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_HAS_EXPIRED)
            return 1;
        /* Otherwise don't override */
        return ok;
    };


    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem,
                                                      chain_pem,
                                                      verify_callback_accept_exipred);

    //assert
    EXPECT_EQ(result, 1);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "");
}



TEST_F(CustomVerifyCallBacksTestSuite, expiredCertPartialChainINVALIDEvenThoughExpiredIsAllowedInCallBack) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired-rsa-dv-ssl-com.pem");
    auto chain_pem = readFile(dataPath / "INCOMPLETE-expired-rsa-dv-ssl-com-chain.pem");
    testing::internal::CaptureStderr();

    auto verify_callback_accept_exipred = [](int ok, X509_STORE_CTX *ctx) {
        /* Tolerate certificate expiration */
        if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_HAS_EXPIRED)
            return 1;
        /* Otherwise don't override */
        return ok;
    };

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem,
                                                      chain_pem,
                                                      verify_callback_accept_exipred);

    //assert
    EXPECT_EQ(result, 0);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "unable to get issuer certificate; ");
}

TEST_F(CustomVerifyCallBacksTestSuite, expiredCertPartialChainValidDueToCustomVerifyCallbackAndParameter) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired-rsa-dv-ssl-com.pem");
    auto chain_pem = readFile(dataPath / "expired-rsa-dv-ssl-com-chain.pem");
    testing::internal::CaptureStderr();

    auto verify_callback_accept_exipred = [](int ok, X509_STORE_CTX *ctx) {
        /* Tolerate certificate expiration */
        if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_HAS_EXPIRED)
            return 1;
        /* Otherwise don't override */
        return ok;
    };

    X509_VERIFY_PARAM_uptr param(X509_VERIFY_PARAM_new());
    X509_VERIFY_PARAM_set_flags(param.get(), X509_V_FLAG_PARTIAL_CHAIN);

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem,
                                                      chain_pem,
                                                      param.get(),
                                                      verify_callback_accept_exipred);

    //assert
    EXPECT_EQ(result, 1);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "");
}

TEST_F(OpenSSLDataGatheringTestSuite, certSANMatches) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    auto result = OpenSSL::x509_subject_alternative_dns_names(cert_x509.get());

    //assert
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "raymii.org");
    EXPECT_EQ(result[1], "www.raymii.org");
}

TEST_F(OpenSSLDataGatheringTestSuite, FourSansMatches) {
    //arrange
    auto cert_pem = readFile(dataPath / "example.org.crt");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    auto result = OpenSSL::x509_subject_alternative_dns_names(cert_x509.get());

    //assert
    ASSERT_EQ(result.size(), 5);
    EXPECT_EQ(result[0], "example.org");
    EXPECT_EQ(result[1], "www.example.org");
    EXPECT_EQ(result[2], "ex.example.org");
    EXPECT_EQ(result[3], "www.ex.example.org");
}

TEST_F(OpenSSLDataGatheringTestSuite, noSANS) {
    //arrange
    auto cert_pem = readFile(dataPath / "Staat_der_Nederlanden_Organisatie_Persoon_CA_G3.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    auto result = OpenSSL::x509_subject_alternative_dns_names(cert_x509.get());

    //assert
    ASSERT_EQ(result.size(), 0);
}



TEST_F(OpenSSLTestSuite, certNotSignedByFakeChain) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "FAKE-Chain-Sectigo_UserTRUST_RSA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, -1);
}



TEST_F(OpenSSLDGSTSuite, getPubKeyFromCert) {
    //arrange
    // openssl x509 -in raymii.org.2023.pem -pubkey -noout
    auto expected_pubkey_pem =
            "-----BEGIN PUBLIC KEY-----\n"
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvz5LrA5t1Bv4qzJX++bQ\n"
            "myR0eYPpBe/rgzEh5EhGDPoT6Jd1gtA59VaIPHrkag0eOY3xclko3TPSo5CftGMg\n"
            "aQWa8/ho8fChS5sjClucanMSz74+J0O9GE0Gw0WmchXwnUDaPr0U18VA5Mj5mw+x\n"
            "3cJ9YHZpZZkh3q7XP1X52MRF735eFVXAaRcuxrXUYf9+CcEZ9ahdU/rtP192uFsR\n"
            "phYYDWFk5Z5BscyykCLgiaQlwqs5pDQNEBt2I4WKzmUy8bXRRHQC4IKu8X1rbDQb\n"
            "8O7V64Vd0qimLDMKi+CA+jtvinC7mhkVOC8FG6oZgsR0xrIR4FY78yADXDHl53Qj\n"
            "iUmLeWO0hfNTANf+GGuNo1qcVXpbJVRFvJ1HpTScp8c92+GVmSgqz4EICHH92yFw\n"
            "m+lOyHdbj77RtqPDThSPFvhgKQhwSbzhvai3Jnsg0Jf0ZsUm/KJGrMQNFWD4cGSw\n"
            "xPn/MWsLGGFGQgLSuw6RoylKHTWUETlPFKd/ALXETstWZ/CEOjD6+Qj1Bvy9Gphr\n"
            "FryZrCMK7fvdsBjnDP5OMcdeNgewGF89aqW55bjTkOfMISBb1rRdYKfW8N0aA7hS\n"
            "3hW3gYwMRFo4xyZL4+oRg9/oM0JcKGwuKaZqjaFDucNipD2GFDsdkm7ZYj8CIxJ7\n"
            "yvTL4A1x2xHNrg7fmnt1GHUCAwEAAQ==\n"
            "-----END PUBLIC KEY-----\n";

    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto cert = OpenSSL::cert_to_x509(cert_pem);

    //act
    auto result = OpenSSL::x509_to_evp_pubkey(cert.get());
    auto resultString = OpenSSL::x509_to_public_key_pem(cert.get());


    //assert
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(resultString, expected_pubkey_pem);
}


TEST_F(OpenSSLDGSTSuite, gibberishResultsInEmptyPubkey) {
    //arrange
    auto cert_pem = readFile(dataPath / "gibberish.pem");
    auto cert = OpenSSL::cert_to_x509(cert_pem);

    //act
    auto result = OpenSSL::x509_to_evp_pubkey(cert.get());
    auto resultString = OpenSSL::x509_to_public_key_pem(cert.get());


    //assert
    ASSERT_EQ(result, nullptr);
    EXPECT_EQ(resultString, "");
}


TEST_F(OpenSSLDGSTSuite, base64Decode) {
    //arrange
    auto encoded_input = "UmVteSBpcyBkZSBiZXN0ZQ==";
    auto expected_decoded_output = "Remy is de beste";

    //act
    auto result = OpenSSL::base64_decode(encoded_input);

    //assert
    EXPECT_EQ(result, expected_decoded_output);
}


TEST_F(OpenSSLDGSTSuite, base64Encode) {
    //arrange
    std::string decoded_input = "Remy is de beste!!!";
    std::string expected_encoded_output = "UmVteSBpcyBkZSBiZXN0ZSEhIQ==";

    //act
    std::string result = OpenSSL::base64_encode(decoded_input);

    //assert
    EXPECT_EQ(result, expected_encoded_output);
}



TEST_F(OpenSSLDGSTSuite, multiLineBase64Decode) {
    //arrange
    auto encoded_input = "UmVteSBpcy\n"
                                   "BkZSBiZXN0ZQ==";
    auto expected_decoded_output = "Remy is de beste";

    //act
    auto result = OpenSSL::base64_decode(encoded_input);

    //assert
    EXPECT_EQ(result, expected_decoded_output);
}

TEST_F(OpenSSLDGSTSuite, base64BinaryEncode) {
    //arrange
    auto decoded_input = OpenSSL::read_binary_file(dataPath / "raymii.org.2023.der");
    std::string decoded_string(decoded_input.data(), decoded_input.size());
    // coreutils base64 -w 0 raymii.org.2023.der:
    auto expected_encoded_output = "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";

    //act
    auto result = OpenSSL::base64_encode(decoded_string);

    //assert
    EXPECT_EQ(result, expected_encoded_output);
}


TEST_F(OpenSSLDGSTSuite, base64BinaryDecode) {
    //arrange
    std::string encoded_input ("MIIHLjCCBhagAwIBAgIQcAuZ3LmvyqD6VkaeqMrkszANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdvIFJTQSBEb21haW4gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMB4XDTIzMDEwODAwMDAwMFoXDTI0MDEyNDIzNTk1OVowFTETMBEGA1UEAxMKcmF5bWlpLm9yZzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL8+S6wObdQb+KsyV/vm0JskdHmD6QXv64MxIeRIRgz6E+iXdYLQOfVWiDx65GoNHjmN8XJZKN0z0qOQn7RjIGkFmvP4aPHwoUubIwpbnGpzEs++PidDvRhNBsNFpnIV8J1A2j69FNfFQOTI+ZsPsd3CfWB2aWWZId6u1z9V+djERe9+XhVVwGkXLsa11GH/fgnBGfWoXVP67T9fdrhbEaYWGA1hZOWeQbHMspAi4ImkJcKrOaQ0DRAbdiOFis5lMvG10UR0AuCCrvF9a2w0G/Du1euFXdKopiwzCovggPo7b4pwu5oZFTgvBRuqGYLEdMayEeBWO/MgA1wx5ed0I4lJi3ljtIXzUwDX/hhrjaNanFV6WyVURbydR6U0nKfHPdvhlZkoKs+BCAhx/dshcJvpTsh3W4++0bajw04Ujxb4YCkIcEm84b2otyZ7INCX9GbFJvyiRqzEDRVg+HBksMT5/zFrCxhhRkIC0rsOkaMpSh01lBE5TxSnfwC1xE7LVmfwhDow+vkI9Qb8vRqYaxa8mawjCu373bAY5wz+TjHHXjYHsBhfPWqlueW405DnzCEgW9a0XWCn1vDdGgO4Ut4Vt4GMDERaOMcmS+PqEYPf6DNCXChsLimmao2hQ7nDYqQ9hhQ7HZJu2WI/AiMSe8r0y+ANcdsRza4O35p7dRh1AgMBAAGjggL9MIIC+TAfBgNVHSMEGDAWgBSNjF7EVK2K4Xfpm/mbBeG4AY1h4TAdBgNVHQ4EFgQUXqg5HcIH3nzbUZfLW8F4/n9sWc4wDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMEkGA1UdIARCMEAwNAYLKwYBBAGyMQECAgcwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQIBMIGEBggrBgEFBQcBAQR4MHYwTwYIKwYBBQUHMAKGQ2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1JTQURvbWFpblZhbGlkYXRpb25TZWN1cmVTZXJ2ZXJDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMCUGA1UdEQQeMByCCnJheW1paS5vcmeCDnd3dy5yYXltaWkub3JnMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdwB2/4g/Crb7lVHCYcz1h7o0tKTNuyncaEIKn+ZnTFo6dAAAAYWRTHPqAAAEAwBIMEYCIQCeYN9L9aWzXyXUP2c0xyWjdOZznUI8mvzFTqS+qWKezQIhAIbgggrtQo3d2bKl8nCOzGZXx/W8NaRBvEj/df59jXkxAHYA2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6sAAAGFkUxzvQAABAMARzBFAiEAj5GVP8VEdj61cP9opFkiGBoi2uOXbN6slDOink0rzOQCIFaE6d9Poif0Ms16BnHpaWA+FfdeVK/3u30xDobBMdmfAHYA7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZsAAAGFkUxziQAABAMARzBFAiBN96pJVZ3kpOiJOqdrm6xjIpoQ61lgJIYHW+j3Yd7GgQIhANxgtntpgYEIDOS+G8D4/KkcoqYYaGhh1mIhnd5T4ZS0MA0GCSqGSIb3DQEBCwUAA4IBAQChWuF/uOnEmzmiCo8BWbf3PALgevmDaPmy6PcdxfIWg8TR2PsOAmIVkv3YxiKvJYBdtiLXliFvPdsaojk5mwRKayPehUgJgzawfrVIPxMUPMPCt9ULGVN8PnkeosvG1gNjw6JuYDrxYooBy1zV3RtZXQfQhSb96R27wuCEECr871AuH0Cott0HBjiwxEndICgdbUJf4n4e5rs2Z5QWnssc1ZD6OpofWnW//1bG6JILTegNbDX163JBLEVxAmj6lLsbTfGaoJSTAtGDYOF7zRMuNDgQnw9+dIE6nTmOMI72x7Mnx1/LrD//LMlfN0kZgjbupuLLn6D6MjP2UyKpahqc");
    auto binfile = OpenSSL::read_binary_file(dataPath / "raymii.org.2023.der");
    std::string expected_decoded_output(binfile.data(), binfile.size());

    //act
    auto result = OpenSSL::base64_decode(encoded_input);

    //assert
    EXPECT_EQ(result, expected_decoded_output);
}


TEST_F(OpenSSLDGSTSuite, base64DecodeEmpty) {
    EXPECT_EQ(OpenSSL::base64_decode(""), "");
}


TEST_F(OpenSSLDGSTSuite, base64EncodeEmpty) {
    EXPECT_EQ(OpenSSL::base64_encode(""), "");;
}



TEST_F(OpenSSLDGSTSuite, verifyHashCorrect) {
    // arrange
    //openssl dgst -sha256 -sign tst_sign.key -out sign.txt.sha256 sign.txt
    //openssl dgst -sha256 -verify  <(openssl x509 -in tst_sign.crt  -pubkey -noout) -signature sign.txt.sha256 sign.txt
    //Verified OK
    //base64 sign.txt.sha256 > sign.txt.sha256.txt

    std::string message = readFile(dataPath / "sign.txt");
    std::string base64_encoded_signature = readFile(dataPath / "sign.txt.sha256.txt");
    X509_uptr cert_with_pubkey_that_signed_message = OpenSSL::cert_to_x509(readFile(dataPath / "tst_sign.crt"));

    // act
    int result = OpenSSL::verify_sha256_digest_signature(message, base64_encoded_signature, cert_with_pubkey_that_signed_message.get());

    // assert
    EXPECT_EQ(result, 1);
}


TEST_F(OpenSSLDGSTSuite, verifyTamperedDataFails) {
    // arrange
    std::string message = readFile(dataPath / "sign-tampered.txt");
    std::string base64_encoded_signature = readFile(dataPath / "sign.txt.sha256.txt");
    X509_uptr cert_with_pubkey_that_signed_message = OpenSSL::cert_to_x509(readFile(dataPath / "tst_sign.crt"));

    // act
    int result = OpenSSL::verify_sha256_digest_signature(message, base64_encoded_signature, cert_with_pubkey_that_signed_message.get());

    // assert
    EXPECT_EQ(result, 0);
}


TEST_F(OpenSSLDGSTSuite, verifyOtherCertificateFails) {
    // arrange
    std::string message = readFile(dataPath / "sign.txt");
    std::string base64_encoded_signature = readFile(dataPath / "sign.txt.sha256.txt");
    X509_uptr cert_with_pubkey_that_signed_message = OpenSSL::cert_to_x509(readFile(dataPath / "raymii.org.2023.pem"));

    // act
    int result = OpenSSL::verify_sha256_digest_signature(message, base64_encoded_signature, cert_with_pubkey_that_signed_message.get());

    // assert
    EXPECT_EQ(result, 0);
}

TEST_F(OpenSSLDGSTSuite, verifyTamperedSignatureFails) {
    // arrange
    std::string message = readFile(dataPath / "sign-tampered.txt");
    std::string base64_encoded_signature = readFile(dataPath / "sign.tampered.sha256.txt");
    X509_uptr cert_with_pubkey_that_signed_message = OpenSSL::cert_to_x509(readFile(dataPath / "tst_sign.crt"));

    // act
    int result = OpenSSL::verify_sha256_digest_signature(message, base64_encoded_signature, cert_with_pubkey_that_signed_message.get());

    // assert
    EXPECT_EQ(result, 0);
}

TEST_F(OpenSSLDGSTSuite, emptyMessageResultsInError) {
    // arrange
    std::string message;
    std::string base64_encoded_signature = readFile(dataPath / "sign.txt.sha256.txt");
    X509_uptr cert_with_pubkey_that_signed_message = OpenSSL::cert_to_x509(readFile(dataPath / "tst_sign.crt"));

    // act
    int result = OpenSSL::verify_sha256_digest_signature(message, base64_encoded_signature, cert_with_pubkey_that_signed_message.get());

    // assert
    EXPECT_EQ(result, -1);
}


TEST_F(OpenSSLDGSTSuite, emptySignatureResultsInError) {
    // arrange
    std::string message = readFile(dataPath / "sign.txt");
    std::string base64_encoded_signature;
    X509_uptr cert_with_pubkey_that_signed_message = OpenSSL::cert_to_x509(readFile(dataPath / "tst_sign.crt"));

    // act
    int result = OpenSSL::verify_sha256_digest_signature(message, base64_encoded_signature, cert_with_pubkey_that_signed_message.get());

    // assert
    EXPECT_EQ(result, -1);
}


TEST_F(OpenSSLDGSTSuite, emptyCertResultsInError) {
    // arrange
    std::string message = readFile(dataPath / "sign.txt");
    std::string base64_encoded_signature = readFile(dataPath / "sign.txt.sha256.txt");
    X509_uptr cert_with_pubkey_that_signed_message = nullptr;

    // act
    int result = OpenSSL::verify_sha256_digest_signature(message, base64_encoded_signature, cert_with_pubkey_that_signed_message.get());

    // assert
    EXPECT_EQ(result, -1);
}
