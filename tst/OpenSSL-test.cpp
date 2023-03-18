#include "OpenSSL.h"

#include "gtest/gtest.h"
#include <filesystem>
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

struct CustomVerifyCallBacksTestSuite : public OpenSSLTestSuite
{

};

TEST_F(OpenSSLTestSuite, certSubjectMatches) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_subject(cert_x509.get());

    //assert
    EXPECT_EQ(result, "CN=raymii.org");
}


TEST_F(OpenSSLTestSuite, certSubjectEmptyOnNonExistingFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "notexist.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_subject(cert_x509.get());

    //assert
    EXPECT_EQ(result, "");
}

TEST_F(OpenSSLTestSuite, certSubjectEmptyOnGarbageFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "gibberish.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_subject(cert_x509.get());

    //assert
    EXPECT_EQ(result, "");
}

TEST_F(OpenSSLTestSuite, pointerEmptyOnNotExistingFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "notexist.pem");
    X509_uptr empty{nullptr};

    //act
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //assert
    EXPECT_EQ(cert_x509, empty);
}

TEST_F(OpenSSLTestSuite, pointerEmptyOnGarbageFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "gibberish.pem");
    X509_uptr empty{nullptr};

    //act
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //assert
    EXPECT_EQ(cert_x509, empty);
}

TEST_F(OpenSSLTestSuite, certIssuerMatches) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_issuer(cert_x509.get());

    //assert
    EXPECT_EQ(result, "C=GB,ST=Greater Manchester,L=Salford,O=Sectigo Limited,CN=Sectigo RSA Domain Validation Secure Server CA");
}


TEST_F(OpenSSLTestSuite, certIssuerEmptyOnNonExistingFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "notexist.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_issuer(cert_x509.get());

    //assert
    EXPECT_EQ(result, "");
}

TEST_F(OpenSSLTestSuite, certIssuerEmptyOnGarbageFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "gibberish.pem");
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //act
    std::string result = OpenSSL::x509_issuer(cert_x509.get());

    //assert
    EXPECT_EQ(result, "");
}


TEST_F(OpenSSLTestSuite, certSignedByIssuer) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(cert_pem, issuer_pem);
    
    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(OpenSSLTestSuite, issuerSignedByRoot) {
    //arrange
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");
    auto root_pem = readFile(dataPath / "USERTrust_RSA_Certification_Authority.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(issuer_pem, root_pem);

    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(OpenSSLTestSuite, nonExistingClientResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "notexist.pem");
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLTestSuite, garbageFileResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "gibberish.pem");
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLTestSuite, garbageIssuerFileResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto issuer_pem = readFile(dataPath / "garbage.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLTestSuite, nonExistingIssuerResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");
    auto issuer_pem = readFile(dataPath / "notexist.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}


TEST_F(OpenSSLTestSuite, issuerNotSignedByFakeRootWithSameSubject) {
    //arrange
    auto issuer_pem = readFile(dataPath / "Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem");
    auto root_pem = readFile(dataPath / "FAKE_USERTrust_RSA_Certification_Authority.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(issuer_pem, root_pem);

    //assert
    EXPECT_EQ(result, 0);
}


TEST_F(OpenSSLTestSuite, clientNotSignedByRoot) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto root_pem = readFile(dataPath / "USERTrust_RSA_Certification_Authority.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(cert_pem, root_pem);

    //assert
    EXPECT_EQ(result, 0);
}

TEST_F(OpenSSLTestSuite, certSignedByChain) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "Chain-Sectigo_UserTRUST_RSA.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(OpenSSLTestSuite, certChainHasMultipleSubjects) {
    //arrange
    auto chain_pem = readFile(dataPath / "Chain-Sectigo_UserTRUST_RSA.pem");
    auto chain = OpenSSL::certs_to_x509(chain_pem);

    //act & assert
    ASSERT_EQ(chain.size(), 2u);
    EXPECT_EQ(OpenSSL::x509_subject(chain[0].get()), "C=GB,ST=Greater Manchester,L=Salford,O=Sectigo Limited,CN=Sectigo RSA Domain Validation Secure Server CA");
    EXPECT_EQ(OpenSSL::x509_subject(chain[1].get()), "C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority");
}

TEST_F(OpenSSLTestSuite, invalidIntermidiateInChainFails) {
    //arrange
    auto chain_pem = readFile(dataPath / "chain-with-gibberish-intermidiate.pem");
    auto chain = OpenSSL::certs_to_x509(chain_pem);

    //act & assert
    ASSERT_EQ(chain.size(), 0u);
}


TEST_F(OpenSSLTestSuite, invalidRootInChainSkipsInvalidCertificate) {
    //arrange
    auto chain_pem = readFile(dataPath / "chain-with-gibberish-root.pem");
    auto chain = OpenSSL::certs_to_x509(chain_pem);

    //act & assert
    ASSERT_EQ(chain.size(), 1u);
    EXPECT_EQ(OpenSSL::x509_subject(chain[0].get()), "C=GB,ST=Greater Manchester,L=Salford,O=Sectigo Limited,CN=Sectigo RSA Domain Validation Secure Server CA");
}


TEST_F(OpenSSLTestSuite, certNotSignedByWrongChain) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "Chain-Staat_der_Nederlanden_Organisatie.pem");
    testing::internal::CaptureStderr();


    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, 0);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "\nunable to get local issuer certificate\n");
}

TEST_F(OpenSSLTestSuite, certNotSignedByEmptyChain) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = "";

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLTestSuite, certNotSignedByChainWithGibberishIntermidiate) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "chain-with-gibberish-intermidiate.pem");
    testing::internal::CaptureStderr();

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, 0);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "\nunable to get local issuer certificate\n");
}

TEST_F(OpenSSLTestSuite, certSignedCheckIgnoresGibberishRootWhenSignedByChainWithGibberishRoot) {
    //arrange
    auto cert_pem = readFile(dataPath / "raymii.org.2023.pem");
    auto chain_pem = readFile(dataPath / "chain-with-gibberish-root.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem, chain_pem);

    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(OpenSSLTestSuite, otherCertSignedOtherChain) {
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


TEST_F(CustomVerifyCallBacksTestSuite, expiredCertValidDueToParams) {
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

TEST_F(CustomVerifyCallBacksTestSuite, expiredBadSSLCertInvalid) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired.baddssl.com.cert.pem");
    auto chain_pem = readFile(dataPath / "expired.baddssl.com.chain.pem");
    testing::internal::CaptureStderr();

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem,
                                                      chain_pem);

    //assert
    EXPECT_EQ(result, 0);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "\ncertificate has expired\n");
}

TEST_F(CustomVerifyCallBacksTestSuite, expiredBadSSLWithExpiredChainCertValidDueToParams) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired.baddssl.com.cert.pem");
    auto chain_pem = readFile(dataPath / "expired.baddssl.com.chain.pem");

    X509_VERIFY_PARAM_uptr param(X509_VERIFY_PARAM_new());
    X509_VERIFY_PARAM_set_flags(param.get(), X509_V_FLAG_NO_CHECK_TIME);

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem,
                                                      chain_pem,
                                                      param.get());

    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(CustomVerifyCallBacksTestSuite, expiredCertInvalid) {
    //arrange
    auto cert_pem = readFile(dataPath / "expired-rsa-dv-ssl-com.pem");
    auto chain_pem = readFile(dataPath / "expired-rsa-dv-ssl-com-chain.pem");
    testing::internal::CaptureStderr();

    //act
    int result = OpenSSL::verify_cert_signed_by_chain(cert_pem,
                                                      chain_pem);

    //assert
    EXPECT_EQ(result, 0);
    EXPECT_EQ(testing::internal::GetCapturedStderr(), "\ncertificate has expired\n");
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
};

TEST_F(OpenSSLTestSuite, certSANMatches) {
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

TEST_F(OpenSSLTestSuite, FourSansMatches) {
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

