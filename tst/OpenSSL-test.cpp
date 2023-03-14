#include "OpenSSL.h"

#include "gtest/gtest.h"
#include <filesystem>
namespace fs = std::filesystem;


struct OpenSSLTestSuite : public ::testing::Test
{

    fs::path dataPath = fs::path(__FILE__).parent_path() / "data/";
    OpenSSLTestSuite() = default;
    ~OpenSSLTestSuite() override = default;

   std::string readFile(const fs::path& filename) {
       if(!fs::exists(filename))
           return "";

       std::ifstream in(filename);
       std::string out((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
       return out;
   }


};


TEST_F(OpenSSLTestSuite, certSubjectMatches) {
    //arrange
    auto cert_pem = readFile(dataPath / "cert.pem");
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
    X509_uptr empty{nullptr, ::X509_free};

    //act
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //assert
    EXPECT_EQ(cert_x509, empty);
}

TEST_F(OpenSSLTestSuite, pointerEmptyOnGarbageFile) {
    //arrange
    auto cert_pem = readFile(dataPath / "gibberish.pem");
    X509_uptr empty{nullptr, ::X509_free};

    //act
    auto cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    //assert
    EXPECT_EQ(cert_x509, empty);
}

TEST_F(OpenSSLTestSuite, certIssuerMatches) {
    //arrange
    auto cert_pem = readFile(dataPath / "cert.pem");
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
    auto cert_pem = readFile(dataPath / "cert.pem");
    auto issuer_pem = readFile(dataPath / "issuer.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(cert_pem, issuer_pem);
    
    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(OpenSSLTestSuite, issuerSignedByRoot) {
    //arrange
    auto issuer_pem = readFile(dataPath / "issuer.pem");
    auto root_pem = readFile(dataPath / "trusted-root.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(issuer_pem, root_pem);

    //assert
    EXPECT_EQ(result, 1);
}

TEST_F(OpenSSLTestSuite, nonExistingClientResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "notexist.pem");
    auto issuer_pem = readFile(dataPath / "issuer.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLTestSuite, garbageFileResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "gibberish.pem");
    auto issuer_pem = readFile(dataPath / "issuer.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLTestSuite, garbageIssuerFileResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "cert.pem");
    auto issuer_pem = readFile(dataPath / "garbage.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}

TEST_F(OpenSSLTestSuite, nonExistingIssuerResultsInError) {
    //arrange
    auto client_pem = readFile(dataPath / "issuer.pem");
    auto issuer_pem = readFile(dataPath / "notexist.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(client_pem, issuer_pem);

    //assert
    EXPECT_EQ(result, -1);
}


TEST_F(OpenSSLTestSuite, issuerNotSignedByFakeRootWithSameSubject) {
    //arrange
    auto issuer_pem = readFile(dataPath / "issuer.pem");
    auto root_pem = readFile(dataPath / "fake-root-with-same-name.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(issuer_pem, root_pem);

    //assert
    EXPECT_EQ(result, 0);
}


TEST_F(OpenSSLTestSuite, clientNotSignedByRoot) {
    //arrange
    auto cert_pem = readFile(dataPath / "cert.pem");
    auto root_pem = readFile(dataPath / "trusted-root.pem");

    //act
    int result = OpenSSL::verify_cert_signed_by_issuer(cert_pem, root_pem);

    //assert
    EXPECT_EQ(result, 0);
}