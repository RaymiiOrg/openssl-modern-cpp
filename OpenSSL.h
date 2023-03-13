#pragma once


#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <memory>
#include <iostream>
#include <fstream>
#include <filesystem>


using X509_uptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using BIO_MEM_uptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using EVP_PKEY_uptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BUF_MEM_uptr = std::unique_ptr<BUF_MEM, decltype(&::BUF_MEM_free)>;
using X509_STORE_CTX_uptr = std::unique_ptr<X509_STORE_CTX, decltype(&::X509_STORE_CTX_free)>;

inline static const int maxKeySize = 4096;


class OpenSSL {
public:
    OpenSSL();

    /**
     * Uses OpenSSL X509_STORE_CTX to verify a certificate against a chain
     * @param cert_pem single PEM encoded certificate to check against chain
     * @param chain PEM encoded chain (list of certificates)
     * @return 1 if OK, 0 if NOT OK, -1 on error
     */
    [[nodiscard]] static int verify_cert_signed_by_chain(const std::string& cert_pem, const std::string& issuer_pem) ;


    /**
     * Uses OpenSSL X509_verify to verify a certificates signature
     * (eg. if it's signed by the issuer provided).
     * @param cert_pem single PEM encoded certificate to check against issuer
     * @param issuer_pem single PEM encoded issuer certificate
     * @return 1 if OK, 0 if NOT OK, -1 on error
     */
    [[nodiscard]] static int verify_cert_signed_by_issuer(const std::string& cert_pem, const std::string& issuer_pem) ;

    /**
     * Returns a unique_ptr<X509>, requiring no manual X509_free
     * @param cert_pem PEM encoded certificate
     */
    [[nodiscard]] static X509_uptr cert_to_x509(const std::string& cert_pem) ;

    /**
     * @param x509 OpenSSL X509 struct filled with certificate.
     * @return Contents of issuer field of certificate, empty on error.
     */
    static std::string x509_issuer (const X509* x509) ;

    /**
     * @param x509 OpenSSL X509 struct filled with certificate.
     * @return Contents of subject field of certificate, empty on error.
     */
    static std::string x509_subject (const X509* x509) ;
};
