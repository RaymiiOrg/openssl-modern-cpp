#pragma once


#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <memory>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <functional>

struct OpenSSLFree
{
    void operator() (BIO* bio) const
    { BIO_free(bio); }

    void operator() (X509* x509) const
    { X509_free(x509); }

    void operator() (STACK_OF(X509)* st) const
    { sk_X509_free(st); }

    void operator() (X509_STORE* store) const
    { X509_STORE_free(store); }

    void operator() (X509_STORE_CTX* ctx) const
    { X509_STORE_CTX_free(ctx); }

    void operator() (X509_VERIFY_PARAM* param) const
    { X509_VERIFY_PARAM_free(param); }

    void operator() (GENERAL_NAME* gn) const
    {GENERAL_NAME_free(gn); }

    void operator() (STACK_OF(GENERAL_NAME)* st) const
    { sk_GENERAL_NAME_free(st); }

    void operator() (EVP_PKEY* evp_pkey) const
    { EVP_PKEY_free(evp_pkey); }
};

using X509_uptr = std::unique_ptr<X509, OpenSSLFree>;
using STACK_OF_X509_uptr = std::unique_ptr<STACK_OF(X509), OpenSSLFree>;
using BIO_MEM_uptr = std::unique_ptr<BIO, OpenSSLFree>;
using EVP_PKEY_uptr = std::unique_ptr<EVP_PKEY, OpenSSLFree>;
using BUF_MEM_uptr = std::unique_ptr<BUF_MEM,OpenSSLFree>;
using X509_STORE_CTX_uptr = std::unique_ptr<X509_STORE_CTX, OpenSSLFree>;
using X509_STORE_uptr = std::unique_ptr<X509_STORE, OpenSSLFree>;
using X509_VERIFY_PARAM_uptr = std::unique_ptr<X509_VERIFY_PARAM, OpenSSLFree>;
using GENERAL_NAME_uptr = std::unique_ptr<GENERAL_NAME, OpenSSLFree>;
using STACK_OF_GENERAL_NAME_uptr = std::unique_ptr<STACK_OF(GENERAL_NAME), OpenSSLFree>;


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
    [[nodiscard]] static int verify_cert_signed_by_chain(const std::string& cert_pem,
                                                         const std::string& issuer_pem);

    /**
     * Uses OpenSSL X509_STORE_CTX to verify a certificate against a chain
     * @param cert_pem single PEM encoded certificate to check against chain
     * @param chain PEM encoded chain (list of certificates)
     * @param verify_cb optional X509_STORE_CTX_verify_cb function
     * @return 1 if OK, 0 if NOT OK, -1 on error
     */
    [[nodiscard]] static int verify_cert_signed_by_chain(const std::string& cert_pem,
                                                         const std::string& issuer_pem,
                                                         int (*verify_cb)(int, X509_STORE_CTX *));


    /**
     * Uses OpenSSL X509_STORE_CTX to verify a certificate against a chain
     * @param cert_pem single PEM encoded certificate to check against chain
     * @param chain PEM encoded chain (list of certificates)
     * @param x509_verify_param optional X509_VERIFY_PARAM to for example disable time checks, X509_V_FLAG_NO_CHECK_TIME
     * @return 1 if OK, 0 if NOT OK, -1 on error
     */
    [[nodiscard]] static int verify_cert_signed_by_chain(const std::string& cert_pem,
                                                         const std::string& issuer_pem,
                                                         const X509_VERIFY_PARAM* x509_verify_param);

    /**
     * Uses OpenSSL X509_STORE_CTX to verify a certificate against a chain
     * @param cert_pem single PEM encoded certificate to check against chain
     * @param chain PEM encoded chain (list of certificates)
     * @param x509_verify_param optional X509_VERIFY_PARAM to for example disable time checks, X509_V_FLAG_NO_CHECK_TIME
     * @param verify_cb optional X509_STORE_CTX_verify_cb function
     * @return 1 if OK, 0 if NOT OK, -1 on error
     */
    [[nodiscard]] static int verify_cert_signed_by_chain(const std::string& cert_pem,
                                                         const std::string& issuer_pem,
            const X509_VERIFY_PARAM* x509_verify_param,
            int (*verify_cb)(int, X509_STORE_CTX *));


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
    static std::string x509_subject (const X509* x509);


    /*
     * Parses the X509* and returns the subjectAlternativeNames
     * @param x509 OpenSSL X509 struct filled with certificate
     * @return vector of strings filled with subjectAlternativeName
     * NOTE: only parses DNS:. Not IP: or others.
     */
    static std::vector<std::string> x509_subject_alternative_dns_names(const X509* x509);

    /**
    * Parses the X509* and returns the subjectAlternativeNames
    * @param x509 OpenSSL X509 struct filled with certificate
    * @return vector of strings filled with subjectAlternativeName
    * NOTE: only parses IP:. Not DNS: or others.
    */
    static std::vector<std::string> x509_subject_alternative_ip_names(const X509* x509);


    [[nodiscard]] static std::vector<X509_uptr> certs_to_x509(const std::string& certs_pem);


private:

    /**
     * Used as a base class to convert subject or issuer to std::string,
     * handles allocation and conversion.
     * @param X509_X_NAME_FUNC Lambda that calls for example X509_get_subject_name.
     * @return
     */
    static std::string x509_name_base(const X509 *const x509,
                                      const std::function<void(const X509 *, const BIO_MEM_uptr &)> &X509_X_NAME_FUNC);
};

