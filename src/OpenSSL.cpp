#include <vector>
#include <functional>
#include "OpenSSL.h"

OpenSSL::OpenSSL()
{
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
}




int OpenSSL::verify_cert_signed_by_issuer(const std::string& cert_pem, const std::string& issuer_pem)
{
    if(cert_pem.empty() || issuer_pem.empty())
        return -1;

    BIO_MEM_uptr bio_issuer(BIO_new(BIO_s_mem()), ::BIO_free);
    if(BIO_puts(bio_issuer.get(), issuer_pem.c_str()) <= 0)
        return -1;

    X509_uptr issuer(PEM_read_bio_X509(bio_issuer.get(), nullptr,
                                       nullptr, nullptr), ::X509_free);
    if(issuer == nullptr)
        return -1;

    EVP_PKEY_uptr signing_key(X509_get_pubkey(issuer.get()), ::EVP_PKEY_free);

    BIO_MEM_uptr bio_cert(BIO_new(BIO_s_mem()), ::BIO_free);
    if(BIO_puts(bio_cert.get(), cert_pem.c_str()) <= 0)
        return -1;

    X509_uptr cert(PEM_read_bio_X509(bio_cert.get(), nullptr,
                                     nullptr, nullptr), ::X509_free);

    if(cert == nullptr)
        return -1;

    int result = X509_verify(cert.get(), signing_key.get());

    return result;
}

X509_uptr OpenSSL::cert_to_x509(const std::string& cert_pem)
{
    if(cert_pem.empty())
        return X509_uptr{nullptr, ::X509_free};

    auto certs_x509 = certs_to_x509(cert_pem);
    if(certs_x509.empty())
        return X509_uptr{nullptr, ::X509_free};

    return std::move(certs_x509.front());
}

std::string OpenSSL::x509_subject (const X509* const x509)
{
    std::string result;
    if(x509 == nullptr)
        return result;

    char subject_buffer[maxKeySize] = {0};
    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()), ::BIO_free);

    // X509_get_subject_name() returns the subject name of certificate x.
    // The returned value is an internal pointer which MUST NOT be freed.
    X509_NAME *subject_name = X509_get_subject_name(x509);
    X509_NAME_print_ex(bio.get(), subject_name,
                       0, XN_FLAG_SEP_COMMA_PLUS);

    BIO_read(bio.get(), subject_buffer, maxKeySize);
    result.assign(subject_buffer);
    return result;
}

std::string OpenSSL::x509_issuer (const X509* const x509)
{
    std::string result;
    if(x509 == nullptr)
        return result;

    char issuer_buffer[maxKeySize] = {0};
    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()), ::BIO_free);

    // X509_get_issuer_name() returns the subject name of certificate x.
    // The returned value is an internal pointer which MUST NOT be freed.
    X509_NAME *issuer_name = X509_get_issuer_name(x509);
    X509_NAME_print_ex(bio.get(), issuer_name,
                       0, XN_FLAG_SEP_COMMA_PLUS);

    BIO_read(bio.get(), issuer_buffer, maxKeySize);
    result.assign(issuer_buffer);
    return result;
}


std::vector<X509_uptr> OpenSSL::certs_to_x509(const std::string& certs_pem)
{
    if(certs_pem.empty())
        return {};

    std::vector<X509_uptr> result;

    X509_uptr x509(X509_new(), ::X509_free);
    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_puts(bio.get(), certs_pem.c_str());

    while (X509_uptr cert = {PEM_read_bio_X509(bio.get(), nullptr,
                             nullptr, nullptr), ::X509_free}) {
        result.push_back(std::move(cert));
    }

    return result;
}


int OpenSSL::verify_cert_signed_by_chain(const std::string &cert_pem,
                                         const std::string &chain_pem) {

    return verify_cert_signed_by_chain(cert_pem, chain_pem,
                                       nullptr, nullptr);
}

int OpenSSL::verify_cert_signed_by_chain(const std::string &cert_pem,
                                         const std::string &chain_pem,
                                         const X509_VERIFY_PARAM* x509_verify_param) {
    return verify_cert_signed_by_chain(cert_pem, chain_pem,
                                       x509_verify_param, nullptr);
}

int OpenSSL::verify_cert_signed_by_chain(const std::string &cert_pem,
                                         const std::string &chain_pem,
                                         int (*verify_cb)(int, X509_STORE_CTX *)) {
    return verify_cert_signed_by_chain(cert_pem, chain_pem,
                                       nullptr, verify_cb);
}


int OpenSSL::verify_cert_signed_by_chain(const std::string &cert_pem,
                                         const std::string &chain_pem,
                                         const X509_VERIFY_PARAM* x509_verify_param,
                                         int (*verify_cb)(int, X509_STORE_CTX *)) {

    if(cert_pem.empty() || chain_pem.empty())
        return -1;

    X509_STORE_uptr store(X509_STORE_new(), ::X509_STORE_free);

    if(store == nullptr)
        return -1;

    if(x509_verify_param != nullptr) {
        X509_STORE_set1_param(store.get(), x509_verify_param);
    }

    //https://github.com/openssl/openssl/issues/7871
    //https://github.com/curl/curl/pull/4655
    X509_VERIFY_PARAM_uptr param(X509_VERIFY_PARAM_new(), ::X509_VERIFY_PARAM_free);
    X509_VERIFY_PARAM_set_flags(param.get(), X509_V_FLAG_PARTIAL_CHAIN);
    X509_STORE_set1_param(store.get(), param.get());

    if(verify_cb != nullptr) {
        X509_STORE_set_verify_cb(store.get(), verify_cb);
    }

    auto chain_x509_certs = certs_to_x509(chain_pem);
    for(const auto& chain_x509 : chain_x509_certs) {
        X509_STORE_add_cert(store.get(), chain_x509.get());
    }

    X509_STORE_CTX_uptr store_ctx(X509_STORE_CTX_new(), ::X509_STORE_CTX_free);
    if(store_ctx == nullptr)
        return -1;

    X509_uptr cert_x509 = cert_to_x509(cert_pem);
    if(X509_STORE_CTX_init(store_ctx.get(), store.get(), cert_x509.get(), nullptr) != 1)
        return -1;

    int result = X509_verify_cert(store_ctx.get());
    if(result != 1) {
        int error = X509_STORE_CTX_get_error(store_ctx.get());
        std::string errorMessage = std::string(X509_verify_cert_error_string(error));
        std::cerr << std::endl << errorMessage << std::endl;
    }
    return result;
}

