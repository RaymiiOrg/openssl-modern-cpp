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
    BIO_puts(bio_issuer.get(), issuer_pem.c_str());
    X509_uptr issuer(PEM_read_bio_X509(bio_issuer.get(), nullptr,
                                       nullptr, nullptr), ::X509_free);

    EVP_PKEY_uptr signing_key(X509_get_pubkey(issuer.get()), ::EVP_PKEY_free);

    BIO_MEM_uptr bio_cert(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_puts(bio_cert.get(), cert_pem.c_str());
    X509_uptr cert(PEM_read_bio_X509(bio_cert.get(), nullptr,
                                     nullptr, nullptr), ::X509_free);

    int result = X509_verify(cert.get(), signing_key.get());

    return result;
}

X509_uptr OpenSSL::cert_to_x509(const std::string& cert_pem)
{
    X509_uptr x509(X509_new(), ::X509_free);
    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_puts(bio.get(), cert_pem.c_str());

    X509_uptr cert(PEM_read_bio_X509(bio.get(), nullptr,
                                     nullptr, nullptr), ::X509_free);

    return cert;
}

std::string OpenSSL::x509_subject (const X509* const x509)
{
    std::string result;
    char subject_buffer[maxKeySize] = {0};
    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()), BIO_free);

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
    char issuer_buffer[maxKeySize] = {0};
    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()), BIO_free);

    // X509_get_issuer_name() returns the subject name of certificate x.
    // The returned value is an internal pointer which MUST NOT be freed.
    X509_NAME *issuer_name = X509_get_issuer_name(x509);
    X509_NAME_print_ex(bio.get(), issuer_name,
                       0, XN_FLAG_SEP_COMMA_PLUS);

    BIO_read(bio.get(), issuer_buffer, maxKeySize);
    result.assign(issuer_buffer);
    return result;
}

int OpenSSL::verify_cert_signed_by_chain(const std::string &cert_pem, const std::string &issuer_pem) {

    if(cert_pem.empty() || issuer_pem.empty())
        return -1;

    X509_STORE_CTX_uptr store_ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);


    return 0;
}

