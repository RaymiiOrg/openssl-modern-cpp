#include <vector>
#include <functional>
#include "OpenSSL.h"

int OpenSSL::verify_cert_signed_by_issuer(const std::string& cert_pem, const std::string& issuer_pem)
{
    if(cert_pem.empty() || issuer_pem.empty())
        return -1;

    BIO_MEM_uptr bio_issuer(BIO_new(BIO_s_mem()));
    if(BIO_puts(bio_issuer.get(), issuer_pem.c_str()) <= 0)
        return -1;

    X509_uptr issuer(PEM_read_bio_X509(bio_issuer.get(), nullptr,
                                       nullptr, nullptr));
    if(issuer == nullptr)
        return -1;

    EVP_PKEY_uptr signing_key(X509_get_pubkey(issuer.get()));

    BIO_MEM_uptr bio_cert(BIO_new(BIO_s_mem()));
    if(BIO_puts(bio_cert.get(), cert_pem.c_str()) <= 0)
        return -1;

    X509_uptr cert(PEM_read_bio_X509(bio_cert.get(), nullptr,
                                     nullptr, nullptr));

    if(cert == nullptr)
        return -1;

    int result = X509_verify(cert.get(), signing_key.get());

    return result;
}

X509_uptr OpenSSL::cert_to_x509(const std::string& cert_pem)
{
    if(cert_pem.empty())
        return X509_uptr{nullptr};

    auto certs_x509 = certs_to_x509(cert_pem);
    if(certs_x509.empty())
        return X509_uptr{nullptr};

    return std::move(certs_x509.front());
}


std::string OpenSSL::x509_name_base(const X509 *const x509,
                                    const std::function<void(const X509 *, const BIO_MEM_uptr &)> &X509_X_NAME_FUNC)
{
    std::string result;
    if(x509 == nullptr)
        return result;

    std::vector<unsigned char> subject_buffer(maxKeySize, 0);
    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()));

    // X509_get_subject_name() or
    // X509_get_issuer_name() returns the subject name of certificate x.
    // The returned value is an internal pointer which MUST NOT be freed.
    X509_X_NAME_FUNC(x509, bio);

    BIO_read(bio.get(), subject_buffer.data(), maxKeySize);
    result.assign(subject_buffer.begin(), subject_buffer.end());
    result.erase(std::find(result.begin(), result.end(), '\0'), result.end());
    return result;
}

std::string OpenSSL::x509_subject (const X509* const x509)
{
    return x509_name_base(x509, [](const X509 *x509p, const BIO_MEM_uptr &bio) {
        const X509_NAME *subject_name = X509_get_subject_name(x509p);
        X509_NAME_print_ex(bio.get(), subject_name,
                           0, XN_FLAG_SEP_COMMA_PLUS);
    });


}

std::string OpenSSL::x509_issuer (const X509* const x509)
{
    return x509_name_base(x509, [](const X509 *x509p, const BIO_MEM_uptr &bio) {
        const X509_NAME *issuer_name = X509_get_issuer_name(x509p);
        X509_NAME_print_ex(bio.get(), issuer_name,
                           0, XN_FLAG_SEP_COMMA_PLUS);
    });
}


std::vector<X509_uptr> OpenSSL::certs_to_x509(const std::string& certs_pem)
{
    if(certs_pem.empty())
        return {};

    std::vector<X509_uptr> result;

    X509_uptr x509(X509_new());
    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()));
    BIO_puts(bio.get(), certs_pem.c_str());

    while (X509_uptr cert {PEM_read_bio_X509(bio.get(), nullptr,
                             nullptr, nullptr)}) {
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


std::vector<std::string> OpenSSL::x509_subject_alternative_dns_names(const X509 *x509) {
    std::vector<std::string> result;
    STACK_OF_GENERAL_NAME_uptr names((STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(x509,
                                        NID_subject_alt_name, nullptr, nullptr));
    int count = sk_GENERAL_NAME_num(names.get());
    for (int i = 0; i < count; ++i)
    {
        GENERAL_NAME_uptr entry(GENERAL_NAME_dup(sk_GENERAL_NAME_value(names.get(), i)));
        if (!entry) continue;

        result.emplace_back(reinterpret_cast<char const*>(ASN1_STRING_get0_data(entry->d.dNSName)),
                    ASN1_STRING_length(entry->d.dNSName));
    }

    return result;
}

STACK_OF_X509_uptr OpenSSL::certs_to_stack_of_x509(const std::string &certs_pem)
{
    if(certs_pem.empty())
        return {};

    STACK_OF_X509_uptr result(sk_X509_new(nullptr));

    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()));
    BIO_puts(bio.get(), certs_pem.c_str());

    while (X509_uptr cert {PEM_read_bio_X509(bio.get(), nullptr,
                                             nullptr, nullptr)})
    {
        sk_X509_push(result.get(), X509_dup(cert.get()));
    }

    return result;
}



int OpenSSL::verify_cert_signed_by_chain(const std::string &cert_pem,
                                         const std::string &chain_pem,
                                         const X509_VERIFY_PARAM* x509_verify_param,
                                         int (*verify_cb)(int, X509_STORE_CTX *)) {

    if(cert_pem.empty() || chain_pem.empty())
        return -1;

    X509_STORE_uptr store(X509_STORE_new());

    if(store == nullptr)
        return -1;

    if(x509_verify_param != nullptr) {
        X509_STORE_set1_param(store.get(), x509_verify_param);
    }

    if(verify_cb != nullptr) {
        X509_STORE_set_verify_cb(store.get(), verify_cb);
    }

    auto stack_of_x509_certs = certs_to_stack_of_x509(chain_pem);

    X509_uptr cert_x509 = cert_to_x509(cert_pem);

    // store == nullptr otherwise chain would have to be anchors to trusted
    // root in store. with_self_signed = 1 because this method validates up
    // to a user provided trusted root.
    STACK_OF_X509_uptr chain((STACK_OF(X509)*)X509_build_chain(cert_x509.get(), stack_of_x509_certs.get(),
    nullptr, 1, nullptr, nullptr));

    int chainSize = sk_X509_num(chain.get());
    for (int i = 0; i < chainSize; i++) {
        X509* chainCert = sk_X509_value(chain.get(), i);
        // add the last chain as trusted root anchor
        if(i == (chainSize - 1))
            X509_STORE_add_cert(store.get(), chainCert);
    }

    X509_STORE_CTX_uptr store_ctx(X509_STORE_CTX_new());
    if(store_ctx == nullptr)
        return -1;

    if(X509_STORE_CTX_init(store_ctx.get(), store.get(), cert_x509.get(), chain.get()) != 1)
        return -1;

    int result = X509_verify_cert(store_ctx.get());
    if(result != 1) {
        int error = X509_STORE_CTX_get_error(store_ctx.get());
        auto errorMessage = std::string(X509_verify_cert_error_string(error));
        std::cerr << errorMessage << "; ";
    }
    return result;
}

EVP_PKEY_uptr OpenSSL::x509_to_evp_pkey(const X509 *x509) {
    if(!x509)
        return {};

    X509_uptr non_const_x509(X509_dup(x509));
    return EVP_PKEY_uptr(X509_get_pubkey(non_const_x509.get()));
}

std::string OpenSSL::x509_to_public_key_pem(const X509 *x509) {
    std::string result;
    std::vector<unsigned char> pem_buffer(maxKeySize, 0);
    if(!x509)
        return result;

    EVP_PKEY_uptr evp_pkey_uptr = x509_to_evp_pkey(x509);

    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PUBKEY_ex(bio.get(), evp_pkey_uptr.get(), nullptr, nullptr);

    BIO_read(bio.get(), pem_buffer.data(), maxKeySize);
    result.assign(pem_buffer.begin(), pem_buffer.end());
    result.erase(std::find(result.begin(), result.end(), '\0'), result.end());
    return result;
}

int OpenSSL::verify_sha256_digest_signature(const std::string &message, const std::string &base64_encoded_signature,
                                            const X509 *x509_that_has_pubkey_that_signed_the_message) {
    if(message.empty() ||
        base64_encoded_signature.empty() ||
        x509_that_has_pubkey_that_signed_the_message == nullptr)
        return -1;

    EVP_PKEY_uptr evp_pkey_uptr = x509_to_evp_pkey(x509_that_has_pubkey_that_signed_the_message);
    if(evp_pkey_uptr == nullptr)
        return -1;


    return 0;
}

std::string OpenSSL::base64_decode(const std::string &message) {

    if(message.size() > std::numeric_limits<int>::max())
        return "";

    if(message.empty())
        return "";

    size_t decoded_size =  (((message.length() + 1) * 3) / 4);
    std::vector<char> message_buffer(decoded_size);


    int length_decoded = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(message_buffer.data()),
                                         reinterpret_cast<const unsigned char*>(message.c_str()),
                                         message.length());

    if(length_decoded <= 0)
        return "";

    std::string result(message_buffer.data(), message_buffer.size());
    result.erase(result.find_last_not_of('\0') + 1, std::string::npos);
    return result;
}

std::string OpenSSL::base64_encode(const std::string &message) {

    if(message.size() > std::numeric_limits<int>::max())
        return "";

    if(message.empty())
        return "";

    size_t encoded_size = (1 + ((message.length() + 2) / 3 * 4));
    std::vector<char> message_buffer(encoded_size);

    int length_encoded = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(message_buffer.data()),
                                         reinterpret_cast<const unsigned char*>(message.c_str()),
                                         message.length());

    if(length_encoded <= 0)
        return "";

    std::string result(message_buffer.data(), message_buffer.size());
    result.erase(result.find_last_not_of('\0') + 1, std::string::npos);
    return result;
}


std::string OpenSSL::read_binary_file(const std::string &filename) {
    std::ifstream infile(filename, std::ios::binary);
    if (!infile) {
        return "";
    }

    infile.seekg(0, std::ios::end);
    std::streamsize size = infile.tellg();
    infile.seekg(0, std::ios::beg);

    std::string buffer(size, ' ');
    if (!infile.read(&buffer[0], size)) {
        return "";
    }

    return buffer;
}
