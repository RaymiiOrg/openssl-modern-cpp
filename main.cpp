/*
 * Copyright (c) 2023 Remy van Elst <raymii.org>
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


#include <iostream>
#include <fstream>
#include <filesystem>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>


using X509_uptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using BIO_MEM_uptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using EVP_PKEY_uptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BUF_MEM_uptr = std::unique_ptr<BUF_MEM, decltype(&::BUF_MEM_free)>;

inline static const int maxKeySize = 4096;

int verify_cert_signed_by_issuer(const std::string& cert_pem, const std::string& issuer_pem)
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

X509_uptr cert_to_x509(const std::string& cert_pem)
{
    X509_uptr x509(X509_new(), ::X509_free);
    BIO_MEM_uptr bio(BIO_new(BIO_s_mem()), ::BIO_free);
    BIO_puts(bio.get(), cert_pem.c_str());

    X509_uptr cert(PEM_read_bio_X509(bio.get(), nullptr,
                                     nullptr, nullptr), ::X509_free);

    return cert;
}

std::string x509_subject (const X509* const x509)
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

std::string x509_issuer (const X509* const x509)
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


void printSignatureValidationResult(int goodSignature) {
    switch(goodSignature) {
        case 1:
            std::cout << "Signature valid" << std::endl;
            break;
        case 0:
            std::cout << "Signature INVALID"<< std::endl;
            break;
        default:
            std::cout << "Failed to verify signature. Cert incomplete, "
                         "ill-formed or other erro" << std::endl;
            break;
    }
}

int main(int argc, char **argv)
{
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    // runs in build folder, certs are one folder up
    std::string cert_pem_filename = "../cert.pem";
    std::string issuer_pem_filename = "../issuer.pem";
    std::string root_pem_filename = "../trusted-root.pem";
    std::string fake_root_pem_filename = "../fake-root-with-same-name.pem";


    if(!std::filesystem::exists(cert_pem_filename) ||
       !std::filesystem::exists(issuer_pem_filename) ||
       !std::filesystem::exists(root_pem_filename) ||
       !std::filesystem::exists(fake_root_pem_filename))
        return 1;

    std::ifstream cert_pem_in(cert_pem_filename);
    std::string cert_pem((std::istreambuf_iterator<char>(cert_pem_in)),
                    std::istreambuf_iterator<char>());

    std::ifstream issuer_pem_in(issuer_pem_filename);
    std::string issuer_pem((std::istreambuf_iterator<char>(issuer_pem_in)),
                         std::istreambuf_iterator<char>());

    std::ifstream root_pem_in(root_pem_filename);
    std::string root_pem((std::istreambuf_iterator<char>(root_pem_in)),
                           std::istreambuf_iterator<char>());

    std::ifstream fake_root_pem_in(fake_root_pem_filename);
    std::string fake_root_pem((std::istreambuf_iterator<char>(fake_root_pem_in)),
                         std::istreambuf_iterator<char>());

    X509_uptr cert_x509 = cert_to_x509(cert_pem);
    X509_uptr issuer_x509 = cert_to_x509(issuer_pem);
    X509_uptr root_x509 = cert_to_x509(root_pem);
    X509_uptr fake_root_x509 = cert_to_x509(fake_root_pem);

    std::cout << "certificate subject: " << x509_subject(cert_x509.get()) << std::endl;
    std::cout << "certificate issuer : " << x509_issuer(cert_x509.get()) << std::endl;

    std::cout << "issuer subject     : " << x509_subject(issuer_x509.get()) << std::endl;
    std::cout << "issuer issuer      : " << x509_issuer(issuer_x509.get()) << std::endl;

    std::cout << "root   subject     : " << x509_subject(root_x509.get()) << std::endl;
    std::cout << "root   issuer      : " << x509_issuer(root_x509.get()) << std::endl;

    std::cout << "fake root subject  : " << x509_subject(fake_root_x509.get()) << std::endl;
    std::cout << "fake root issuer   : " << x509_issuer(fake_root_x509.get()) << std::endl;


    int goodSignature = verify_cert_signed_by_issuer(cert_pem, issuer_pem);
    std::cout <<  "Certificate signed by issuer (should be valid): ";
    printSignatureValidationResult(goodSignature);

    int goodSignature2 = verify_cert_signed_by_issuer(issuer_pem, root_pem);
    std::cout << "Issuer signed by root (should be valid): ";
    printSignatureValidationResult(goodSignature2);

    int badSignature = verify_cert_signed_by_issuer(cert_pem, root_pem);
    std::cout << "Certificate signed by root (should be INVALID): ";
    printSignatureValidationResult(badSignature);

    int badSignature2 = verify_cert_signed_by_issuer(issuer_pem, fake_root_pem);
    std::cout << "Issuer signed by FAKE root (should be INVALID): ";
    printSignatureValidationResult(badSignature2);

}
