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

#include "OpenSSL.h"
#include <filesystem>
#include <iostream>
#include <string>

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

    // runs in build/src folder, certs are in tst folder
    std::string cert_pem_filename = "../../tst/data/raymii.org.2023.pem";
    std::string issuer_pem_filename = "../../tst/data/Sectigo_RSA_Domain_Validation_Secure_Server_CA.pem";
    std::string root_pem_filename = "../../tst/data/USERTrust_RSA_Certification_Authority.pem";
    std::string fake_root_pem_filename = "../../tst/data/FAKE_USERTrust_RSA_Certification_Authority.pem";


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

    X509_uptr cert_x509 = OpenSSL::cert_to_x509(cert_pem);
    X509_uptr issuer_x509 = OpenSSL::cert_to_x509(issuer_pem);
    X509_uptr root_x509 = OpenSSL::cert_to_x509(root_pem);
    X509_uptr fake_root_x509 = OpenSSL::cert_to_x509(fake_root_pem);

    std::cout << "certificate subject: " << OpenSSL::x509_subject(cert_x509.get()) << std::endl;
    std::cout << "certificate issuer : " << OpenSSL::x509_issuer(cert_x509.get()) << std::endl;

    std::cout << "issuer subject     : " << OpenSSL::x509_subject(issuer_x509.get()) << std::endl;
    std::cout << "issuer issuer      : " << OpenSSL::x509_issuer(issuer_x509.get()) << std::endl;

    std::cout << "root   subject     : " << OpenSSL::x509_subject(root_x509.get()) << std::endl;
    std::cout << "root   issuer      : " << OpenSSL::x509_issuer(root_x509.get()) << std::endl;

    std::cout << "fake root subject  : " << OpenSSL::x509_subject(fake_root_x509.get()) << std::endl;
    std::cout << "fake root issuer   : " << OpenSSL::x509_issuer(fake_root_x509.get()) << std::endl;


    int goodSignature = OpenSSL::verify_cert_signed_by_issuer(cert_pem, issuer_pem);
    std::cout <<  "Certificate signed by issuer (should be valid): ";
    printSignatureValidationResult(goodSignature);

    int goodSignature2 = OpenSSL::verify_cert_signed_by_issuer(issuer_pem, root_pem);
    std::cout << "Issuer signed by root (should be valid): ";
    printSignatureValidationResult(goodSignature2);

    int badSignature = OpenSSL::verify_cert_signed_by_issuer(cert_pem, root_pem);
    std::cout << "Certificate signed by root (should be INVALID): ";
    printSignatureValidationResult(badSignature);

    int badSignature2 = OpenSSL::verify_cert_signed_by_issuer(issuer_pem, fake_root_pem);
    std::cout << "Issuer signed by FAKE root (should be INVALID): ";
    printSignatureValidationResult(badSignature2);


    std::cout << "Take a look at the unit tests for more usage examples!";
}
