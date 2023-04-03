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
    std::string pem_chain_filename = "../../tst/data/Chain-Sectigo_UserTRUST_RSA.pem";


    if(!std::filesystem::exists(cert_pem_filename) ||
       !std::filesystem::exists(pem_chain_filename))
        return 1;

    std::ifstream cert_pem_in(cert_pem_filename);
    std::string cert_pem((std::istreambuf_iterator<char>(cert_pem_in)),
                    std::istreambuf_iterator<char>());

    std::ifstream pem_chain_in(pem_chain_filename);
    std::string pem_chain((std::istreambuf_iterator<char>(pem_chain_in)),
                          std::istreambuf_iterator<char>());


    X509_uptr cert_x509 = OpenSSL::cert_to_x509(cert_pem);

    std::cout << "certificate subject: " << OpenSSL::x509_subject(cert_x509.get()) << std::endl;
    std::cout << "certificate sans   : ";
    for(const auto& s : OpenSSL::x509_subject_alternative_dns_names(cert_x509.get()))
        std::cout << s << " ";
    std::cout << std::endl;
    std::cout << "certificate issuer : " << OpenSSL::x509_issuer(cert_x509.get()) << std::endl;

    int goodSignature = OpenSSL::verify_cert_signed_by_chain(cert_pem, pem_chain);
    std::cout << "Issuer signed by chain (should be valid): ";
    printSignatureValidationResult(goodSignature);


    std::cout << std::endl << "** Take a look at the unit tests for more usage examples! **" << std::endl;
}
