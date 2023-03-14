# Modern C++ OpenSSL example

This repository shows how to use
the OpenSSL C API with modern C++.

This mainly shows using the OpenSSL 
primitives as smart pointers (no 
XXX_free needed).


Note that cloning this repository does not automatically include the nested git projects.
They can be included by adding the `--recurse-submodules` when cloning.


## Included examples

The code shows how to validate
if a certificate (PEM encoded)
is signed by another certificate.

The repo includes a fake root certificate
with the same subject, to show that 
the code does not validate by comparing
issuer <> subject, but uses the actual
OpenSSL `x509_verify` method.

The code shows how to use the OpenSSL
primitives as `unique_ptr`. When those
go out of scope, no manual `delete` or
`free` is needed.

The code also shows how to print the 
`issuer` and `subject` field of a 
certificate. It includes an intermediate
method to convert a PEM file to an 
`X509` object.

## Usage

The repo was tested with OpenSSL 3.0.2 on Ubuntu 22.04.
Make sure to `apt install libssl-dev`.

Compile:

    mkdir build
    cd build
    cmake ..
    make

Example output:

    /home/remy/CLionProjects/cert-test/cmake-build-debug/cert_test
    certificate subject: CN=raymii.org
    certificate issuer : C=GB,ST=Greater Manchester,L=Salford,O=Sectigo Limited,CN=Sectigo RSA Domain Validation Secure Server CA
    issuer subject     : C=GB,ST=Greater Manchester,L=Salford,O=Sectigo Limited,CN=Sectigo RSA Domain Validation Secure Server CA
    issuer issuer      : C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority
    root   subject     : C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority
    root   issuer      : C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority
    fake root subject  : C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority
    fake root issuer   : C=US,ST=New Jersey,L=Jersey City,O=The USERTRUST Network,CN=USERTrust RSA Certification Authority
    Certificate signed by issuer (should be valid): Signature valid
    Issuer signed by root (should be valid): Signature valid
    Certificate signed by root (should be INVALID): Signature INVALID
    Issuer signed by FAKE root (should be INVALID): Signature INVALID


If you want to verify an entire certificate chain, you must 
split the individual certificates yourself.


## License

GNU GPL v3

```
 Copyright (c) 2023 Remy van Elst

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, version 3.

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <http://www.gnu.org/licenses/>.
```
