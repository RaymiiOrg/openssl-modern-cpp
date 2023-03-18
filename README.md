# Modern C++ OpenSSL example

This repository shows how to use
the OpenSSL C API with modern C++.

This mainly shows using the OpenSSL 
primitives as smart pointers (no 
XXX_free needed) and has a bunch of 
unit tests demonstrating different
validation methods as well as a few 
example data gathering methods (for example
to get a certificate subject as a `std::string`).

It also shows how to link against OpenSSL
using CMake and `CMakeLists.txt`.

Note that cloning this repository does not automatically include the nested git projects.
They can be included by adding the `--recurse-submodules` when cloning.

[Read more over here](https://raymii.org).

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
`free` is needed. This is important because
in between the `new` and the `free`, you
might get an exception which leaves a 
memory leak.

The code also shows how to print the 
`issuer` and `subject` field of a 
certificate. It includes an intermediate
method to convert a PEM file to an 
`X509` object.

The unit test further show how to use the code.

## Example unit tests

The `tst` folder has a bunch of unit tests checking
valid, invalid and other scenario's, like expired 
certifcates or custom `(*verify_cb)(int, X509_STORE_CTX *)`
lambda's that are passed as function pointers 
(because they don't capture anything). 

### Expired certificate validation

To validate an expired certificate, you can either
pass the `X509_V_FLAG_NO_CHECK_TIME` as 
`X509_VERIFY_PARAM*` (also provided as `unique_ptr`),
or provide a custom callback lambda mimicking a 
`int (*verify_cb)(int, X509_STORE_CTX *)`:

    auto verify_callback_accept_exipred = [](int ok, X509_STORE_CTX *ctx) -> int {
        /* Tolerate certificate expiration */
        if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_HAS_EXPIRED)
        return 1;
        /* Otherwise don't override */
        return ok;
    };


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
