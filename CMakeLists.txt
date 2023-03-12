cmake_minimum_required(VERSION 3.24)
project(cert_test)

set(CMAKE_CXX_STANDARD 17)


add_executable(cert_test main.cpp)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    MESSAGE(STATUS "Using OpenSSL: ${OPENSSL_VERSION} from: ${OPENSSL_LIBRARIES}")
    target_link_libraries(cert_test ${OPENSSL_LIBRARIES})
    target_include_directories(cert_test PUBLIC ${OPENSSL_INCLUDE_DIR})
endif()
