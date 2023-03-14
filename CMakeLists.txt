cmake_minimum_required(VERSION 3.24)
project(openssl_modern_cpp)

set(CMAKE_CXX_STANDARD 17)

include_directories(src)

add_subdirectory(src)
add_subdirectory(tst)
add_subdirectory(lib/googletest)
