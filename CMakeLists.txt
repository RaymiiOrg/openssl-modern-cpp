cmake_minimum_required(VERSION 3.24)
project(openssl_modern_cpp)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} --coverage")
set(CMAKE_CXX_STANDARD 17)

include_directories(src)

add_subdirectory(src)
add_subdirectory(tst)

