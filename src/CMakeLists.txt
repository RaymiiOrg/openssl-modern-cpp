set(BINARY ${CMAKE_PROJECT_NAME})

file(GLOB_RECURSE SOURCES LIST_DIRECTORIES true *.h *.cpp)

set(SOURCES ${SOURCES})

add_executable(${BINARY}_run ${SOURCES})

add_library(${BINARY}_lib STATIC ${SOURCES})

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    MESSAGE(STATUS "Using OpenSSL: ${OPENSSL_VERSION} from: ${OPENSSL_LIBRARIES}")
    target_link_libraries(${BINARY}_run ${OPENSSL_LIBRARIES})
    target_include_directories(${BINARY}_run PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${BINARY}_lib ${OPENSSL_LIBRARIES})
    target_include_directories(${BINARY}_lib PUBLIC ${OPENSSL_INCLUDE_DIR})
endif()
