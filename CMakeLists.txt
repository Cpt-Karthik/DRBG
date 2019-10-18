cmake_minimum_required(VERSION 3.14)
project(drbg C)

set(CMAKE_C_STANDARD 99)

# Search OpenSSL
unset(OPENSSL_ROOT_DIR)
set(OPENSSL_ROOT_DIR /usr/local/Cellar/openssl@1.1/1.1.1d)
find_package(openssl REQUIRED)
include_directories(${OPENSSL_ROOT_DIR}/include)
link_directories(${OPENSSL_ROOT_DIR}/lib)
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

include_directories(include)

set(COMMON_FILES
        test/timer_util.c
        common/random_source.c)

add_executable(drbg_hash
        main_hash.c
        drbg_hash.c
        hash/sha256_hash.c
        ${COMMON_FILES})

target_link_libraries(drbg_hash ${OPENSSL_LIBRARIES})

add_executable(drbg_hmac
        main_hmac.c
        drbg_hmac.c
        hmac/sha256_hmac.c
        ${COMMON_FILES})

target_link_libraries(drbg_hmac ${OPENSSL_LIBRARIES})

add_executable(drbg_ctr
        main_ctr.c
        drbg_ctr.c
        cipher/aes256_ctr.c
        ${COMMON_FILES})

target_link_libraries(drbg_ctr ${OPENSSL_LIBRARIES})