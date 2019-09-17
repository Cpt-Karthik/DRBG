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

set(COMMON_FILES
        include/bool.h
        include/test/timer_util.h
        test/timer_util.c
        include/random_source.h
        common/random_source.c)

add_executable(drbg_hash
        main_hash.c
        include/drbg_hash.h
        drbg_hash.c
        include/hash/sha256_hash.h
        hash/sha256_hash.c
        ${COMMON_FILES})

target_link_libraries(drbg_hash ${OPENSSL_LIBRARIES})

add_executable(drbg_hmac
        main_hmac.c
        include/drbg_hmac.h
        drbg_hmac.c
        include/hmac/sha256_hmac.h
        hmac/sha256_hmac.c
        ${COMMON_FILES})

target_link_libraries(drbg_hmac ${OPENSSL_LIBRARIES})

add_executable(drbg_ctr
        main_ctr.c
        include/drbg_ctr.h
        drbg_ctr.c
        include/cipher/aes256_ctr.h
        cipher/aes256_ctr.c
        ${COMMON_FILES})

target_link_libraries(drbg_ctr ${OPENSSL_LIBRARIES})