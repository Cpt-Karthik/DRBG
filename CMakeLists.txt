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

add_executable(drbg_hash
        main_hash.c
        drbg_hash.c
        include/drbg_hash.h
        include/random_source.h
        include/bool.h
        test/timer_util.c
        include/test/timer_util.h
        hash/sha256_hash.c
        include/hash/sha256_hash.h common/random_source.c include/hmac/sha256_hmac.h)

target_link_libraries(drbg_hash ${OPENSSL_LIBRARIES})

add_executable(drbg_hmac
        drbg_hmac.c
        include/drbg_hmac.h
        include/random_source.h
        include/bool.h
        test/timer_util.c
        include/test/timer_util.h
        main_hmac.c
        common/random_source.c
        hmac/sha256_hmac.c
        include/hmac/sha256_hmac.h)

target_link_libraries(drbg_hmac ${OPENSSL_LIBRARIES})