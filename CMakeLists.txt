cmake_minimum_required(VERSION 3.14)
project(drbg C)

set(CMAKE_C_STANDARD 99)

add_executable(drbg
        hash/sm3.c
        main.c
        drbg_hash.c
        include/drbg_hash.h
        include/random_source.h
        include/drbg_util.h
        hash/sm3_hash.c
        include/hash/sm3_hash.h
        include/hash/sm3.h
        include/bool.h
        test/timer_util.c
        include/test/timer_util.h
        include/drbg_hmac.h drbg_hmac.c)