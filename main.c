#include "include/drbg_hash.h"
#include "include/hash/sha256_hash.h"
#include "include/test/timer_util.h"
#include <stdio.h>

#if defined(__APPLE__)

#include <sys/random.h>

#elif defined(_Win32)
// Windows entropy random source header
#else
// Linux entropy random source header
#endif

#define DRBG_LEN 32
#define ENTROPY_LEN 32

int main() {
    DRBG_HASH drbg;
    DRBG_HASH_CONF conf;

    print_time(1);
    if (!DRBG_HASH_SHA256_conf(&conf)) {
        printf("Conf err");
        return 1;
    }

    print_time(2);
    if (!DRBG_HASH_new(&drbg, &conf)) {
        printf("New err");
        return 2;
    }

    print_time(3);
    uint8_t ent[ENTROPY_LEN];
#if defined(__APPLE__)
    int result = getentropy(ent, ENTROPY_LEN);
#elif defined(_Win32)
    // Windows entropy random source func
    int result = getrandom();
#else
    // Linux entropy random source func
    int result = getrandom();
#endif
    if (result) {
        printf("System call err1 %d", result);
        return result;
    }

    uint8_t serial[16];
    print_time(4);
    if (!DRBG_HASH_instantiate(&drbg, ent, ENTROPY_LEN, NULL, 0, serial, 16)) {
        printf("Instantiate err");
        return 3;
    }

    print_time(5);
    uint8_t res[DRBG_LEN];
    for (int j = 0; j < 1000; ++j) {
        if (!DRBG_HASH_generate(&drbg, serial, 16, DRBG_LEN, res)) {
            printf("Gen err");
            return 4;
        } else {
            for (int i = 0; i < DRBG_LEN; ++i) {
                printf("%d ", res[i]);
            }
            printf("\n");
        }
    }

    print_time(6);
#if defined(__APPLE__)
    result = getentropy(ent, ENTROPY_LEN);
#elif defined(_Win32)
    // Windows entropy random source func
    result = getrandom();
#else
    // Linux entropy random source func
    result = getrandom();
#endif
    if (result) {
        printf("System call err2 %d", result);
        return result;
    }

    print_time(7);
    if (!DRBG_HASH_reseed(&drbg, ent, ENTROPY_LEN, serial, 16)) {
        printf("Reseed err");
        return 5;
    }

    print_time(8);
    for (int j = 0; j < 1000; ++j) {
        if (!DRBG_HASH_generate(&drbg, serial, 16, DRBG_LEN, res)) {
            printf("Gen err after reseed");
            return 6;
        } else {
            for (int i = 0; i < DRBG_LEN; ++i) {
                printf("%d ", res[i]);
            }
            printf("\n");
        }
    }

    print_time(9);
    if (!DRBG_HASH_uninstantiate(&drbg)) {
        printf("Uninstant err");
        return 7;
    }

    return 0;
}