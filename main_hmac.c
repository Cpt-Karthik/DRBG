#include "include/drbg_hmac.h"
#include "include/hmac/sha256_hmac.h"
#include "include/test/timer_util.h"
#include "include/random_source.h"
#include <stdio.h>

#define DRBG_LEN 32
#define ENTROPY_LEN 32

int main() {
    DRBG_HMAC drbg;
    DRBG_HMAC_CONF conf;

    print_time(1);
    if (!DRBG_HMAC_SHA256_conf(&conf)) {
        printf("Conf err");
        return 1;
    }

    print_time(2);
    if (!DRBG_HMAC_new(&drbg, &conf)) {
        printf("New err");
        return 2;
    }

    print_time(3);
    uint8_t ent[ENTROPY_LEN];
    int result = Get_Entropy(ENTROPY_LEN, false, ent);
    if (result) {
        printf("System call err1 %d", result);
        return result;
    }

    uint8_t serial[16];
    print_time(4);
    if (!DRBG_HMAC_instantiate(&drbg, ent, ENTROPY_LEN, NULL, 0, serial, 16)) {
        printf("Instantiate err");
        return 3;
    }

    print_time(5);
    uint8_t res[DRBG_LEN];
    for (int j = 0; j < 10; ++j) {
        if (!DRBG_HMAC_generate(&drbg, serial, 16, DRBG_LEN, res)) {
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
    result = Get_Entropy(ENTROPY_LEN, false, ent);
    if (result) {
        printf("System call err2 %d", result);
        return result;
    }

    print_time(7);
    if (!DRBG_HMAC_reseed(&drbg, ent, ENTROPY_LEN, serial, 16)) {
        printf("Reseed err");
        return 5;
    }

    print_time(8);
    for (int j = 0; j < 10; ++j) {
        if (!DRBG_HMAC_generate(&drbg, serial, 16, DRBG_LEN, res)) {
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
    if (!DRBG_HMAC_uninstantiate(&drbg)) {
        printf("Uninstant err");
        return 7;
    }

    return 0;
}