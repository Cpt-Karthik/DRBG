//
// Created by Ghost on 2019/9/17.
//

#include "../include/hash/sha256_hash.h"

static bool hash_function(const uint8_t *input1, uint32_t input1_len,
                          const uint8_t *input2, uint32_t input2_len,
                          const uint8_t *input3, uint32_t input3_len,
                          const uint8_t *input4, uint32_t input4_len,
                          uint8_t *output) {

    SHA256_CTX ctx;
    return SHA256_Init(&ctx) &&
           (input1 == NULL || SHA256_Update(&ctx, input1, input1_len)) &&
           (input2 == NULL || SHA256_Update(&ctx, input2, input2_len)) &&
           (input3 == NULL || SHA256_Update(&ctx, input3, input3_len)) &&
           (input4 == NULL || SHA256_Update(&ctx, input4, input4_len)) &&
           SHA256_Final(output, &ctx);
}

bool DRBG_HASH_SHA256_conf(DRBG_HASH_CONF *conf) {
    if (conf == NULL)
        return false;

    conf->seed_len = 55; // 440 bit
    conf->out_len = SHA256_HASH_SIZE; // equals the hash size
    conf->reseed_interval = 0x1u << 10u;
    conf->security_strength = 1; // not used in DRBG_HASH operation
    conf->hash = &hash_function;

    return true;
}