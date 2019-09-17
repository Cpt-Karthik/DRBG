//
// Created by Ghost on 2019/9/17.
//

#include "../include/hmac/sha256_hmac.h"

static bool hmac_function(const uint8_t *input1, uint32_t input1_len,
                          const uint8_t *input2, uint32_t input2_len,
                          const uint8_t *input3, uint32_t input3_len,
                          const uint8_t *input4, uint32_t input4_len,
                          const uint8_t *input5, uint32_t input5_len,
                          uint8_t *key, uint32_t key_len, uint8_t *output) {

    uint32_t return_len = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();
    return ctx != NULL && HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL) &&
           (input1 == NULL || HMAC_Update(ctx, input1, input1_len)) &&
           (input2 == NULL || HMAC_Update(ctx, input2, input2_len)) &&
           (input3 == NULL || HMAC_Update(ctx, input3, input3_len)) &&
           (input4 == NULL || HMAC_Update(ctx, input4, input4_len)) &&
           (input5 == NULL || HMAC_Update(ctx, input5, input5_len)) &&
           HMAC_Final(ctx, output, &return_len) &&
           return_len == SHA256_HMAC_SIZE;
}

bool DRBG_HMAC_SHA256_conf(DRBG_HMAC_CONF *conf) {
    if (conf == NULL)
        return false;

    conf->out_len = SHA256_HMAC_SIZE; // equals the hash size
    conf->reseed_interval = 0x1u << 10u;
    conf->security_strength = 1; // not used in DRBG_HASH operation
    conf->hmac = &hmac_function;

    return true;
}