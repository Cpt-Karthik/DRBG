//
// Created by Ghost on 2019/9/17.
//

#include "../include/cipher/aes256_ctr.h"

static bool encrypt_function(const uint8_t *input, uint32_t input_len,
                             const uint8_t *key, uint32_t key_len, uint8_t *output) {

    if (input_len != AES256_BLOCK_SIZE) return false;

    AES_KEY skey;
    AES_set_encrypt_key(key, key_len * 8, &skey);

    AES_ecb_encrypt(input, output, &skey, AES_ENCRYPT);
    return true;
}

bool DRBG_CTR_AES256_conf(DRBG_CTR_CONF *conf) {

    conf->key_len = AES256_KEY_SIZE;
    conf->block_len = AES256_BLOCK_SIZE;
    conf->ctr_len = AES256_BLOCK_SIZE;  // 4 <= ctr <= block_len
    conf->reseed_interval = 1u << 10u;
    conf->security_strength = 1; // not used
    conf->encrypt = &encrypt_function;

    return true;
}