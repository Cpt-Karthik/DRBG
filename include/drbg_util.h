//
// Created by Ghost on 2019/9/11.
//

#ifndef DRBG_DRBG_UTIL_H
#define DRBG_DRBG_UTIL_H

#include <stdint.h>

// returns output length
extern uint32_t hash_function(uint8_t *input, uint32_t length, uint8_t *output);

extern uint32_t hmac_function(uint8_t *input, uint32_t input_length,
        uint8_t *key, uint32_t key_length, uint8_t *output);

#endif //DRBG_DRBG_UTIL_H
