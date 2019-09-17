//
// Created by Ghost on 2019/9/17.
//

#ifndef DRBG_AES256_CTR_H
#define DRBG_AES256_CTR_H

#include "../bool.h"
#include "../drbg_ctr.h"
#include <openssl/aes.h>

#define AES256_BLOCK_SIZE AES_BLOCK_SIZE // bytes
#define AES256_KEY_SIZE 32

bool DRBG_CTR_AES256_conf(DRBG_CTR_CONF *conf);

#endif //DRBG_AES256_CTR_H
