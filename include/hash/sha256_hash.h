//
// Created by Ghost on 2019/9/17.
//

#ifndef DRBG_SHA256_HASH_H
#define DRBG_SHA256_HASH_H

#include "../bool.h"
#include "../drbg_hash.h"
#include <openssl/sha.h>

#define SHA256_HASH_SIZE SHA256_DIGEST_LENGTH // bytes

bool DRBG_HASH_SHA256_conf(DRBG_HASH_CONF *conf);

#endif //DRBG_SHA256_HASH_H
