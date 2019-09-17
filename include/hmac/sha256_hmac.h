//
// Created by Ghost on 2019/9/17.
//

#ifndef DRBG_SHA256_HMAC_H
#define DRBG_SHA256_HMAC_H

#include "../bool.h"
#include "../drbg_hmac.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define SHA256_HMAC_SIZE SHA256_DIGEST_LENGTH

bool DRBG_HMAC_SHA256_conf(DRBG_HMAC_CONF *conf);

#endif //DRBG_SHA256_HMAC_H
