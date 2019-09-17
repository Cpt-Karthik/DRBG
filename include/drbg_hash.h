//
// Created by Ghost on 2019/9/11.
//

#ifndef DRBG_DRBG_HASH_H
#define DRBG_DRBG_HASH_H

#include <string.h>
#include "bool.h"
#include <stdint.h>
#include <stdlib.h>

/* Configuration about hash algorithm */
typedef struct {

    uint32_t seed_len; // byte
    uint32_t out_len; // byte
    uint32_t reseed_interval;

    /* Admin variables */
    uint32_t security_strength; // in this method its not used

    /* hash function used in instantiate, reseed and generate */
    // input might be null, so be ware that you need to check null yourself
    uint32_t (*hash)(const uint8_t *input1, uint32_t input1_len, const uint8_t *input2,
            uint32_t input2_len, const uint8_t *input3, uint32_t input3_len,
            const uint8_t *input4, uint32_t input4_len, uint8_t *output);

} DRBG_HASH_CONF;

/* Intern state in DRBG_HASH */
typedef struct {

    /** working state **/
    uint8_t *V;
    uint8_t *C;
    uint32_t reseed_counter;

    /** admin variables **/

    // uint32_t security_strength; moved to conf since it depends on hash algorithm and user settings
    bool prediction_resistance_flag; // use for reseed demand from consuming application

    /** configures about hash algorithm **/
    DRBG_HASH_CONF *conf;

} DRBG_HASH;

/**
 * Use a configure struct to initialize a DRBG_HASH
 *
 * @param conf configure to init a DRBG
 * @return status 0 if success, failed otherwise
 */
bool DRBG_HASH_new(DRBG_HASH *, DRBG_HASH_CONF *conf);

/**
 * Instantiate a DRBG of hash type
 *
 * @param entropy entropy input
 * @param entropy_length
 * @param nonce
 * @param nonce_length
 * @param pstr personalization string
 * @param pstr_length
 * @return status 0 if success, failed otherwise
 */
bool DRBG_HASH_instantiate(DRBG_HASH *,
                          const uint8_t *entropy, uint32_t entropy_length,
                          const uint8_t *nonce, uint32_t nonce_length,
                          const uint8_t *pstr, uint32_t pstr_length);

/**
 * Reseed a DRBG of hash type
 *
 * @param entropy entropy input
 * @param entropy_length
 * @param add_input additional input
 * @param add_length
 * @return status 0 if success, failed otherwise
 */
bool DRBG_HASH_reseed(DRBG_HASH *,
                     uint8_t *entropy, uint32_t entropy_length,
                     uint8_t *add_input, uint32_t add_length);

/**
 * Generate rand numbers from DRBG
 *
 * @param add_input additional input
 * @param add_length
 * @param req_length request random byte length
 * @param result request random byte
 * @return status 0 if success, failed otherwise
 */
bool DRBG_HASH_generate(DRBG_HASH *,
                       uint8_t *add_input, uint32_t add_length,
                       uint32_t req_length, uint8_t *result);

bool DRBG_HASH_uninstantiate(DRBG_HASH *);

#endif //DRBG_DRBG_HASH_H
