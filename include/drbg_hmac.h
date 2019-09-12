//
// Created by Ghost on 2019/9/12.
//

#ifndef DRBG_DRBG_HMAC_H
#define DRBG_DRBG_HMAC_H

#include "bool.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* Configuration about hash algorithm */
typedef struct {

    // uint32_t seed_len; // byte using out_len
    uint32_t out_len; // byte
    uint32_t reseed_interval;

    /* Admin variables */
    uint32_t security_strength; // in this method its not used

    /* hash function used in instantiate, reseed and generate */
    uint32_t (*hmac)(uint8_t *, uint32_t, uint8_t *, uint32_t , uint8_t *);

} DRBG_HMAC_CONF;

/* Intern state in DRBG_HASH */
typedef struct {

    /** working state **/
    uint8_t *V;
    uint8_t *Key;
    uint32_t reseed_counter;

    /** admin variables **/

    // uint32_t security_strength; moved to conf since it depends on hash algorithm and user settings
    bool prediction_resistance_flag; // use for reseed demand from consuming application

    /** configures about hash algorithm **/
    DRBG_HMAC_CONF *conf;

} DRBG_HMAC;

/**
 * Use a configure struct to initialize a DRBG_HMAC
 *
 * @param conf configure to init a DRBG
 * @return status 0 if success, failed otherwise
 */
bool DRBG_HMAC_new(DRBG_HMAC *, DRBG_HMAC_CONF *conf);

/**
 * Instantiate a DRBG of hmac type
 *
 * @param entropy entropy input
 * @param entropy_length entropy input length
 * @param nonce nonce
 * @param nonce_length nonce length
 * @param pstr personalization string
 * @param pstr_length personalization string length
 * @return status 0 if success, failed otherwise
 */
bool DRBG_HMAC_instantiate(DRBG_HMAC *,
                           const uint8_t *entropy, uint32_t entropy_length,
                           const uint8_t *nonce, uint32_t nonce_length,
                           const uint8_t *pstr, uint32_t pstr_length);

/**
 * Reseed a DRBG of hmac type
 *
 * @param entropy entropy input
 * @param entropy_length entropy input length
 * @param add_input additional input
 * @param add_length additional input length
 * @return status 0 if success, failed otherwise
 */
bool DRBG_HMAC_reseed(DRBG_HMAC *,
                      uint8_t *entropy, uint32_t entropy_length,
                      uint8_t *add_input, uint32_t add_length);

/**
 * Generate rand numbers from DRBG
 *
 * @param add_input additional input
 * @param add_length additional input length
 * @param req_length request random byte length
 * @param result request random byte
 * @return status 0 if success, failed otherwise
 */
bool DRBG_HMAC_generate(DRBG_HMAC *,
                        uint8_t *add_input, uint32_t add_length,
                        uint32_t return_length, uint8_t *output);

bool DRBG_HMAC_uninstantiate(DRBG_HMAC *);

#endif //DRBG_DRBG_HMAC_H
