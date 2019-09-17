//
// Created by Ghost on 2019/9/17.
//

#ifndef DRBG_DRBG_CTR_H
#define DRBG_DRBG_CTR_H

#include <string.h>
#include "bool.h"
#include <stdint.h>
#include <stdlib.h>

#define MAXIMUM_REQUESTED_BYTES 64

/* Configuration about cipher algorithm */
typedef struct {

    uint32_t key_len; // byte
    uint32_t block_len; // byte aka out_len
    // uint32_t seed_len = key_len + block_len
    uint32_t ctr_len; // byte 4 <= ctr_len <= block_len
    uint32_t reseed_interval;

    /* df function usage */
    bool useDerivationFunction;

    /* Admin variables */
    uint32_t security_strength; // in this method its not used

    /* cipher function used in instantiate, reseed and generate */
    // input might be null, so be ware that you need to check null yourself
    bool (*encrypt)(const uint8_t *input, uint32_t input_len /* must be block_len or failed */,
                 const uint8_t *key, uint32_t key_len, uint8_t *output);

} DRBG_CTR_CONF;

/* Intern state in DRBG_CTR */
typedef struct {

    /** working state **/
    uint8_t *V;
    uint8_t *key;
    uint32_t reseed_counter;

    /** admin variables **/

    // uint32_t security_strength; moved to conf since it depends on cipher algorithm and user settings
    bool prediction_resistance_flag; // use for reseed demand from consuming application

    /** configures about cipher algorithm **/
    DRBG_CTR_CONF *conf;

} DRBG_CTR;

/**
 * Use a configure struct to initialize a DRBG_CTR
 *
 * @param conf configure to init a DRBG
 * @param useDerivationFunction is use derivation function
 * @return status 0 if success, failed otherwise
 */
bool DRBG_CTR_new(DRBG_CTR *, DRBG_CTR_CONF *conf, bool useDerivationFunction);

/**
 * Instantiate a DRBG of cipher type
 *
 * @param entropy entropy input
 * notice that if NOT use derivation function, this should be seed_len long,
 * AND in this function it will NOT be checked
 * @param entropy_length
 * @param nonce
 * @param nonce_length
 * @param pstr personalization string
 * @param pstr_length
 * @return status 0 if success, failed otherwise
 */
bool DRBG_CTR_instantiate(DRBG_CTR *,
                           const uint8_t *entropy, uint32_t entropy_length,
                           const uint8_t *nonce, uint32_t nonce_length,
                           const uint8_t *pstr, uint32_t pstr_length);

/**
 * Reseed a DRBG of cipher type
 *
 * @param entropy entropy input
 * @param entropy_length
 * @param add_input additional input
 * @param add_length
 * @return status 0 if success, failed otherwise
 */
bool DRBG_CTR_reseed(DRBG_CTR *,
                      const uint8_t *entropy, uint32_t entropy_length,
                      const uint8_t *add_input, uint32_t add_length);

/**
 * Generate rand numbers from DRBG
 *
 * @param add_input additional input
 * @param add_length notice that if USE derivation function, this should be seed_len long,
 * AND in this function it will NOT be checked
 * @param result request random byte
 * @param req_length request random byte length
 * @return status 0 if success, failed otherwise
 */
bool DRBG_CTR_generate(DRBG_CTR *,
                        const uint8_t *add_input, uint32_t add_length,
                       uint8_t *output, uint32_t return_length);

bool DRBG_CTR_uninstantiate(DRBG_CTR *);

#endif //DRBG_DRBG_CTR_H
