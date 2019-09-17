//
// Created by Ghost on 2019/9/12.
//

#include "include/drbg_hmac.h"

static bool DRBG_HMAC_Update(DRBG_HMAC *drbg,
                             const uint8_t *input1, uint32_t input1_len,
                             const uint8_t *input2, uint32_t input2_len,
                             const uint8_t *input3, uint32_t input3_len) {

    // Key = hmac(Key, V || 0x00 || pdata)
    uint8_t zero = 0x00;
    if (!drbg->conf->hmac(drbg->V, drbg->conf->out_len, &zero, 1,
                          input1, input1_len, input2, input2_len, input3, input3_len,
                          drbg->Key, drbg->conf->out_len, drbg->Key))
        return false;

    // V = hmac(Key, V)
    if (!drbg->conf->hmac(drbg->V, drbg->conf->out_len, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                          drbg->Key, drbg->conf->out_len, drbg->V))
        return false;

    // if provided data is null, return
    if (input1 == NULL && input2 == NULL && input3 == NULL) return true;

    // Key = hmac(Key, V || 0x01 || pdata)
    uint8_t one = 0x01;
    if (!drbg->conf->hmac(drbg->V, drbg->conf->out_len, &one, 1,
                          input1, input1_len, input2, input2_len, input3, input3_len,
                          drbg->Key, drbg->conf->out_len, drbg->Key))
        return false;

    // V = hmac(Key, V)
    if (!drbg->conf->hmac(drbg->V, drbg->conf->out_len, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                          drbg->Key, drbg->conf->out_len, drbg->V))
        return false;

    return true;
}

bool DRBG_HMAC_new(DRBG_HMAC *drbg, DRBG_HMAC_CONF *conf) {
    // validate config
    if (conf == NULL || conf->hmac == NULL ||
        conf->out_len == 0 ||
        conf->reseed_interval == 0 ||
        conf->security_strength == 0)
        return false;

    drbg->conf = conf;

    /* initialize internal state */
    uint8_t *v = malloc(conf->out_len);
    memset(v, 0, conf->out_len);
    drbg->V = v;
    uint8_t *key = malloc(conf->out_len);
    memset(key, 0, conf->out_len);
    drbg->Key = key;
    drbg->reseed_counter = 0;
    drbg->prediction_resistance_flag = false;
    return true;
}

bool DRBG_HMAC_instantiate(DRBG_HMAC *drbg,
                           const uint8_t *entropy, uint32_t entropy_length,
                           const uint8_t *nonce, uint32_t nonce_length,
                           const uint8_t *pstr, uint32_t pstr_length) {

    // seed_material = entropy_input || nonce || personalization_string
    // Key = 0x0000 with outlen
    memset(drbg->Key, 0x00, drbg->conf->out_len);
    // V = 0x0101 with outlen
    memset(drbg->V, 0x01, drbg->conf->out_len);

    DRBG_HMAC_Update(drbg, entropy, entropy_length, nonce, nonce_length, pstr, pstr_length);
    drbg->reseed_counter = 1;
    return true;
}

bool DRBG_HMAC_reseed(DRBG_HMAC *drbg,
                      uint8_t *entropy, uint32_t entropy_length,
                      uint8_t *add_input, uint32_t add_length) {

    // seed_material = entropy_input || additional_input
    uint32_t seed_mat_length = entropy_length + add_length;
    uint8_t seed_mat[seed_mat_length];
    memcpy(seed_mat, entropy, entropy_length);
    memcpy(&seed_mat[entropy_length], add_input, add_length);

    DRBG_HMAC_Update(drbg, entropy, entropy_length, add_input, add_length, NULL, 0);
    drbg->reseed_counter = 1;
    return true;
}

bool DRBG_HMAC_generate(DRBG_HMAC *drbg,
                        const uint8_t *add_input, uint32_t add_length,
                        uint32_t return_length, uint8_t *output) {

    if (add_input != NULL && add_length != 0) {
        DRBG_HMAC_Update(drbg, add_input, add_length, NULL, 0, NULL, 0);
    }

    // since round is calculated to make output full of data returned
    // we directly calculate remaining bytes to fill up output
    for (uint32_t remain = return_length;; remain -= drbg->conf->out_len) {

        // V = hmac(Key, V)
        if (!drbg->conf->hmac(drbg->V, drbg->conf->out_len, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                              drbg->Key, drbg->conf->out_len, drbg->V))
            return false;

        // temp = temp || V
        // use the smaller one size, hash outputs up to hash_size length
        if (remain > drbg->conf->out_len) memcpy(&output[return_length - remain], drbg->V, drbg->conf->out_len);
        else {
            // output remains less than out_len, which reaches final block
            memcpy(&output[return_length - remain], drbg->V, remain);
            break;
        }
    }

    DRBG_HMAC_Update(drbg, add_input, add_length, NULL, 0, NULL, 0);
    drbg->reseed_counter++;

    return true;
}

bool DRBG_HMAC_uninstantiate(DRBG_HMAC *drbg) {

    // clear V and Key state
    memset(drbg->V, 0, drbg->conf->out_len);
    free(drbg->V);
    drbg->V = NULL;
    memset(drbg->Key, 0, drbg->conf->out_len);
    free(drbg->Key);
    drbg->Key = NULL;
    drbg->reseed_counter = 0;

    return true;
}