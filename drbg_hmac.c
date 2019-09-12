//
// Created by Ghost on 2019/9/12.
//

#include "include/drbg_hmac.h"

bool DRBG_HMAC_Update(DRBG_HMAC *drbg, uint8_t *pdata, uint32_t pdata_len) {

    uint32_t ktmp_len = drbg->conf->out_len + 1 + pdata_len;
    uint8_t ktmp[ktmp_len];

    // Key = hmac(Key, V || 0x00 || pdata)
    memcpy(ktmp, drbg->V, drbg->conf->out_len);
    ktmp[drbg->conf->out_len] = 0x00;
    memcpy(ktmp, pdata, pdata_len);
    uint32_t len = drbg->conf->hmac(ktmp, ktmp_len, drbg->Key, drbg->conf->out_len, drbg->Key);
    if (len == 0) return false;

    // V = hmac(Key, V)
    drbg->conf->hmac(drbg->V, drbg->conf->out_len, drbg->Key, drbg->conf->out_len, drbg->V);

    // if provided data is null, return
    if (pdata == NULL) return true;

    // Key = hmac(Key, V || 0x01 || pdata)
    memcpy(ktmp, drbg->V, drbg->conf->out_len);
    ktmp[drbg->conf->out_len] = 0x01;
    memcpy(ktmp, pdata, pdata_len);
    len = drbg->conf->hmac(ktmp, ktmp_len, drbg->Key, drbg->conf->out_len, drbg->Key);
    if (len == 0) return false;

    // V = hmac(Key, V)
    drbg->conf->hmac(drbg->V, drbg->conf->out_len, drbg->Key, drbg->conf->out_len, drbg->V);

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
    uint32_t seed_mat_length = entropy_length + nonce_length + pstr_length;
    uint8_t seed_mat[seed_mat_length];
    memcpy(seed_mat, entropy, entropy_length);
    memcpy(&seed_mat[entropy_length], nonce, nonce_length);
    memcpy(&seed_mat[entropy_length + nonce_length], pstr, pstr_length);

    // Key = 0x0000 with outlen
    memset(drbg->Key, 0x00, drbg->conf->out_len);
    // V = 0x0101 with outlen
    memset(drbg->V, 0x01, drbg->conf->out_len);

    DRBG_HMAC_Update(drbg, seed_mat, seed_mat_length);
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

    DRBG_HMAC_Update(drbg, seed_mat, seed_mat_length);
    drbg->reseed_counter = 1;
    return true;
}

bool DRBG_HMAC_generate(DRBG_HMAC *drbg,
                        uint8_t *add_input, uint32_t add_length,
                        uint32_t return_length, uint8_t *output) {

    if (add_input != NULL && add_length != 0) {
        DRBG_HMAC_Update(drbg, add_input, add_length);
    }

    // since round is calculated to make output full of data returned
    // we directly calculate remaining bytes to fill up output
    uint8_t tmp[drbg->conf->out_len];
    for (uint32_t remain = return_length;; remain -= drbg->conf->out_len) {

        // V = hmac(Key, V)
        uint32_t len = drbg->conf->hmac(drbg->V, drbg->conf->out_len,
                                        drbg->Key, drbg->conf->out_len, drbg->V);
        if (len == 0) return false;

        // use the smaller one size, hash outputs up to hash_size length
        if (remain > len) memcpy(&output[return_length - remain], tmp, len);
        else {
            // output remains less than out_len, which reaches final block
            memcpy(&output[return_length - remain], tmp, remain);
            break;
        }
    }

    DRBG_HMAC_Update(drbg, add_input, add_length);
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