//
// Created by Ghost on 2019/9/11.
//

#include "include/drbg_hash.h"

bool hash_df(DRBG_HASH_CONF *conf,
             const uint8_t *input, uint32_t input_length,
             uint8_t *output, uint32_t return_length) {

    uint8_t counter = 0;
    uint8_t temp[conf->out_len];
    // for every round, hash function output outlen bytes data

    // since round is calculated to make output full of data returned
    // we directly calculate remaining bytes to fill up output
    uint8_t to_hash[1 + 4 + input_length];
    for (uint32_t remain = return_length;; remain -= conf->out_len) {

        to_hash[0] = ++counter;
        to_hash[1] = (uint8_t) ((input_length >> 24u) & 0xffu);
        to_hash[2] = (uint8_t) ((input_length >> 16u) & 0xffu);
        to_hash[3] = (uint8_t) ((input_length >> 8u) & 0xffu);
        to_hash[4] = (uint8_t) (input_length & 0xffu);
        memcpy(&to_hash[5], input, input_length);

        uint32_t len =
                conf->hash(to_hash, 1 + 4 + input_length, temp);
        if (len == 0) return false;

        // use the smaller one size, hash outputs up to hash_size length
        if (remain > len) memcpy(&output[return_length - remain], temp, len);
        else {
            // output remains less than out_len, which reaches final block
            memcpy(&output[return_length - remain], temp, remain);
            break;
        }
    }

    return true;
}

bool DRBG_HASH_new(DRBG_HASH *drbg, DRBG_HASH_CONF *conf) {

    // validate config
    if (conf == NULL || conf->hash == NULL ||
        conf->seed_len == 0 ||
        conf->out_len == 0 ||
        conf->reseed_interval == 0 ||
        conf->security_strength == 0)
        return false;

    drbg->conf = conf;

    /* initialize internal state */
    uint8_t *v = malloc(conf->seed_len);
    memset(v, 0, conf->seed_len);
    drbg->V = v;
    uint8_t *c = malloc(conf->seed_len);
    memset(c, 0, conf->seed_len);
    drbg->C = c;
    drbg->reseed_counter = 0;
    drbg->prediction_resistance_flag = false;
    return true;
}

bool DRBG_HASH_instantiate(DRBG_HASH *drbg,
                           const uint8_t *entropy, uint32_t entropy_length,
                           const uint8_t *nonce, uint32_t nonce_length,
                           const uint8_t *pstr, uint32_t pstr_length) {

    // seed_material = entropy_input || nonce || personalization_string
    uint32_t mat_length = entropy_length + nonce_length + pstr_length;
    uint8_t seed_mat[mat_length];
    memcpy(seed_mat, entropy, entropy_length);
    memcpy(seed_mat, nonce, nonce_length);
    memcpy(seed_mat, pstr, pstr_length);

    // V = Hash_df(seed_material, seed_len)
    hash_df(drbg->conf,
            seed_mat, mat_length,
            drbg->V, drbg->conf->seed_len);

    // C = Hash_df(0x00||V, seed_len)
    uint8_t ctmp[1 + drbg->conf->seed_len];
    ctmp[0] = 0x00;
    memcpy(&ctmp[1], drbg->V, drbg->conf->seed_len);
    hash_df(drbg->conf,
            ctmp, 1 + drbg->conf->seed_len,
            drbg->C, drbg->conf->seed_len);

    drbg->reseed_counter = 1;
    return true;

}

bool DRBG_HASH_reseed(DRBG_HASH *drbg,
                      uint8_t *entropy, uint32_t entropy_length,
                      uint8_t *add_input, uint32_t add_length) {

    // seed_material = 0x01 || V || entropy_input || additional_input
    uint32_t mat_length = 1 + drbg->conf->seed_len + entropy_length + add_length;
    uint8_t seed_mat[mat_length];
    seed_mat[0] = 0x01;
    memcpy(&seed_mat[1], drbg->V, drbg->conf->seed_len);
    memcpy(&seed_mat[1 + drbg->conf->seed_len], entropy, entropy_length);
    memcpy(&seed_mat[1 + drbg->conf->seed_len + entropy_length], add_input, add_length);

    // V = Hash_df(seed_material, seed_len)
    hash_df(drbg->conf,
            seed_mat, mat_length,
            drbg->V, drbg->conf->seed_len);

    // C = Hash_df(0x00||V, seed_len)
    uint8_t ctmp[1 + drbg->conf->seed_len];
    ctmp[0] = 0x00;
    memcpy(&ctmp[1], drbg->V, drbg->conf->seed_len);
    hash_df(drbg->conf,
            ctmp, 1 + drbg->conf->seed_len,
            drbg->C, drbg->conf->seed_len);

    drbg->reseed_counter = 1;
    return true;
}

// modify from openssl/crypto/rand/drbg_hash.c
bool add_bytes(DRBG_HASH *drbg, uint8_t *dst,
               const uint8_t *in, uint32_t inlen) {
    uint32_t i;
    uint32_t result;
    const uint8_t *add;
    uint8_t carry = 0, *d;

    if (!(drbg->conf->seed_len >= 1 && inlen >= 1 && inlen <= drbg->conf->seed_len)) return false;

    d = &dst[drbg->conf->seed_len - 1];
    add = &in[inlen - 1];

    for (i = inlen; i > 0; i--, d--, add--) {
        result = *d + *add + carry;
        carry = (uint8_t) (result >> 8u);
        *d = (uint8_t) (result & 0xffu);
    }

    if (carry != 0) {
        /* Add the carry to the top of the dst if inlen is not the same size */
        for (i = drbg->conf->seed_len - inlen; i > 0; --i, d--) {
            *d += 1;     /* Carry can only be 1 */
            if (*d != 0) /* exit if carry doesnt propagate to the next byte */
                break;
        }
    }
    return true;
}

bool hashgen(DRBG_HASH *drbg, uint32_t return_length, uint8_t *output) {

    // data = V
    uint8_t data[drbg->conf->seed_len];
    memcpy(data, drbg->V, drbg->conf->seed_len);

    // since round is calculated to make output full of data returned
    // we directly calculate remaining bytes to fill up output
    uint8_t tmp[drbg->conf->out_len];
    for (uint32_t remain = return_length;; remain -= drbg->conf->out_len) {

        // W = W || hash(data), till full of return length long bytes
        uint32_t len = drbg->conf->hash(data, drbg->conf->seed_len, tmp);
        if (len == 0) return false;

        // use the smaller one size, hash outputs up to hash_size length
        if (remain > len) memcpy(&output[return_length - remain], tmp, len);
        else {
            // output remains less than out_len, which reaches final block
            memcpy(&output[return_length - remain], tmp, remain);
            break;
        }

        // data = (data + 1) mod 2^seed_len
        uint8_t one = 1;
        add_bytes(drbg, data, &one, 1);
    }

    return true;
}

bool DRBG_HASH_generate(DRBG_HASH *drbg,
                        uint8_t *add_input, uint32_t add_length,
                        uint32_t req_length, uint8_t *result) {

    if (add_input == NULL) {

        // w = hash(0x02||V||additional_input)
        uint32_t tmp_len = 1 + drbg->conf->seed_len + add_length;
        uint8_t tmp[tmp_len];
        uint8_t w[drbg->conf->out_len];

        tmp[0] = 0x02;
        memcpy(&tmp[1], drbg->V, drbg->conf->seed_len);
        memcpy(&tmp[1 + drbg->conf->seed_len], add_input, add_length);
        uint32_t len = drbg->conf->hash(tmp, tmp_len, w);
        if (len == 0) return false;

        // V = (V + w) mod 2^seed_len
        add_bytes(drbg, drbg->V, w, drbg->conf->out_len);
    }

    hashgen(drbg, req_length, result);

    // H = hash(0x03||V)
    uint8_t htmp[1 + drbg->conf->seed_len];
    uint8_t H[drbg->conf->out_len];
    htmp[0] = 0x03;
    memcpy(&htmp[1], drbg->V, drbg->conf->seed_len);
    uint32_t len = drbg->conf->hash(htmp, 1 + drbg->conf->seed_len, H);
    if (len == 0) return false;

    // V = (V + H + C + reseed_counter) mod 2^seed_len
    add_bytes(drbg, drbg->V, H, drbg->conf->out_len);
    add_bytes(drbg, drbg->V, drbg->C, drbg->conf->seed_len);

    uint8_t counter[4];
    uint32_t reseed_counter = drbg->reseed_counter;

    counter[0] = (uint8_t) ((reseed_counter >> 24u) & 0xffu);
    counter[1] = (uint8_t) ((reseed_counter >> 16u) & 0xffu);
    counter[2] = (uint8_t) ((reseed_counter >> 8u) & 0xffu);
    counter[3] = (uint8_t) (reseed_counter & 0xffu);
    add_bytes(drbg, drbg->V, counter, 4);

    drbg->reseed_counter++;
    return true;
}

bool DRBG_HASH_uninstantiate(DRBG_HASH *drbg) {

    // clear V and C state
    memset(drbg->V, 0, drbg->conf->seed_len);
    free(drbg->V);
    drbg->V = NULL;
    memset(drbg->C, 0, drbg->conf->seed_len);
    free(drbg->C);
    drbg->C = NULL;
    drbg->reseed_counter = 0;

    return true;
}
