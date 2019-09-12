//
// Created by Ghost on 2019/9/11.
//

#ifndef DRBG_RANDOM_SOURCE_H
#define DRBG_RANDOM_SOURCE_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Get random resource from external DRBGs/NRBGs/physical sources
 *
 * @param min_len minimum bytes of result
 * @param max_len maximum bytes of result
 * @param prediction_resistance_flag request a reseed action if its parent is a DRBG
 * @param result
 * @return bytes of the result
 */
extern int Get_Entropy(uint32_t min_len, uint32_t max_len, bool prediction_resistance_flag, uint8_t *result);

#endif //DRBG_RANDOM_SOURCE_H
