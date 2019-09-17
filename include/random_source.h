//
// Created by Ghost on 2019/9/11.
//

#ifndef DRBG_RANDOM_SOURCE_H
#define DRBG_RANDOM_SOURCE_H

#include <stdint.h>
#include <stdbool.h>

#if defined(__APPLE__)

#include <stdio.h>
#include <sys/random.h>

#elif defined(_Win32)
// Windows entropy random source header
#else
// Linux entropy random source header
#include <sys/random.h>
#endif

/**
 * Get random resource from external DRBGs/NRBGs/physical sources
 *  (in our implementation we use system call to get entropy,
 *  so that we need to use fixed length and ignore the prediction resistance flag)
 *
 * @param length bytes of result
 * @param prediction_resistance_flag request a reseed action if its parent is a DRBG // ignored
 * @param result
 * @return result code
 */
uint32_t Get_Entropy(uint32_t length, bool prediction_resistance_flag, uint8_t *result);

#endif //DRBG_RANDOM_SOURCE_H
