//
// Created by Ghost on 2019/9/17.
//

#include "../include/random_source.h"

uint32_t Get_Entropy(uint32_t length, bool prediction_resistance_flag, uint8_t *result) {

    uint32_t result_code = 0;
#if defined(__APPLE__)
    result_code = getentropy(result, length);
#elif defined(_Win32)
    // Windows entropy random source func
    int result = getrandom();
#else
    // Linux entropy random source func
    int result = getrandom(result, length, 0);
#endif

    return result_code;
}