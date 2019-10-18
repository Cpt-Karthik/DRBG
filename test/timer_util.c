//
// Created by Ghost on 2019/9/12.
//

#include "../include/test/timer_util.h"

static struct timeval t;

void print_time(int index) {
    uint32_t previous_ms = 0;
    uint64_t previous_s = 0;
    uint32_t interval;

    if (index != 1) {
        previous_s = t.tv_sec;
        previous_ms = t.tv_usec;
    }

    gettimeofday(&t, NULL);
    printf("start %d: %ld:%d", index, t.tv_sec, t.tv_usec);

    if (index != 1) {
        interval = (1000000 * (t.tv_sec - previous_s)) + t.tv_usec - previous_ms;
        printf("    passed time: %d\n", interval);
    } else {
        printf("\n");
    }
}
