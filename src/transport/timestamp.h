#pragma once

#include <time.h>
#include <stdint.h>

#define USQUE_SECONDS ((uint64_t)1000000000ULL)

static inline uint64_t usque_timestamp(void) {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint64_t)tp.tv_sec * USQUE_SECONDS + (uint64_t)tp.tv_nsec;
}
