#pragma once

#include <stdint.h>

#define USQUE_SECONDS ((uint64_t)1000000000ULL)

#ifdef _WIN32
#include <windows.h>

static inline uint64_t usque_timestamp(void) {
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    /* Convert to nanoseconds */
    return (uint64_t)((double)counter.QuadPart / (double)freq.QuadPart * 1e9);
}

#else
#include <time.h>

static inline uint64_t usque_timestamp(void) {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint64_t)tp.tv_sec * USQUE_SECONDS + (uint64_t)tp.tv_nsec;
}

#endif
