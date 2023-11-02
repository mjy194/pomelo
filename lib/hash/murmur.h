#pragma once

#include <typedef.h>

inline uint64_t murmur_hash64(const void *key, int len) {
    const int r = 24;
    const uint32_t m = 0x5bd1e995;
    uint32_t seed = 0x29840270;

    const uint32_t* data = (const uint32_t *)key;

    const unsigned char *data_tail;
    uint32_t k1;
    uint32_t k2;
    uint32_t h2;

    uint64_t h;

    uint32_t h1 = seed ^ len;
    h2 = 0;

    while (len >= 8) {
        k1 = *data++;
        k1 *= m; k1 ^= k1 >> r; k1 *= m;
        h1 *= m; h1 ^= k1;

        k2 = *data++;
        k2 *= m; k2 ^= k2 >> r; k2 *= m;
        h2 *= m; h2 ^= k2;

        len -= 8;
    }

    if (len >= 4)
    {
        k1 = *data++;
        k1 *= m; k1 ^= k1 >> r; k1 *= m;
        h1 *= m; h1 ^= k1;
        len -= 4;
    }

    data_tail = (const unsigned char *)data;

    switch(len) {
        case 3:
            h2 ^= (uint32_t)(data_tail[2]) << 16;
        case 2:
            h2 ^= (uint32_t)(data_tail[1]) << 8;
        case 1:
            h2 ^= (uint32_t)(data_tail[0]);
            h2 *= m;
    };

    h1 ^= h2 >> 18; h1 *= m;
    h2 ^= h1 >> 22; h2 *= m;
    h1 ^= h2 >> 17; h1 *= m;
    h2 ^= h1 >> 19; h2 *= m;

    h = h1;
    h = (h << 32) | h2;

    return h;
}