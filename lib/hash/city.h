#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint64_t first;
    uint64_t second;
} uint128_t;

#define UINT128_L64(x) ((x) ? (x)->first : 0)
#define UINT128_H64(x) ((x) ? (x)->second : 0)

uint32_t city_hash32(const void* buf, size_t len);
uint64_t city_hash64(const void* buf, size_t len);

#ifdef __cplusplus
}
#endif
