#pragma once
#include <stdint.h>

#if defined __GNUC__
    #define PACK(__Declaration__) __Declaration__ __attribute__ ((packed))
#elif _WIN32
    #define PACK(__Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
#endif

#ifndef ARRAY_SIZE
    #define ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))
#endif

#define MK_U16(l,h) ((uint16_t) (l) | (((uint16_t) (h)) << 8))
#define MK_U32(l,h) ((uint32_t) (l) | (((uint32_t) (h)) << 16))
#define MK_U64(l,h) ((uint64_t) (l) | (((uint64_t) (h)) << 32))

#define L16(n) ((uint16_t)((uint32_t)n & 0x0000FFFF))
#define H16(n) ((uint16_t)((uint32_t)n & 0xFFFF0000))

#define BYTE_IN_U64(u, i) (((u) >> (sizeof(uint64_t) * i)) & 0xff)

#ifndef O_CLOEXEC
#define O_CLOEXEC	0
#endif


#define b16swp(x) (((x)>>8) | ((x)<<8))