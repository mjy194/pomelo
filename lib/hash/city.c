#include "city.h"
#include <string.h>

static uint64_t UNALIGNED_LOAD64(const char* p) {
    uint64_t result;
    memcpy(&result, p, sizeof(result));
    return result;
}

static uint32_t UNALIGNED_LOAD32(const char* p) {
    uint32_t result;
    memcpy(&result, p, sizeof(result));
    return result;
}

#ifdef _MSC_VER

#include <stdlib.h>
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)

#elif defined(__APPLE__)

// Mac OS X / Darwin features
#include <libkern/OSByteOrder.h>
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#elif defined(__sun) || defined(sun)

#include <sys/byteorder.h>
#define bswap_32(x) BSWAP_32(x)
#define bswap_64(x) BSWAP_64(x)

#elif defined(__FreeBSD__)

#include <sys/endian.h>
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)

#elif defined(__OpenBSD__)

#include <sys/types.h>
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)

#elif defined(__NetBSD__)

#include <machine/bswap.h>
#include <sys/types.h>
#if defined(__BSWAP_RENAME) && !defined(__bswap_32)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#endif

#else

#include <byteswap.h>

#endif

#ifdef WORDS_BIGENDIAN
#define uint32_in_expected_order(x) (bswap_32(x))
#define uint64_in_expected_order(x) (bswap_64(x))
#else
#define uint32_in_expected_order(x) (x)
#define uint64_in_expected_order(x) (x)
#endif

#if !defined(LIKELY)
#if HAVE_BUILTIN_EXPECT
#define LIKELY(x) (__builtin_expect(!!(x), 1))
#else
#define LIKELY(x) (x)
#endif
#endif

#define SHIFT_MIX(v) ((v) ^ ((v) >> 47))

static uint64_t city_fetch64(const char* p) {
    return uint64_in_expected_order(UNALIGNED_LOAD64(p));
}

static uint32_t city_fetch32(const char* p) {
    return uint32_in_expected_order(UNALIGNED_LOAD32(p));
}

// Some primes between 2^63 and 2^64 for various uses.
static const uint64_t k0 = 0xc3a5c85c97cb3127ULL;
static const uint64_t k1 = 0xb492b66fbe98f273ULL;
static const uint64_t k2 = 0x9ae16a3b2f90404fULL;

// Magic numbers for 32-bit hashing.  Copied from Murmur3.
static const uint32_t c1 = 0xcc9e2d51;
static const uint32_t c2 = 0x1b873593;

static uint32_t city_fmix(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

// Hash 128 input bits down to 64 bits of output.
// This is intended to be a reasonably good hash function.
static inline uint64_t city_hash128_to_64(const uint128_t* x) {
    // Murmur-inspired hashing.
    const uint64_t kMul = 0x9ddfea08eb382d69ULL;
    uint64_t a = (UINT128_L64(x) ^ UINT128_H64(x)) * kMul;
    a ^= (a >> 47);
    uint64_t b = (UINT128_H64(x) ^ a) * kMul;
    b ^= (b >> 47);
    b *= kMul;
    return b;
}

static uint32_t city_rotate32(uint32_t val, int shift) {
    // Avoid shifting by 32: doing so yields an undefined result.
    return shift == 0 ? val : ((val >> shift) | (val << (32 - shift)));
}

// Bitwise right rotate.  Normally this will compile to a single
// instruction, especially if the shift is a manifest constant.
static uint64_t city_rotate(uint64_t val, int shift) {
    // Avoid shifting by 64: doing so yields an undefined result.
    return shift == 0 ? val : ((val >> shift) | (val << (64 - shift)));
}

#define CITY_SWAP(T, a, b)                                                     \
    do {                                                                       \
        T tmp = a;                                                             \
        (a) = b;                                                               \
        (b) = tmp;                                                             \
    } while (0)

#undef PERMUTE3
#define PERMUTE3(a, b, c)                                                      \
    do {                                                                       \
        CITY_SWAP(uint32_t, a, b);                                             \
        CITY_SWAP(uint32_t, a, c);                                             \
    } while (0)

static uint32_t city_mur(uint32_t a, uint32_t h) {
    // Helper from Murmur3 for combining two 32-bit values.
    a *= c1;
    a = city_rotate32(a, 17);
    a *= c2;
    h ^= a;
    h = city_rotate32(h, 19);
    return h * 5 + 0xe6546b64;
}

static uint32_t city_hash32_len_0_to_4(const char* s, size_t len) {
    uint32_t b = 0;
    uint32_t c = 9;
    for (size_t i = 0; i < len; i++) {
        signed char v = s[i];
        b = b * c1 + v;
        c ^= b;
    }
    return city_fmix(city_mur(b, city_mur(len, c)));
}

static uint32_t city_hash32_len_5_to_12(const char* s, size_t len) {
    uint32_t a = len, b = a * 5, c = 9, d = b;
    a += city_fetch32(s);
    b += city_fetch32(s + len - 4);
    c += city_fetch32(s + ((len >> 1) & 4));
    return city_fmix(city_mur(c, city_mur(b, city_mur(a, d))));
}

static uint32_t city_hash32_len_13_to_24(const char* s, size_t len) {
    uint32_t a = city_fetch32(s - 4 + (len >> 1));
    uint32_t b = city_fetch32(s + 4);
    uint32_t c = city_fetch32(s + len - 8);
    uint32_t d = city_fetch32(s + (len >> 1));
    uint32_t e = city_fetch32(s);
    uint32_t f = city_fetch32(s + len - 4);
    uint32_t h = len;

    return city_fmix(city_mur(
        f, city_mur(e, city_mur(d, city_mur(c, city_mur(b, city_mur(a, h)))))));
}

static uint64_t city_hash_len_16(uint64_t u, uint64_t v) {
    uint128_t x = {u, v};
    return city_hash128_to_64(&x);
}

static uint64_t city_hash_len_16_with_mul(uint64_t u, uint64_t v,
                                          uint64_t mul) {
    // Murmur-inspired hashing.
    uint64_t a = (u ^ v) * mul;
    a ^= (a >> 47);
    uint64_t b = (v ^ a) * mul;
    b ^= (b >> 47);
    b *= mul;
    return b;
}

static uint64_t city_hash_len_0_to_16(const char* s, size_t len) {
    if (len >= 8) {
        uint64_t mul = k2 + len * 2;
        uint64_t a = city_fetch64(s) + k2;
        uint64_t b = city_fetch64(s + len - 8);
        uint64_t c = city_rotate(b, 37) * mul + a;
        uint64_t d = (city_rotate(a, 25) + b) * mul;
        return city_hash_len_16_with_mul(c, d, mul);
    }
    if (len >= 4) {
        uint64_t mul = k2 + len * 2;
        uint64_t a = city_fetch32(s);
        return city_hash_len_16_with_mul(len + (a << 3),
                                         city_fetch32(s + len - 4),
                                         mul);
    }
    if (len > 0) {
        uint8_t a = s[0];
        uint8_t b = s[len >> 1];
        uint8_t c = s[len - 1];
        uint32_t y = a + (b << 8);
        uint32_t z = len + (c << 2);
        return SHIFT_MIX(y * k2 ^ z * k0) * k2;
    }
    return k2;
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
static uint64_t city_hash_len_17_to_32(const char* s, size_t len) {
    uint64_t mul = k2 + len * 2;
    uint64_t a = city_fetch64(s) * k1;
    uint64_t b = city_fetch64(s + 8);
    uint64_t c = city_fetch64(s + len - 8) * mul;
    uint64_t d = city_fetch64(s + len - 16) * k2;
    return city_hash_len_16_with_mul(city_rotate(a + b, 43) +
                                         city_rotate(c, 30) + d,
                                     a + city_rotate(b + k2, 18) + c, mul);
}

// Return a 16-byte hash for 48 bytes.  Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
static uint128_t city_weak_hash_len_32_with_seeds1(uint64_t w, uint64_t x,
                                                   uint64_t y, uint64_t z,
                                                   uint64_t a, uint64_t b) {
    a += w;
    b = city_rotate(b + a + z, 21);
    uint64_t c = a;
    a += x;
    a += y;
    b += city_rotate(a, 44);
    uint128_t ret = {a + z, b + c};
    return ret;
}

// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
static uint128_t city_weak_hash_len_32_with_seeds(const char* s, uint64_t a,
                                                  uint64_t b) {
    return city_weak_hash_len_32_with_seeds1(
        city_fetch64(s), city_fetch64(s + 8),
                                             city_fetch64(s + 16),
                                             city_fetch64(s + 24), a, b);
}

// Return an 8-byte hash for 33 to 64 bytes.
static uint64_t city_hash_len_33_to_64(const char* s, size_t len) {
    uint64_t mul = k2 + len * 2;
    uint64_t a = city_fetch64(s) * k2;
    uint64_t b = city_fetch64(s + 8);
    uint64_t c = city_fetch64(s + len - 24);
    uint64_t d = city_fetch64(s + len - 32);
    uint64_t e = city_fetch64(s + 16) * k2;
    uint64_t f = city_fetch64(s + 24) * 9;
    uint64_t g = city_fetch64(s + len - 8);
    uint64_t h = city_fetch64(s + len - 16) * mul;
    uint64_t u = city_rotate(a + g, 43) + (city_rotate(b, 30) + c) * 9;
    uint64_t v = ((a + g) ^ d) + f + 1;
    uint64_t w = bswap_64((u + v) * mul) + h;
    uint64_t x = city_rotate(e + f, 42) + c;
    uint64_t y = (bswap_64((v + w) * mul) + g) * mul;
    uint64_t z = e + f + c;
    a = bswap_64((x + z) * mul + y) + b;
    b = SHIFT_MIX((z + a) * mul + d + h) * mul;
    return b + x;
}

uint32_t city_hash32(const void* s, size_t len) {
    if (len <= 24) {
        return len <= 12 ? (len <= 4 ? city_hash32_len_0_to_4(s, len)
                                     : city_hash32_len_5_to_12(s, len))
                         : city_hash32_len_13_to_24(s, len);
    }

    // len > 24
    uint32_t h = len, g = c1 * h, f = g;
    uint32_t a0 = city_rotate32(city_fetch32(s + len - 4) * c1, 17) * c2;
    uint32_t a1 = city_rotate32(city_fetch32(s + len - 8) * c1, 17) * c2;
    uint32_t a2 = city_rotate32(city_fetch32(s + len - 16) * c1, 17) * c2;
    uint32_t a3 = city_rotate32(city_fetch32(s + len - 12) * c1, 17) * c2;
    uint32_t a4 = city_rotate32(city_fetch32(s + len - 20) * c1, 17) * c2;
    h ^= a0;
    h = city_rotate32(h, 19);
    h = h * 5 + 0xe6546b64;
    h ^= a2;
    h = city_rotate32(h, 19);
    h = h * 5 + 0xe6546b64;
    g ^= a1;
    g = city_rotate32(g, 19);
    g = g * 5 + 0xe6546b64;
    g ^= a3;
    g = city_rotate32(g, 19);
    g = g * 5 + 0xe6546b64;
    f += a4;
    f = city_rotate32(f, 19);
    f = f * 5 + 0xe6546b64;
    size_t iters = (len - 1) / 20;
    do {
        uint32_t a0 = city_rotate32(city_fetch32(s) * c1, 17) * c2;
        uint32_t a1 = city_fetch32(s + 4);
        uint32_t a2 = city_rotate32(city_fetch32(s + 8) * c1, 17) * c2;
        uint32_t a3 = city_rotate32(city_fetch32(s + 12) * c1, 17) * c2;
        uint32_t a4 = city_fetch32(s + 16);
        h ^= a0;
        h = city_rotate32(h, 18);
        h = h * 5 + 0xe6546b64;
        f += a1;
        f = city_rotate32(f, 19);
        f = f * c1;
        g += a2;
        g = city_rotate32(g, 18);
        g = g * 5 + 0xe6546b64;
        h ^= a3 + a1;
        h = city_rotate32(h, 19);
        h = h * 5 + 0xe6546b64;
        g ^= a4;
        g = bswap_32(g) * 5;
        h += a4 * 5;
        h = bswap_32(h);
        f += a0;
        PERMUTE3(f, h, g);
        s += 20;
    } while (--iters != 0);
    g = city_rotate32(g, 11) * c1;
    g = city_rotate32(g, 17) * c1;
    f = city_rotate32(f, 11) * c1;
    f = city_rotate32(f, 17) * c1;
    h = city_rotate32(h + g, 19);
    h = h * 5 + 0xe6546b64;
    h = city_rotate32(h, 17) * c1;
    h = city_rotate32(h + f, 19);
    h = h * 5 + 0xe6546b64;
    h = city_rotate32(h, 17) * c1;
    return h;
}

uint64_t city_hash64(const void* s, size_t len) {
    if (len <= 32) {
        if (len <= 16) {
            return city_hash_len_0_to_16(s, len);
        } else {
            return city_hash_len_17_to_32(s, len);
        }
    } else if (len <= 64) {
        return city_hash_len_33_to_64(s, len);
    }

    // For strings over 64 bytes we hash the end first, and then as we
    // loop we keep 56 bytes of state: v, w, x, y, and z.
    uint64_t x = city_fetch64(s + len - 40);
    uint64_t y = city_fetch64(s + len - 16) + city_fetch64(s + len - 56);
    uint64_t z =
        city_hash_len_16(city_fetch64(s + len - 48) + len,
                                  city_fetch64(s + len - 24));
    uint128_t v = city_weak_hash_len_32_with_seeds(s + len - 64, len, z);
    uint128_t w = city_weak_hash_len_32_with_seeds(s + len - 32, y + k1, x);
    x = x * k1 + city_fetch64(s);

    // Decrease len to the nearest multiple of 64, and operate on 64-byte
    // chunks.
    len = (len - 1) & ~(size_t)63;
    do {
        x = city_rotate(x + y + v.first + city_fetch64(s + 8), 37) * k1;
        y = city_rotate(y + v.second + city_fetch64(s + 48), 42) * k1;
        x ^= w.second;
        y += v.first + city_fetch64(s + 40);
        z = city_rotate(z + w.first, 33) * k1;
        v = city_weak_hash_len_32_with_seeds(s, v.second * k1, x + w.first);
        w = city_weak_hash_len_32_with_seeds(s + 32, z + w.second,
                                             y + city_fetch64(s + 16));
        CITY_SWAP(uint64_t, z, x);
        s += 64;
        len -= 64;
    } while (len != 0);
    return city_hash_len_16(city_hash_len_16(v.first, w.first) +
                                SHIFT_MIX(y) * k1 + z,
                            city_hash_len_16(v.second, w.second) + x);
}
