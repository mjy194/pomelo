#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

inline static bool bin_to_hex(uint8_t* bin, size_t binsz, char* hex, size_t hexsz) {
    char dict[] = "0123456789abcdef";
    size_t i = 0, j = 0;

    memset(hex, 0, hexsz);

    for (; i < binsz && j < hexsz; i++) {
        hex[j++] = dict[(bin[i] >> 4) & 0x0F];
        hex[j++] = dict[bin[i] & 0x0F];
    }
    return i == binsz;
}


inline static size_t hex_to_bin(const char* hex, size_t hexsz, uint8_t* bin, size_t binsz) {
    memset(bin, 0, binsz);

    size_t bi = 0;
    for (size_t si = 0; si < hexsz && bi < binsz;) {
        for (int i = 0; i < 2; i++) {
            char ch = hex[si++];
            if (ch >= '0' && ch <= '9') {
                ch -= '0';
            } else {
                ch |= 0x20;
                if (ch >= 'a' && ch <= 'f') {
                    ch = ch - 'a' + 10;
                } else {
                    return -1;
                }
            }
            if (i == 0) {
                bin[bi] = ch << 0x04;
            } else {
                bin[bi] |= ch;
            }
        }
        bi++;
    }
    return bi;
}