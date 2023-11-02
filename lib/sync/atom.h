#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#include <windows.h>

#define atom_inc(v) InterlockedIncrement((v))
#define atom_dec(v) InterlockedDecrement((v))
#else
#define atom_inc(v) __sync_add_and_fetch((v), 1)
#define atom_dec(v) __sync_sub_and_fetch((v), 1)
#endif

#ifdef __cplusplus
}
#endif