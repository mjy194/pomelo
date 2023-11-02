#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct fmap {
    volatile long refcnt;
    int fd;
    uint8_t* addr;
    uint64_t size;
    int prot;
    int flags;
    uint64_t fptr;
} fmap_t;

fmap_t* fmap_incref(fmap_t*);
void fmap_release(fmap_t*);

fmap_t* fmap_alloc(int fd, int prot, int flags);

fmap_t* fmap_alloc_by_path(const char* path, int oflags, int prot, int flags);

fmap_t* fmap_alloc_creat_by_path(const char* path, int oflags, uint64_t filesz, int prot, int flags);

uint64_t fmap_write(fmap_t* map, const uint8_t* buf, uint64_t size);

int fmap_truncate(fmap_t*, uint64_t size);

uint64_t fmap_size(const fmap_t*);

#ifdef __cplusplus
}
#endif // __cplusplus