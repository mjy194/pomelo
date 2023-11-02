#include "fmap.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sync/atom.h>

#ifdef WIN32
#include <mman.h>
#include <io.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

fmap_t* fmap_incref(fmap_t* map) {
    if (map) {
        atom_inc(&map->refcnt);
    }
    return map;
}

static void unmmap_file(fmap_t* map) {
    if (map && map->addr && map->size) {
        munmap(map->addr, map->size);
        map->addr = 0;
        map->size = 0;
    }
}

void fmap_release(fmap_t* map) {
    if (map && !atom_dec(&map->refcnt)) {
        unmmap_file(map);
        if (map->fd >= 0) {
            close(map->fd);
        }
        free(map);
    }
}

static int map_file(fmap_t* map) {
    if (!map->size) {
        return -EINVAL;
    }
    map->addr = mmap(0, map->size, map->prot, map->flags, map->fd, 0);
    if (map->addr == MAP_FAILED) {
        unmmap_file(map);
        return -errno;
    }
    return 0;
}

fmap_t* fmap_alloc(int fd, int prot, int flags) {
    fmap_t* map = calloc(sizeof(fmap_t), sizeof(*map));
    if (!map) {
        return map;
    }
    map->fd = dup(fd);
#ifndef WIN32
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
    if (map->fd < 0) {
        free(map);
        return 0;
    }
    struct stat st;
    if (fstat(fd, &st) == -1) {
        fmap_release(map);
        return 0;
    }
    map->size = st.st_size;
    map->prot = prot;
    map->flags = flags;
    if (map_file(map) == 0) {
        return fmap_incref(map);
    }
    fmap_release(map);
    return 0;
}

fmap_t* fmap_alloc_by_path(const char* path, int oflags, int prot, int flags) {
    int fd = open(path, oflags);
    if (fd < 0) {
        return 0;
    }
    fmap_t* map = fmap_alloc(fd, prot, flags);
    close(fd);
    return map;
}

fmap_t* fmap_alloc_creat_by_path(const char* path, int oflags, uint64_t filesz, int prot, int flags) {
    int fd = open(path, oflags, 0644);
    if (fd < 0) {
        return 0;
    }
#ifdef WIN32
    int rc = _chsize(fd, (long)filesz);
#else
    int rc = ftruncate(fd, filesz);
#endif
    if (rc == -1) {
        close(fd);
        return 0;
    }
    fmap_t* map = fmap_alloc(fd, prot, flags);
    close(fd);
    return map;
}

uint64_t fmap_write(fmap_t* map, const uint8_t* buf, uint64_t size) {
    uint64_t fptr = map->fptr;
    if (fptr + size > map->size) {
        fmap_truncate(map, fptr + size);
    }
    if (map->addr) {
        memcpy(map->addr + fptr, buf, size);
        map->fptr += size;
        return size;
    }
    return 0;
}

int fmap_truncate(fmap_t* map, uint64_t size) {
    unmmap_file(map);
#ifdef WIN32
    int rc = chsize(map->fd, (long)size);
#else
    int rc = ftruncate(map->fd, size);
#endif
    if (rc == -1) {
        return rc;
    }
    if (size) {
        map->size = size;
        rc = map_file(map);
    }
    return rc;
}

uint64_t fmap_size(const fmap_t* map) {
    if (map) {
        return map->size;
    }
    return 0;
}

