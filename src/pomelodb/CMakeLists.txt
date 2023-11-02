cmake_minimum_required(VERSION 3.10)

add_definitions(-D_LARGEFILE64_SOURCE=1)
add_definitions(-DPODB_EXPORTS)

project(pomelodb)

set(TARGET_SRC
    database.cpp

    ${SOLUTION_DIR}/lib/hash/byte_order.c
    ${SOLUTION_DIR}/lib/hash/md5.c
    ${SOLUTION_DIR}/lib/hash/sha1.c
    ${SOLUTION_DIR}/lib/hash/sha512.c
    ${SOLUTION_DIR}/lib/fs/fmap.c
)

if (WIN32)
    list(APPEND TARGET_SRC
        ${SOLUTION_DIR}/lib/mman.c
    )
endif ()

set(ZLIB_SRC
    ${SOLUTION_DIR}/lib/zlib/adler32.c
    ${SOLUTION_DIR}/lib/zlib/compress.c
    ${SOLUTION_DIR}/lib/zlib/crc32.c
    ${SOLUTION_DIR}/lib/zlib/deflate.c
    ${SOLUTION_DIR}/lib/zlib/gzclose.c
    ${SOLUTION_DIR}/lib/zlib/gzlib.c
    ${SOLUTION_DIR}/lib/zlib/gzread.c
    ${SOLUTION_DIR}/lib/zlib/gzwrite.c
    ${SOLUTION_DIR}/lib/zlib/infback.c
    ${SOLUTION_DIR}/lib/zlib/inffast.c
    ${SOLUTION_DIR}/lib/zlib/inflate.c
    ${SOLUTION_DIR}/lib/zlib/inftrees.c
    ${SOLUTION_DIR}/lib/zlib/trees.c
    ${SOLUTION_DIR}/lib/zlib/uncompr.c
    ${SOLUTION_DIR}/lib/zlib/zutil.c
)

add_library(${PROJECT_NAME} SHARED ${TARGET_SRC} ${ZLIB_SRC})

set_target_properties(${PROJECT_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

if (NOT WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS -Wl,-undefined,error)
endif ()