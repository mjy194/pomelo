cmake_minimum_required(VERSION 3.10)

include_directories(${SOLUTION_DIR}/src/pomelodb)

project(podbutil)

set(TARGET_SRC
    main.cpp
    app.cpp

    ${SOLUTION_DIR}/lib/hash/byte_order.c
    ${SOLUTION_DIR}/lib/hash/city.c
    ${SOLUTION_DIR}/lib/hash/md5.c
    ${SOLUTION_DIR}/lib/hash/sha1.c
    ${SOLUTION_DIR}/lib/hash/sha512.c
    ${SOLUTION_DIR}/lib/fs/fmap.c
)

if (WIN32)
    list(APPEND TARGET_SRC
        ${SOLUTION_DIR}/lib/mman.c
        ${SOLUTION_DIR}/lib/getopt/getopt.c
        ${SOLUTION_DIR}/lib/getopt/getopt_long.c
    )
endif ()

add_executable(${PROJECT_NAME} ${TARGET_SRC})

target_link_libraries(${PROJECT_NAME} pomelodb)