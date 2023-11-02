cmake_minimum_required(VERSION 3.10)

set(SOLUTION_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

include_directories(${SOLUTION_DIR}/include)
include_directories(${SOLUTION_DIR}/lib)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${SOLUTION_DIR}/output/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${SOLUTION_DIR}/output/bin)

project(pomelo)

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_link_options(-Wl,-disable-new-dtags)
    set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
    add_compile_options("$<$<CONFIG:DEBUG>:-fno-omit-frame-pointer>")
elseif (APPLE)
    set(MACOSX_RPATH ON)
    set(CMAKE_INSTALL_RPATH "@executable_path/../lib")
    add_compile_options("$<$<CONFIG:DEBUG>:-fno-omit-frame-pointer>")
endif ()

add_compile_options("$<$<CONFIG:DEBUG>:-fsanitize=address>")
add_link_options("$<$<CONFIG:DEBUG>:-fsanitize=address>")

add_subdirectory(src/podbutil)
add_subdirectory(src/pomelodb)
