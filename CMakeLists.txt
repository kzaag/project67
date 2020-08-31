cmake_minimum_required(VERSION 3.18.2)
project(p67)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(DBG_FLAGS -D DEBUG -g -fsanitize=address) 

set(BUILD_FLAGS 
    -Wall 
    -Wpedantic 
    -pedantic
    -pthread
    -std=c99
    -Wmissing-prototypes
    -Wstrict-prototypes
    -Wold-style-definition
    -Wno-nonnull-compare
    -Werror
    -D _GNU_SOURCE
    ${DBG_FLAGS})

add_definitions(${BUILD_FLAGS})

file(GLOB_RECURSE libsrc "lib/*.h" "lib/*.c")

add_library(p67 SHARED ${libsrc})

target_link_libraries(p67 ssl crypto opus pulse pulse-simple)
