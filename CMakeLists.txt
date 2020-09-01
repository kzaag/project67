cmake_minimum_required(VERSION 3.18.2)
project(p67)

set(CMAKE_VERBOSE_MAKEFILE ON)

#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(DBG_FLAGS -D DEBUG -g -fsanitize=address) 

include_directories(lib/include)

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

file(GLOB_RECURSE libsrc "lib/*.c")

add_library(p67 SHARED ${libsrc})
target_link_libraries(p67 ssl crypto opus pulse pulse-simple asan)

add_executable(async test/async.c)
target_link_libraries(async asan p67)

add_executable(cert test/cert.c)
target_link_libraries(cert asan p67)

add_executable(net test/net.c)
target_link_libraries(net asan p67)

add_executable(p2pnet test/p2pnet.c)
target_link_libraries(p2pnet asan p67)

add_executable(pdp test/pdp.c)
target_link_libraries(pdp asan p67)

add_executable(stream test/stream.c)
target_link_libraries(stream asan p67)


