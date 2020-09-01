cmake_minimum_required(VERSION 3.13.0)
project(p67)

set(CMAKE_VERBOSE_MAKEFILE ON)

#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(DBG_FLAGS -D DEBUG -g -fsanitize=address) 

include_directories(include)

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

file(GLOB_RECURSE wssrc "server/*.c")

add_executable(server EXCLUDE_FROM_ALL ${wssrc})
target_link_libraries(server asan p67 pq)

file(GLOB_RECURSE cli_src "client/cli/*.c")
add_executable(cli ${cli_src})
target_link_libraries(cli asan p67)

add_custom_command(
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/gencert
    DEPENDS cert
    OUTPUT p2pcert p2pcert.cert
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    COMMENT "generating certificates")

set_property(
    SOURCE test/net.c 
    APPEND PROPERTY OBJECT_DEPENDS p2pcert p2pcert.cert)

add_custom_command(
    COMMAND ln -sf ${CMAKE_CURRENT_SOURCE_DIR}/server/ddl ./;
    OUTPUT ddl
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    COMMENT "linking ddl")

add_custom_command(
    COMMAND ln -f ${CMAKE_CURRENT_SOURCE_DIR}/server/main.conf.e ./;
    OUTPUT main.conf.e
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
    COMMENT "linking db config")

set_property(
    SOURCE ${wssrc}
    APPEND PROPERTY OBJECT_DEPENDS ddl main.conf.e)

install(TARGETS p67 LIBRARY DESTINATION lib)
install(DIRECTORY include/p67/ DESTINATION include/p67
        FILES_MATCHING PATTERN "*.h")
