cmake_minimum_required(VERSION 2.8)
project(lora-opcua-server)

include_directories(${MBEDTLS_INCLUDE_DIR})

aux_source_directory(src SRC_LIST)
set (EXE_NAME lora-opcua-server)


add_executable(${EXE_NAME} src/main.cpp
                           src/parson.c)
target_link_libraries(${EXE_NAME} mbedtls mbedcrypto)
target_compile_options(${EXE_NAME} PRIVATE "-std=c++11")
target_compile_options(${EXE_NAME} PRIVATE "-fpermissive")
