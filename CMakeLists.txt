cmake_minimum_required(VERSION 2.8)
project(lora-opcua-server)
set (EXE_NAME lora-opcua-server)

#########################################################
# Add mbedTLS submodule                                 #
#########################################################
set (MBEDTLS_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set (MBEDTLS_MODULE_NAME "mbedtls")
string( TOUPPER ${MBEDTLS_MODULE_NAME} MBEDTLS_MODULE_NAME_UPPER )
if ( NOT TARGET ${MBEDTLS_MODULE_NAME} )
    set(ENABLE_TESTING OFF CACHE BOOL "Enable mbedTLS tests" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "Enable mbedTLS programs" FORCE)
    message( STATUS "Adding subdirectory ${MBEDTLS_MODULE_PATH}/${MBEDTLS_MODULE_NAME} as subdirectory ${CMAKE_CURRENT_LIST_DIR}/staging/${MBEDTLS_MODULE_NAME}." )
    add_subdirectory(${MBEDTLS_MODULE_PATH}/${MBEDTLS_MODULE_NAME} staging/${MBEDTLS_MODULE_NAME})
endif()
set( ${MBEDTLS_MODULE_NAME_UPPER}_INCLUDE_DIR "${MBEDTLS_MODULE_PATH}/${MBEDTLS_MODULE_NAME}/include/" CACHE STRING "${MBEDTLS_MODULE_NAME} include path" FORCE )
set( ${MBEDTLS_MODULE_NAME_UPPER}_LIB_DIR "${CMAKE_CURRENT_BINARY_DIR}" CACHE STRING "${MBEDTLS_MODULE_NAME} library path" FORCE )
set( ${MBEDTLS_MODULE_NAME_UPPER}_LIB_NAME "${MBEDTLS_MODULE_NAME}" CACHE STRING "${MBEDTLS_MODULE_NAME} library name" FORCE )
message( STATUS "${MBEDTLS_MODULE_NAME_UPPER}_INCLUDE_DIR: ${${MBEDTLS_MODULE_NAME_UPPER}_INCLUDE_DIR}")
message( STATUS "${MBEDTLS_MODULE_NAME_UPPER}_LIB_DIR: ${${MBEDTLS_MODULE_NAME_UPPER}_LIB_DIR}")
message( STATUS "${MBEDTLS_MODULE_NAME_UPPER}_LIB_NAME: ${${MBEDTLS_MODULE_NAME_UPPER}_LIB_NAME}")
include_directories(${MBEDTLS_INCLUDE_DIR})
link_directories(${MBEDTLS_LIB_DIR})
#########################################################
# Add freeopcua-test submodule                          #
#########################################################
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/freeopcua-test)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/freeopcua-test/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR})


add_executable(${EXE_NAME} src/main.cpp
                           src/lora.cpp
                           src/packet_fwd_protocol.cpp
                           src/parson.c
                           src/cmac.c)

target_link_libraries(${EXE_NAME} ${MBEDTLS_LIB_NAME} 
                                  opcuacore
                                  opcuaserver
                                  opcuaprotocol 
                                  freeopcuatest)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fpermissive")
