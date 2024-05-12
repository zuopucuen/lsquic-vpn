# Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE.
CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

PROJECT(lsquic-vpn C)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $ENV{EXTRA_CFLAGS}")

INCLUDE_DIRECTORIES(boringssl/include)
INCLUDE_DIRECTORIES(lsquic/include)
INCLUDE_DIRECTORIES(lsquic/src/liblsquic) 

ADD_SUBDIRECTORY(boringssl)
ADD_SUBDIRECTORY(lsquic/src/liblsquic)

if(APPLE)
    # Need to install libevent, cmd is similar to "brew install libevent"
    INCLUDE_DIRECTORIES(/usr/local/include/)  
    LINK_DIRECTORIES(/usr/local/lib)
endif(APPLE)

SET(LIBS lsquic crypto ssl event m z)

add_executable(vpn_server vpn_server.c prog.c common.c cert.c os.c vpn.c)
add_executable(vpn_client vpn_client.c prog.c common.c cert.c os.c vpn.c) 

TARGET_LINK_LIBRARIES(vpn_server ${LIBS})
TARGET_LINK_LIBRARIES(vpn_client ${LIBS})

INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(sendmmsg HAVE_SENDMMSG)
CHECK_FUNCTION_EXISTS(recvmmsg HAVE_RECVMMSG)
CHECK_FUNCTION_EXISTS(open_memstream HAVE_OPEN_MEMSTREAM)


INCLUDE(CheckSymbolExists)

CHECK_SYMBOL_EXISTS(
    IP_MTU_DISCOVER
    "netinet/in.h"
    HAVE_IP_MTU_DISCOVER
)

CHECK_SYMBOL_EXISTS(
    IPV6_MTU_DISCOVER
    "netinet/in.h"
    HAVE_IPV6_MTU_DISCOVER
)

CHECK_SYMBOL_EXISTS(
    IP_DONTFRAG
    "netinet/in.h"
    HAVE_IP_DONTFRAG
)

CHECK_SYMBOL_EXISTS(
    preadv
    "sys/uio.h"
    HAVE_PREADV
)

INCLUDE(CheckIncludeFiles)

IF (MSVC AND PCRE_LIB)
FIND_PATH(EVENT_INCLUDE_DIR NAMES pcreposix.h)
IF (EVENT_INCLUDE_DIR)
    MESSAGE(STATUS "found pcreposix.h")
    SET(HAVE_REGEX 1)
ELSE()
    MESSAGE(FATAL_ERROR "event2/event.h was not found")
ENDIF()
ELSE()
CHECK_INCLUDE_FILES(regex.h HAVE_REGEX)
ENDIF()

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
