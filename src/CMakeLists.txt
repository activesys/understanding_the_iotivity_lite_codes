#
#   Copyright (C) 2014 - 2018 ACTIVESYS All rights reserved.
#
#   Top CMakeLists for CODES
#

##################################
# CMake preconditions for CODES.
cmake_minimum_required(VERSION 2.8)

##################################
# Set project name and version.
project(understanding_the_iotivity_lite_codes C)
set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 1)
set(PROJECT_VERSION_PATCH 0)

##################################
# Check necessary headers and libraries for CODES development
include(CheckIncludeFile)
include(CheckLibraryExists)

##################################
# Check C header files
CHECK_INCLUDE_FILE(stdio.h      HAVE_STDIO_H)
CHECK_INCLUDE_FILE(stdlib.h     HAVE_STDLIB_H)
CHECK_INCLUDE_FILE(stdint.h     HAVE_STDINT_H)
CHECK_INCLUDE_FILE(string.h     HAVE_STRING_H)
CHECK_INCLUDE_FILE(stdarg.h     HAVE_STDARG_H)
CHECK_INCLUDE_FILE(math.h       HAVE_MATH_H)
CHECK_INCLUDE_FILE(float.h      HAVE_FLOAT_H)
CHECK_INCLUDE_FILE(limits.h     HAVE_LIMITS_H)
CHECK_INCLUDE_FILE(ctype.h      HAVE_CTYPE_H)

if(NOT HAVE_STDIO_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"stdio.h\".")
endif()
if(NOT HAVE_STDLIB_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"stdlib.h\".")
endif()
if(NOT HAVE_STDINT_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"stdint.h\".")
endif()
if(NOT HAVE_STRING_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"string.h\".")
endif()
if(NOT HAVE_STDARG_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"stdarg.h\".")
endif()
if(NOT HAVE_MATH_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"math.h\".")
endif()
if(NOT HAVE_FLOAT_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"float.h\".")
endif()
if(NOT HAVE_LIMITS_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"limits.h\".")
endif()
if(NOT HAVE_CTYPE_H)
    message (FATAL_ERROR "ERROR: CMake can't find the standard C header file \"ctype.h\".")
endif()

# Check Header files of specified platform.
if(WIN32)
    CHECK_INCLUDE_FILE(windows.h    HAVE_WINDOWS_H)
    CHECK_INCLUDE_FILE(direct.h     HAVE_DIRECT_H)
    CHECK_INCLUDE_FILE(Winsock2.h   HAVE_WINSOCK2_H)

    if (NOT HAVE_WINDOWS_H)
        message (FATAL_ERROR "ERROR: CMake can't find the Windows API header file \"windows.h\".")
    endif()
    if (NOT HAVE_DIRECT_H)
        message (FATAL_ERROR "ERROR: CMake can't find the Windows API header file \"direct.h\".")
    endif()
    if (NOT HAVE_WINSOCK2_H)
        message (FATAL_ERROR "ERROR: CMake can't find the Windows API header file \"Winsock2.h\".")
    endif()
else(WIN32)
    CHECK_INCLUDE_FILE(sys/stat.h   HAVE_SYS_STAT_H)
    CHECK_INCLUDE_FILE(sys/time.h   HAVE_SYS_TIME_H)
    CHECK_INCLUDE_FILE(unistd.h     HAVE_UNISTD_H)

    if (NOT HAVE_SYS_STAT_H)
        message (FATAL_ERROR "ERROR: CMake can't find the POSIX API header file \"sys/stat.h\".")
    endif()
    if (NOT HAVE_SYS_TIME_H)
        message (FATAL_ERROR "ERROR: CMake can't find the POSIX API header file \"sys/time.h\".")
    endif()
    if (NOT HAVE_UNISTD_H)
        message (FATAL_ERROR "ERROR: CMake can't find the POSIX API header file \"unistd.h\".")
    endif()

    find_library(ASDEV_M_LIB m)
    if(NOT ASDEV_M_LIB)
        message (FATAL_ERROR "ERROR: CMake can't find the library \"m\".")
    endif()
endif(WIN32)

##################################
if(WIN32)
set(CMAKE_GENERATOR_PLATFORM x64)
if (NOT IOTIVITY_PREFIX)
    set(IOTIVITY_PREFIX "d:\\IoTivity")
endif()
endif(WIN32)

# Check IoTivity-lite
if(WIN32)
    set(IOTIVITY_LITE_LIB_PATH                      ${IOTIVITY_PREFIX}/lib)
    set(IOTIVITY_LITE_INCLUDE_PATH                  ${IOTIVITY_PREFIX}/include/)
    find_library(IOTIVITY_LITE_LIB IoTivity-lite    ${IOTIVITY_LITE_LIB_PATH})
    find_file(IOTIVITY_LITE_H oc_api.h              ${IOTIVITY_LITE_INCLUDE_PATH})
    set(IOTIVITY_LITE_INCLUDE                       ${IOTIVITY_LITE_INCLUDE_PATH})
else(WIN32)
    find_library(IOTIVITY_LITE_LIB iotivity-lite-client-server)
    find_file(IOTIVITY_LITE_H oc_api.h              /usr/local/include/iotivity-lite)
    find_path(IOTIVITY_LITE_INCLUDE oc_api.h        /usr/local/include/iotivity-lite)
endif(WIN32)

if(NOT IOTIVITY_LITE_LIB OR NOT IOTIVITY_LITE_H OR NOT IOTIVITY_LITE_INCLUDE)
    message (FATAL_ERROR "ERROR: CMake can't find the library \"IoTivity-lite\".")
endif()

##################################
# duff_device
include_directories(
    duff_device
)
set(DUFF_DEVICE_SOURCES
    duff_device/duff_device.c
)
add_executable(duff_device ${DUFF_DEVICE_SOURCES})

##################################
# init
if(WIN32)
include_directories(
    init
    ${IOTIVITY_LITE_INCLUDE}
    ${IOTIVITY_LITE_INCLUDE}/port/windows
)
else(WIN32)
include_directories(
    init
    ${IOTIVITY_LITE_INCLUDE}
    ${IOTIVITY_LITE_INCLUDE}/port/linux
)
endif(WIN32)

set(INIT_SERVER_SOURCES
    init/init_server.c
)
set(INIT_CLIENT_SOURCES
    init/init_client.c
)
add_definitions(-DOC_DYNAMIC_ALLOCATION -DOC_SERVER -DOC_CLIENT)
add_executable(init_server ${INIT_SERVER_SOURCES})
add_executable(init_client ${INIT_CLIENT_SOURCES})
if(WIN32)
target_link_libraries(init_server ${IOTIVITY_LITE_LIB} ws2_32 Iphlpapi)
target_link_libraries(init_client ${IOTIVITY_LITE_LIB} ws2_32 Iphlpapi)
else(WIN32)
target_link_libraries(init_server ${IOTIVITY_LITE_LIB})
target_link_libraries(init_client ${IOTIVITY_LITE_LIB})
endif(WIN32)

##################################
# oic_wk_con
if(WIN32)
include_directories(
    oic_wk_con
    ${IOTIVITY_LITE_INCLUDE}
    ${IOTIVITY_LITE_INCLUDE}/port/windows
)
else(WIN32)
include_directories(
    oic_wk_con
    ${IOTIVITY_LITE_INCLUDE}
    ${IOTIVITY_LITE_INCLUDE}/port/linux
)
endif(WIN32)

set(OIC_WK_CON_SERVER_SOURCES
    oic_wk_con/oic_wk_con_server.c
)
set(OIC_WK_CON_CLIENT_SOURCES
    oic_wk_con/oic_wk_con_client.c
)
add_definitions(-DOC_DYNAMIC_ALLOCATION -DOC_SERVER -DOC_CLIENT)
add_executable(oic_wk_con_server ${OIC_WK_CON_SERVER_SOURCES})
add_executable(oic_wk_con_client ${OIC_WK_CON_CLIENT_SOURCES})
if(WIN32)
target_link_libraries(oic_wk_con_server ${IOTIVITY_LITE_LIB} ws2_32 Iphlpapi)
target_link_libraries(oic_wk_con_client ${IOTIVITY_LITE_LIB} ws2_32 Iphlpapi)
else(WIN32)
target_link_libraries(oic_wk_con_server ${IOTIVITY_LITE_LIB})
target_link_libraries(oic_wk_con_client ${IOTIVITY_LITE_LIB})
endif(WIN32)

##################################
# idd
if(WIN32)
include_directories(
    idd
    ${IOTIVITY_LITE_INCLUDE}
    ${IOTIVITY_LITE_INCLUDE}/port/windows
)
else(WIN32)
include_directories(
    idd
    ${IOTIVITY_LITE_INCLUDE}
    ${IOTIVITY_LITE_INCLUDE}/port/linux
)
endif(WIN32)

set(IDD_SERVER_SOURCES
    idd/idd_server.c
)
set(IDD_CLIENT_SOURCES
    idd/idd_client.c
)
set(DEVICE_BUILDER_SERVER_SOURCES
    idd/device_builder_server.c
)
add_definitions(-DOC_DYNAMIC_ALLOCATION -DOC_SERVER -DOC_CLIENT)
add_executable(idd_server ${IDD_SERVER_SOURCES})
add_executable(idd_client ${IDD_CLIENT_SOURCES})
add_executable(device_builder_server ${DEVICE_BUILDER_SERVER_SOURCES})
if(WIN32)
target_link_libraries(idd_server ${IOTIVITY_LITE_LIB} ws2_32 Iphlpapi)
target_link_libraries(idd_client ${IOTIVITY_LITE_LIB} ws2_32 Iphlpapi)
target_link_libraries(device_builder_server ${IOTIVITY_LITE_LIB} ws2_32 Iphlpapi)
else(WIN32)
target_link_libraries(idd_server ${IOTIVITY_LITE_LIB})
target_link_libraries(idd_client ${IOTIVITY_LITE_LIB})
target_link_libraries(device_builder_server ${IOTIVITY_LITE_LIB})
endif(WIN32)

##################################
# collection
if(WIN32)
include_directories(
    collection
    ${IOTIVITY_LITE_INCLUDE}
    ${IOTIVITY_LITE_INCLUDE}/port/windows
)
else(WIN32)
include_directories(
    collection
    ${IOTIVITY_LITE_INCLUDE}
    ${IOTIVITY_LITE_INCLUDE}/port/linux
)
endif(WIN32)

set(COLLECTION_SERVER_SOURCES
    collection/collection_server.c
)
set(COLLECTION_CLIENT_SOURCES
    collection/collection_client.c
)
add_definitions(-DOC_DYNAMIC_ALLOCATION -DOC_SERVER -DOC_CLIENT -DOC_COLLECTIONS -DOC_COLLECTIONS_IF_CREATE)
add_executable(collection_server ${COLLECTION_SERVER_SOURCES})
add_executable(collection_client ${COLLECTION_CLIENT_SOURCES})
if(WIN32)
target_link_libraries(collection_server ${IOTIVITY_LITE_LIB} ws2_32 Iphlpapi)
target_link_libraries(collection_client ${IOTIVITY_LITE_LIB} ws2_32 Iphlpapi)
else(WIN32)
target_link_libraries(collection_server ${IOTIVITY_LITE_LIB})
target_link_libraries(collection_client ${IOTIVITY_LITE_LIB})
endif(WIN32)
