cmake_minimum_required(VERSION 3.18)
project(zvpn_server C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

find_path(ZSTD_INCLUDE_DIR zstd.h REQUIRED)
find_library(ZSTD_LIBRARY NAMES zstd zstd_static libzstd libzstd_static REQUIRED)

add_executable(zvpn-server zvpn_server.c)
target_include_directories(zvpn-server PRIVATE "${ZSTD_INCLUDE_DIR}")
target_link_libraries(zvpn-server PRIVATE "${ZSTD_LIBRARY}")

if(WIN32)
    # Winsock and process-memory metrics; Wintun is loaded dynamically.
    target_link_libraries(zvpn-server PRIVATE ws2_32 psapi)
endif()

if(MSVC)
    target_compile_options(zvpn-server PRIVATE /W4)
else()
    target_compile_options(zvpn-server PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(NOT WIN32)
    find_package(Threads REQUIRED)
    target_link_libraries(zvpn-server PRIVATE Threads::Threads)
endif()
