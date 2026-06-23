cmake_minimum_required(VERSION 3.15)
project(GhostProxifier)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
set(CMAKE_CXX_STANDARD 17)
if(MSVC)
    add_compile_options(/utf-8)
endif()

# Unified output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/$<CONFIG>)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/$<CONFIG>)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/$<CONFIG>)

add_subdirectory(minhook)
add_subdirectory(core)
add_subdirectory(cli)

# Install
install(TARGETS ghost_core ghost-proxifier ghost_launcher ghost_dns_dump
        RUNTIME DESTINATION .
        LIBRARY DESTINATION .)
