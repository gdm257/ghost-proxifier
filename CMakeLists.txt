cmake_minimum_required(VERSION 3.15)
project(GhostProxifier)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
set(CMAKE_CXX_STANDARD 17)
if(MSVC)
    add_compile_options(/utf-8)
endif()

# Unified output directory — all .exe/.dll go directly to bin/
foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_SOURCE_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_SOURCE_DIR}/bin)
endforeach()

add_subdirectory(minhook)
add_subdirectory(core)
# CLI is x64-only (manages both x64 and x86 injections)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_subdirectory(cli)
endif()

# Install
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    install(TARGETS ghost_core ghost-proxifier ghost_launcher ghost_dns_dump
            RUNTIME DESTINATION .
            LIBRARY DESTINATION .)
else()
    install(TARGETS ghost_core ghost_launcher ghost_dns_dump
            RUNTIME DESTINATION .
            LIBRARY DESTINATION .)
endif()
