cmake_minimum_required(VERSION 3.15)
project(GhostProxifier)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
set(CMAKE_CXX_STANDARD 17)
if(MSVC)
    add_compile_options(/utf-8)
endif()

add_subdirectory(minhook)
add_subdirectory(core)
add_subdirectory(cli)

# Install
install(TARGETS ghost_core ghost-proxifier ghost_launcher ghost_dns_dump
        RUNTIME DESTINATION .
        LIBRARY DESTINATION .)
