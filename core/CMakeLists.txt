include_directories(${CMAKE_SOURCE_DIR}/minhook/include)

set(CORE_SOURCES
    ghost_core.cpp
    globals.h
    shellcode.cpp
    hooks_socket.cpp
    hooks_dns.cpp
    injector.cpp
    proxy.cpp
    dns.cpp
    dns_cache.cpp
    dns_pool.cpp
    config.cpp
    utils.cpp
)

add_library(ghost_core MODULE ${CORE_SOURCES})
add_library(ghost_injector STATIC ghost_injector.cpp)
add_executable(ghost_launcher ghost_launcher.cpp)
add_executable(ghost_dns_dump ghost_dns_dump.cpp)

target_link_libraries(ghost_core minhook ws2_32)
target_link_libraries(ghost_injector ws2_32 psapi shell32)
target_link_libraries(ghost_dns_dump ws2_32)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(ghost_core PROPERTIES OUTPUT_NAME "ghost_core_x64")
    set_target_properties(ghost_launcher PROPERTIES OUTPUT_NAME "ghost_launcher_x64")
else()
    set_target_properties(ghost_core PROPERTIES OUTPUT_NAME "ghost_core_x86")
    set_target_properties(ghost_launcher PROPERTIES OUTPUT_NAME "ghost_launcher_x86")
endif()

set_target_properties(ghost_dns_dump PROPERTIES OUTPUT_NAME "ghost_dns_dump")
set(CMAKE_BUILD_TYPE Release)
