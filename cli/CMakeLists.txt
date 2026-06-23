cmake_minimum_required(VERSION 3.15)
project(GhostProxifierCLI)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
if(MSVC)
    add_compile_options(/utf-8)
endif()

include_directories(${CMAKE_SOURCE_DIR}/third_party/nlohmann)

set(CLI_SOURCES
    main.cpp
    commands_list.cpp
    commands_inject.cpp
    commands_config.cpp
    commands_status.cpp
    commands_proxy.cpp
    commands_dns.cpp
    commands_monitor.cpp
    process_tree.cpp
    udp_client.cpp
    utils.cpp
)

add_executable(ghost-proxifier ${CLI_SOURCES})
target_link_libraries(ghost-proxifier ws2_32 wininet psapi)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(ghost-proxifier PROPERTIES OUTPUT_NAME "ghost-proxifier")
else()
    set_target_properties(ghost-proxifier PROPERTIES OUTPUT_NAME "ghost-proxifier_x86")
endif()

# Install rule
install(TARGETS ghost-proxifier RUNTIME DESTINATION .)
