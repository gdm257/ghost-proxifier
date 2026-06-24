set(CLI_SOURCES
    main.cpp
    commands_list.cpp
    commands_inject.cpp
    commands_config.cpp
    commands_status.cpp
    commands_proxy.cpp
    commands_monitor.cpp
    process_tree.cpp
    utils.cpp
)

add_executable(ghost-proxifier ${CLI_SOURCES})
target_include_directories(ghost-proxifier PRIVATE ${CMAKE_SOURCE_DIR}/third_party)
target_link_libraries(ghost-proxifier ws2_32 wininet psapi)
set_target_properties(ghost-proxifier PROPERTIES OUTPUT_NAME "ghost-proxifier")

install(TARGETS ghost-proxifier RUNTIME DESTINATION .)
