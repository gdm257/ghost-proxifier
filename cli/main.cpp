#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string>
#include "utils.h"

void PrintUsage() {
    printf("Ghost Proxifier - Process-level transparent proxy\n\n");
    printf("Usage: ghost-proxifier <command> [options]\n\n");
    printf("Commands:\n");
    printf("  list                     List all processes with proxy status\n");
    printf("  inject <name>             Watch + inject on start (clean, no stale connections)\n");
    printf("  inject <pid>              Inject existing process immediately\n");
    printf("  inject --tree <pid|name>  Also inject child processes\n");
    printf("  eject <pid>              Unload DLL from process\n");
    printf("  status                   Show global proxy status\n");
    printf("  config show              Display current config\n");
    printf("  config upstream add <name> <addr>   Add upstream proxy\n");
    printf("  config upstream rm <id>             Remove upstream proxy\n");
    printf("  config upstream use <name>          Switch active upstream\n");
    printf("  config dns <server>      Set DNS server\n");
    printf("  monitor                  Real-time traffic monitor (Ctrl+C to quit)\n");
}

// Forward declarations
extern int cmd_list(int argc, wchar_t* argv[]);
extern int cmd_inject(int argc, wchar_t* argv[]);
extern int cmd_eject(int argc, wchar_t* argv[]);
extern int cmd_status(int argc, wchar_t* argv[]);
extern int cmd_config(int argc, wchar_t* argv[]);
extern int cmd_monitor(int argc, wchar_t* argv[]);

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::wstring cmd = argv[1];

    int result = 1;

    if (cmd == L"list")        result = cmd_list(argc, argv);
    else if (cmd == L"inject") result = cmd_inject(argc, argv);
    else if (cmd == L"eject")  result = cmd_eject(argc, argv);
    else if (cmd == L"status") result = cmd_status(argc, argv);
    else if (cmd == L"config") result = cmd_config(argc, argv);
    else if (cmd == L"monitor") result = cmd_monitor(argc, argv);
    else {
        PrintUsage();
    }

    return result;
}
