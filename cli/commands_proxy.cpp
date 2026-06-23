#include <windows.h>
#include <stdio.h>
#include "utils.h"

int cmd_proxy(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: ghost-proxifier proxy <on|off>\n");
        return 1;
    }

    std::wstring action = argv[2];

    if (action == L"on") {
        // Read active upstream from config
        json cfg = LoadConfig();
        std::string proxyAddr = "127.0.0.1:7897"; // default

        if (cfg.contains("upstream") && cfg["upstream"].is_array()) {
            for (auto& u : cfg["upstream"]) {
                if (u.value("active", false)) {
                    proxyAddr = u.value("addr", "127.0.0.1:7897");
                    break;
                }
            }
        }

        SetSystemProxy(true, proxyAddr);
        printf("System proxy enabled: %s\n", proxyAddr.c_str());
        return 0;
    }

    if (action == L"off") {
        SetSystemProxy(false);
        printf("System proxy disabled\n");
        return 0;
    }

    fprintf(stderr, "Error: Unknown action '%ls' (expected on or off)\n", argv[2]);
    return 1;
}
