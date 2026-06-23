#include <windows.h>
#include <stdio.h>
#include "utils.h"

int cmd_status(int argc, wchar_t* argv[]) {
    (void)argc; (void)argv;

    auto procs = EnumerateProcesses();

    int injectedCount = 0;
    uint64_t totalUp = 0, totalDown = 0;
    int totalConns = 0;

    for (auto& p : procs) {
        if (p.injected) {
            injectedCount++;
            totalUp += p.up;
            totalDown += p.down;
            totalConns += p.conns;
        }
    }

    printf("Ghost Proxifier Status\n");
    printf("======================\n\n");
    printf("Injected processes: %d\n", injectedCount);
    printf("Total connections:  %d\n", totalConns);

    if (totalUp >= 1073741824ULL)
        printf("Total upload:       %6.2f GB\n", totalUp / 1073741824.0);
    else
        printf("Total upload:       %6.2f MB\n", totalUp / 1048576.0);

    if (totalDown >= 1073741824ULL)
        printf("Total download:     %6.2f GB\n", totalDown / 1073741824.0);
    else
        printf("Total download:     %6.2f MB\n", totalDown / 1048576.0);

    json cfg = LoadConfig();
    printf("\nDNS server:         %s\n",
           cfg["dns"].value("server", "System").c_str());

    if (cfg.contains("upstream") && cfg["upstream"].is_array()) {
        printf("\nUpstream nodes:\n");
        for (auto& u : cfg["upstream"]) {
            std::string marker = u.value("active", false) ? "*" : " ";
            std::string name = u.value("name", u.value("id", "?"));
            std::string addr = u.value("addr", "?");
            printf("  %s %s @ %s\n", marker.c_str(), name.c_str(), addr.c_str());
        }
    }

    printf("\nSystem proxy:       %s\n", IsSystemProxyEnabled() ? "ON" : "OFF");

    return 0;
}
