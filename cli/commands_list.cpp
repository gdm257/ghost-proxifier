#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include "utils.h"

int cmd_list(int argc, wchar_t* argv[]) {
    (void)argc; (void)argv;
    auto procs = EnumerateProcesses();

    // Sort: injected first, then by traffic volume descending
    std::sort(procs.begin(), procs.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
        if (a.injected != b.injected) return a.injected > b.injected;
        return (a.up + a.down) > (b.up + b.down);
    });

    printf("%-8s %-25s %10s %10s %5s %5s %7s %-12s\n",
           "PID", "Name", "UP", "DOWN", "Conns", "Lat", "Status", "Node");
    printf("%s\n", std::string(95, '-').c_str());

    for (auto& p : procs) {
        char upStr[32] = "-";
        char downStr[32] = "-";

        if (p.up >= 1073741824ULL)
            snprintf(upStr, 32, "%6.2f GB", p.up / 1073741824.0);
        else if (p.up >= 1048576ULL)
            snprintf(upStr, 32, "%6.2f MB", p.up / 1048576.0);
        else if (p.up > 0)
            snprintf(upStr, 32, "%6.2f KB", p.up / 1024.0);

        if (p.down >= 1073741824ULL)
            snprintf(downStr, 32, "%6.2f GB", p.down / 1073741824.0);
        else if (p.down >= 1048576ULL)
            snprintf(downStr, 32, "%6.2f MB", p.down / 1048576.0);
        else if (p.down > 0)
            snprintf(downStr, 32, "%6.2f KB", p.down / 1024.0);

        char latStr[16] = "-";
        if (p.latency >= 0) snprintf(latStr, 16, "%dms", p.latency);

        char nameBuf[26] = {};
        WideCharToMultiByte(CP_UTF8, 0, p.name.c_str(), -1, nameBuf, 26, NULL, NULL);
        // Strip newlines
        for (int i = 0; nameBuf[i]; i++)
            if (nameBuf[i] == '\n' || nameBuf[i] == '\r') nameBuf[i] = 0;

        printf("%-8lu %-25.25s %10s %10s %5d %5s %7s %-12s\n",
               p.pid, nameBuf,
               upStr, downStr,
               p.conns, latStr,
               p.injected ? "PROXY" : "DIRECT",
               p.node.c_str());
    }

    return 0;
}
