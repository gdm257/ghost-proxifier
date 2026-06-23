#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include "utils.h"

static volatile bool g_monitorRunning = true;

// Console Ctrl handler
static BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_BREAK_EVENT) {
        g_monitorRunning = false;
        return TRUE;
    }
    return FALSE;
}

// Format bytes to human-readable with unit
static void FormatBytes(uint64_t bytes, char* out, size_t outSize) {
    if (bytes >= 1073741824ULL)
        snprintf(out, outSize, "%6.2f GB", bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)
        snprintf(out, outSize, "%6.2f MB", bytes / 1048576.0);
    else if (bytes >= 1024ULL)
        snprintf(out, outSize, "%6.2f KB", bytes / 1024.0);
    else
        snprintf(out, outSize, "%6llu B ", bytes);
}

int cmd_monitor(int argc, wchar_t* argv[]) {
    (void)argc; (void)argv;

    // Register Ctrl+C handler
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // Enable ANSI escape sequences on Windows 10+
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) {
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    printf("Ghost Proxifier - Real-time Traffic Monitor\n");
    printf("Press Ctrl+C to exit\n\n");

    // Store last tick counts to detect new data
    uint64_t lastTotalUp = 0;
    uint64_t lastTotalDown = 0;

    while (g_monitorRunning) {
        // Move cursor to line 4 (below header) and clear screen from cursor
        printf("\x1b[3;1H\x1b[J");

        auto procs = EnumerateProcesses();

        // Filter to injected processes only
        std::vector<ProcessInfo> injected;
        uint64_t totalUp = 0;
        uint64_t totalDown = 0;
        int totalConns = 0;

        for (auto& p : procs) {
            if (p.injected) {
                injected.push_back(p);
                totalUp += p.up;
                totalDown += p.down;
                totalConns += p.conns;
            }
        }

        // Sort by traffic descending
        std::sort(injected.begin(), injected.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
            return (a.up + a.down) > (b.up + b.down);
        });

        // Header
        printf("%-8s %-25s %10s %10s %5s %5s %-12s\n",
               "PID", "Name", "UP", "DOWN", "Conns", "Lat", "Node");
        printf("%s\n", std::string(80, '-').c_str());

        for (auto& p : injected) {
            char upStr[32] = "-";
            char downStr[32] = "-";
            FormatBytes(p.up, upStr, sizeof(upStr));
            FormatBytes(p.down, downStr, sizeof(downStr));

            char latStr[16] = "-";
            if (p.latency >= 0) snprintf(latStr, 16, "%dms", p.latency);

            char nameBuf[26] = {};
            WideCharToMultiByte(CP_UTF8, 0, p.name.c_str(), -1, nameBuf, 26, NULL, NULL);
            for (int i = 0; nameBuf[i]; i++)
                if (nameBuf[i] == '\n' || nameBuf[i] == '\r') nameBuf[i] = 0;

            printf("%-8lu %-25.25s %10s %10s %5d %5s %-12s\n",
                   p.pid, nameBuf,
                   upStr, downStr,
                   p.conns, latStr,
                   p.node.c_str());
        }

        char totalUpStr[32], totalDownStr[32];
        FormatBytes(totalUp, totalUpStr, sizeof(totalUpStr));
        FormatBytes(totalDown, totalDownStr, sizeof(totalDownStr));

        printf("\n");
        printf("Injected: %zu  |  Conns: %d  |  UP: %s  |  DOWN: %s  |  Proxy: %s\n",
               injected.size(), totalConns,
               totalUpStr, totalDownStr,
               IsSystemProxyEnabled() ? "ON" : "OFF");

        lastTotalUp = totalUp;
        lastTotalDown = totalDown;

        Sleep(1000);
    }

    // Reset console mode
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    printf("\nMonitor stopped.\n");
    return 0;
}
