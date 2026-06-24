#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include "utils.h"

#pragma comment(lib, "ws2_32.lib")

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

    // --- Setup UDP stats listener ---
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET statsSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (statsSock != INVALID_SOCKET) {
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(45002);
        // Bind may fail if another monitor is running — that's OK, we still show process list
        bind(statsSock, (sockaddr*)&addr, sizeof(addr));
        // Non-blocking
        u_long nb = 1;
        ioctlsocket(statsSock, FIONBIO, &nb);

        // Export for future injections
        SetEnvironmentVariableA("GHOST_STATS_PORT", "45002");
    }

    printf("Ghost Proxifier - Real-time Traffic Monitor\n");
    printf("Press Ctrl+C to exit\n\n");

    // Hide cursor to prevent flicker
    printf("\x1b[?25l");

    char statsBuf[2048];

    while (g_monitorRunning) {
        // Drain any pending stats messages
        {
            int n = recv(statsSock, statsBuf, sizeof(statsBuf) - 1, 0);
            while (n > 0) {
                UpdateStatsFromMessage(statsBuf, n);
                n = recv(statsSock, statsBuf, sizeof(statsBuf) - 1, 0);
            }
        }

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

        // Move cursor to line 3 (below header) — don't clear entire screen
        printf("\x1b[3;1H");

        // Header
        printf("%-8s %-25s %10s %10s %5s %5s %-12s\x1b[K\n",
               "PID", "Name", "UP", "DOWN", "Conns", "Lat", "Node");
        printf("%s\x1b[K\n", std::string(80, '-').c_str());

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

            printf("%-8lu %-25.25s %10s %10s %5d %5s %-12s\x1b[K\n",
                   p.pid, nameBuf,
                   upStr, downStr,
                   p.conns, latStr,
                   p.node.c_str());
        }

        // Summary line
        char totalUpStr[32], totalDownStr[32];
        FormatBytes(totalUp, totalUpStr, sizeof(totalUpStr));
        FormatBytes(totalDown, totalDownStr, sizeof(totalDownStr));

        printf("\n\x1b[K"); // blank line before summary
        printf("Injected: %zu  |  Conns: %d  |  UP: %s  |  DOWN: %s\x1b[K\n",
               injected.size(), totalConns,
               totalUpStr, totalDownStr);

        // Clear any leftover lines from previous (longer) render
        printf("\x1b[J");

        // Drain any more stats that arrived during rendering
        {
            int n = recv(statsSock, statsBuf, sizeof(statsBuf) - 1, 0);
            while (n > 0) {
                UpdateStatsFromMessage(statsBuf, n);
                n = recv(statsSock, statsBuf, sizeof(statsBuf) - 1, 0);
            }
        }

        Sleep(1000);
    }

    // Cleanup: show cursor, reset console
    printf("\x1b[?25h");
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    if (statsSock != INVALID_SOCKET) closesocket(statsSock);
    WSACleanup();
    printf("\nMonitor stopped.\n");
    return 0;
}
