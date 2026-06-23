#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <nlohmann/json.hpp>
#include "utils.h"

using json = nlohmann::json;
#pragma comment(lib, "ws2_32.lib")

static SOCKET g_udpSock = INVALID_SOCKET;
static std::thread g_udpThread;
static std::atomic<bool> g_running{false};
static std::atomic<bool> g_wsaInit{false};

struct UdpStatEntry {
    DWORD pid = 0;
    uint64_t up = 0;
    uint64_t down = 0;
    int conns = 0;
    int latency = -1;
    std::string node = "Direct";
    std::string dns = "System";
    DWORD lastSeen = 0;
};

static std::map<DWORD, UdpStatEntry> g_statMap;
static std::mutex g_statMutex;
static uint16_t g_udpPort = 18901;

void StartUdpListener(uint16_t port) {
    if (g_running) return;
    g_udpPort = port;

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;
    g_wsaInit = true;

    g_udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_udpSock == INVALID_SOCKET) {
        WSACleanup();
        g_wsaInit = false;
        return;
    }

    // Allow address reuse for quick restart
    int reuse = 1;
    setsockopt(g_udpSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(g_udpSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(g_udpSock);
        g_udpSock = INVALID_SOCKET;
        WSACleanup();
        g_wsaInit = false;
        return;
    }

    // Set non-blocking so thread can check g_running
    u_long mode = 1;
    ioctlsocket(g_udpSock, FIONBIO, &mode);

    g_running = true;
    g_udpThread = std::thread([]() {
        char buf[4096];
        while (g_running) {
            sockaddr_in from = {};
            int fromLen = sizeof(from);
            int n = recvfrom(g_udpSock, buf, sizeof(buf) - 1, 0, (sockaddr*)&from, &fromLen);
            if (n <= 0) {
                // WSAEWOULDBLOCK or timeout — sleep to avoid busy-wait
                Sleep(100);
                continue;
            }
            buf[n] = 0;

            try {
                json j = json::parse(buf);
                if (!j.is_object() || !j.contains("pid")) continue;

                std::lock_guard<std::mutex> lk(g_statMutex);
                DWORD pid = j.value("pid", 0);
                UdpStatEntry& e = g_statMap[pid];
                e.pid = pid;
                e.up = j.value("up", 0ULL);
                e.down = j.value("down", 0ULL);
                e.conns = j.value("conns", 0);
                e.latency = j.value("latency", -1);
                if (j.contains("node") && j["node"].is_string())
                    e.node = j["node"].get<std::string>();
                if (j.contains("dns") && j["dns"].is_string())
                    e.dns = j["dns"].get<std::string>();
                e.lastSeen = GetTickCount();
            } catch (...) {
                // Ignore malformed packets
            }
        }
    });
}

void StopUdpListener() {
    g_running = false;
    if (g_udpSock != INVALID_SOCKET) {
        closesocket(g_udpSock);
        g_udpSock = INVALID_SOCKET;
    }
    if (g_udpThread.joinable()) {
        g_udpThread.join();
    }
    if (g_wsaInit) {
        WSACleanup();
        g_wsaInit = false;
    }
}

json GetUdpStats() {
    json result = json::array();
    std::lock_guard<std::mutex> lk(g_statMutex);
    for (auto& [pid, e] : g_statMap) {
        json entry;
        entry["pid"] = e.pid;
        entry["up"] = e.up;
        entry["down"] = e.down;
        entry["conns"] = e.conns;
        entry["latency"] = e.latency;
        entry["node"] = e.node;
        entry["dns"] = e.dns;
        result.push_back(entry);
    }
    return result;
}
