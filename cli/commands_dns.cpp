#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "utils.h"

#pragma comment(lib, "ws2_32.lib")

// Resolve a hostname via system DNS (standard getaddrinfo)
static std::vector<std::string> ResolveSystem(const std::string& host) {
    std::vector<std::string> result;
    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0) {
        for (auto* p = res; p; p = p->ai_next) {
            char ip[INET_ADDRSTRLEN] = {};
            auto* addr = (struct sockaddr_in*)p->ai_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
            result.push_back(ip);
        }
        freeaddrinfo(res);
    }
    return result;
}

// Resolve a hostname through a DNS-over-TCP proxy (simple query on port 53)
static std::vector<std::string> ResolveViaDnsServer(const std::string& host, const std::string& dnsServer) {
    std::vector<std::string> result;

    // Build DNS query for A record
    std::vector<uint8_t> query;
    // Header
    uint16_t id = (uint16_t)(GetTickCount() & 0xFFFF);
    query.push_back((id >> 8) & 0xFF);
    query.push_back(id & 0xFF);
    // Flags: standard query, recursion desired
    query.push_back(0x01); query.push_back(0x00); // QR=0, Opcode=0, RD=1
    query.push_back(0x00); query.push_back(0x01); // QDCOUNT=1
    query.push_back(0x00); query.push_back(0x00); // ANCOUNT=0
    query.push_back(0x00); query.push_back(0x00); // NSCOUNT=0
    query.push_back(0x00); query.push_back(0x00); // ARCOUNT=0

    // Question: encode hostname labels
    size_t start = 0;
    while (start < host.size()) {
        size_t dot = host.find('.', start);
        if (dot == std::string::npos) dot = host.size();
        size_t len = dot - start;
        if (len > 63) len = 63; // Max label length
        query.push_back((uint8_t)len);
        for (size_t i = start; i < start + len; i++)
            query.push_back((uint8_t)host[i]);
        start = dot + 1;
    }
    query.push_back(0x00); // Terminator
    // QTYPE=A (1)
    query.push_back(0x00); query.push_back(0x01);
    // QCLASS=IN (1)
    query.push_back(0x00); query.push_back(0x01);

    // Send via UDP to DNS server
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return result;

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, dnsServer.c_str(), &addr.sin_addr);

    // Set timeout
    DWORD timeout = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    sendto(s, (const char*)query.data(), (int)query.size(), 0, (sockaddr*)&addr, sizeof(addr));

    uint8_t response[512];
    sockaddr_in from = {};
    int fromLen = sizeof(from);
    int n = recvfrom(s, (char*)response, sizeof(response), 0, (sockaddr*)&from, &fromLen);
    closesocket(s);

    if (n < 12) return result;

    // Parse response: skip header (12 bytes), skip question section,
    // then read answers
    uint16_t ancount = (response[6] << 8) | response[7];
    size_t offset = 12;

    // Skip question
    while (offset < (size_t)n && response[offset] != 0)
        offset++;
    offset++; // null terminator
    offset += 4; // QTYPE + QCLASS

    // Parse answers
    for (uint16_t i = 0; i < ancount && offset + 10 <= (size_t)n; i++) {
        // Handle name compression (0xC0 prefix)
        if (response[offset] == 0xC0) {
            offset += 2; // Skip pointer
        } else {
            // Skip uncompressed name
            while (offset < (size_t)n && response[offset] != 0)
                offset++;
            offset++; // null
        }

        if (offset + 10 > (size_t)n) break;
        uint16_t rtype = (response[offset] << 8) | response[offset + 1];
        // uint16_t rclass = (response[offset+2] << 8) | response[offset+3];
        // uint32_t ttl = ...;
        uint16_t rdlength = (response[offset + 8] << 8) | response[offset + 9];
        offset += 10;

        if (rtype == 1 && rdlength == 4 && offset + 4 <= (size_t)n) {
            // A record
            char ip[INET_ADDRSTRLEN] = {};
            snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                     response[offset], response[offset + 1],
                     response[offset + 2], response[offset + 3]);
            result.push_back(ip);
        }
        offset += rdlength;
    }

    return result;
}

int cmd_dns(int argc, wchar_t* argv[]) {
    if (argc < 3 || wcscmp(argv[2], L"check") != 0) {
        fprintf(stderr, "Usage: ghost-proxifier dns check\n");
        return 1;
    }

    // Initialize Winsock for this call
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Error: WSAStartup failed\n");
        return 1;
    }

    printf("DNS Leak Check\n");
    printf("==============\n\n");

    // Load config for DNS server
    json cfg = LoadConfig();
    std::string dnsServer = cfg["dns"].value("server", "8.8.8.8");

    const char* testDomain = "dnscheck.ghost-proxifier.local";
    // Use a well-known domain for real detection
    const char* realDomain = "www.google.com";

    printf("Resolving %s via system DNS...\n", realDomain);
    auto sysIps = ResolveSystem(realDomain);
    printf("  System DNS returned %zu IP(s):\n", sysIps.size());
    for (auto& ip : sysIps) printf("    %s\n", ip.c_str());

    printf("\nResolving %s via proxy DNS (%s)...\n", realDomain, dnsServer.c_str());
    auto proxyIps = ResolveViaDnsServer(realDomain, dnsServer);
    printf("  Proxy DNS returned %zu IP(s):\n", proxyIps.size());
    for (auto& ip : proxyIps) printf("    %s\n", ip.c_str());

    // Compare results
    printf("\nResult: ");
    if (sysIps.empty() && proxyIps.empty()) {
        printf("INCONCLUSIVE - Both DNS paths failed to resolve\n");
    } else if (sysIps.empty()) {
        printf("PASS - System DNS did not resolve (proxy likely active)\n");
    } else if (proxyIps.empty()) {
        printf("WARNING - Proxy DNS failed! Proxy may not be functioning\n");
    } else if (sysIps == proxyIps) {
        printf("PASS - Both DNS paths returned same results\n");
    } else {
        printf("WARNING - DNS answers differ! Possible DNS leak or geo-DNS results\n");
        printf("  System DNS IPs differ from proxy DNS IPs.\n");
        printf("  This may indicate DNS requests bypassing the proxy.\n");
    }

    WSACleanup();
    return 0;
}
