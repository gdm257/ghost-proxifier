// ghost_dns_dump.cpp — Dump Ghost shared DNS cache
// Usage: ghost_dns_dump.exe
// No dependencies beyond kernel32.lib; no MinHook, no ws2_32.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <time.h>

#define SHARED_DNS_CACHE_ENTRIES 256
#define SHARED_DNS_CACHE_MAGIC   0x47444E54  // v2 with domain field

struct SharedDnsCacheEntry {
    DWORD domain_hash;
    DWORD ips[4];
    DWORD expire_tick;
    DWORD access_tick;
    char  domain[48];
};

struct SharedDnsCacheHeader {
    DWORD magic;
    DWORD entry_count;
    DWORD max_ttl_ms;
    DWORD padding;
};

static void IpToStr(DWORD ip, char* out, size_t len) {
    unsigned char* b = (unsigned char*)&ip;
    snprintf(out, len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

int main() {
    printf("Ghost DNS Cache Dump\n");
    printf("====================\n\n");

    HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\GhostDnsCacheMutex");
    if (!hMutex) {
        printf("[ERROR] No shared DNS cache found (mutex not present).\n");
        printf("        Make sure at least one injected process is running.\n");
        return 1;
    }

    WaitForSingleObject(hMutex, INFINITE);

    DWORD totalSize = sizeof(SharedDnsCacheHeader) + SHARED_DNS_CACHE_ENTRIES * sizeof(SharedDnsCacheEntry);
    HANDLE hMapping = OpenFileMappingW(FILE_MAP_READ, FALSE, L"Global\\GhostDnsCache");
    if (!hMapping) {
        printf("[ERROR] Cannot open shared memory mapping (err=%lu).\n", GetLastError());
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    BYTE* pBase = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, totalSize);
    if (!pBase) {
        printf("[ERROR] Cannot map view of file (err=%lu).\n", GetLastError());
        CloseHandle(hMapping);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    SharedDnsCacheHeader* hdr = (SharedDnsCacheHeader*)pBase;
    SharedDnsCacheEntry* entries = (SharedDnsCacheEntry*)(pBase + sizeof(SharedDnsCacheHeader));

    printf("Shared Memory : Global\\GhostDnsCache\n");
    printf("Mutex         : Global\\GhostDnsCacheMutex\n");

    if (hdr->magic != SHARED_DNS_CACHE_MAGIC) {
        printf("Magic         : 0x%08X [UNKNOWN — format mismatch?]\n", hdr->magic);
    } else {
        printf("Magic         : 0x%08X [OK]\n", hdr->magic);
    }
    printf("Entries       : %u\n", hdr->entry_count);
    printf("TTL           : %u ms (%u s)\n", hdr->max_ttl_ms, hdr->max_ttl_ms / 1000);
    printf("\n");

    DWORD now = GetTickCount();
    int used = 0;
    int expired = 0;

    // Column widths
    printf("%-8s %-8s %-32s %-18s %8s\n", "Slot", "Hash", "Domain", "IPs", "Age(s)");
    printf("%-8s %-8s %-32s %-18s %8s\n", "----", "----", "------------------", "---", "------");

    for (DWORD i = 0; i < hdr->entry_count; i++) {
        SharedDnsCacheEntry& e = entries[i];
        if (e.domain_hash == 0) continue;

        bool isExpired = (e.expire_tick <= now);
        if (!isExpired) used++; else expired++;

        char ipList[64] = "-";
        if (e.ips[0] != 0) {
            char tmp[16];
            int off = 0;
            for (int j = 0; j < 4; j++) {
                if (e.ips[j] == 0) break;
                IpToStr(e.ips[j], tmp, sizeof(tmp));
                off += snprintf(ipList + off, sizeof(ipList) - off, "%s%s", j > 0 ? ", " : "", tmp);
            }
        }

        DWORD age = now - e.access_tick;
        int ageS = (int)(age / 1000);
        const char* marker = isExpired ? " [EXP]" : "";
        const char* domain = e.domain[0] ? e.domain : "(empty)";

        printf("%-8u 0x%04X  %-32s %-18s %6d%s\n",
               i, (e.domain_hash & 0xFFFF), domain, ipList, ageS, marker);
    }

    printf("\n");
    printf("-------------------------------\n");
    printf("  Active  : %d\n", used);
    printf("  Expired : %d\n", expired);
    printf("  Empty   : %d\n", (int)(hdr->entry_count) - used - expired);
    printf("  Total   : %u\n", hdr->entry_count);
    printf("-------------------------------\n");

    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return 0;
}
