#include "globals.h"

// --- DNS Cache (shared memory, cross-process) globals ---
static HANDLE g_hSharedCacheMapping = NULL;
static SharedDnsCacheEntry* g_pSharedCache = NULL;
static HANDLE g_hSharedCacheMutex = NULL;
static SharedDnsCacheHeader* g_pSharedHeader = NULL;

// --- Per-process DNS cache globals ---
std::unordered_map<std::string, DnsCacheEntry> g_DnsCache;
std::mutex g_DnsCacheMutex;

// FNV-1a hash — deterministic across processes
DWORD HashDomainForCache(const char* domain) {
    DWORD hash = 2166136261u;
    for (const char* p = domain; *p; p++) {
        hash ^= (unsigned char)(*p);
        hash *= 16777619u;
    }
    return hash ? hash : 1;  // 0 means "empty slot"
}

// Shared memory layout:
//   [0]               SharedDnsCacheHeader
//   [sizeof(Header)]  SharedDnsCacheEntry[entry_count]
// g_pSharedCache points to the first entry (NOT the header).

void InitSharedDnsCache() {
    if (g_pSharedCache) return;

    g_hSharedCacheMutex = CreateMutexW(NULL, FALSE, L"Global\\GhostDnsCacheMutex");
    if (!g_hSharedCacheMutex) return;

    WaitForSingleObject(g_hSharedCacheMutex, INFINITE);

    DWORD totalSize = sizeof(SharedDnsCacheHeader) + SHARED_DNS_CACHE_ENTRIES * sizeof(SharedDnsCacheEntry);
    g_hSharedCacheMapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, totalSize, L"Global\\GhostDnsCache");

    bool isFirst = (g_hSharedCacheMapping && GetLastError() != ERROR_ALREADY_EXISTS);

    if (!g_hSharedCacheMapping) {
        ReleaseMutex(g_hSharedCacheMutex);
        return;
    }

    BYTE* pBase = (BYTE*)MapViewOfFile(g_hSharedCacheMapping, FILE_MAP_ALL_ACCESS, 0, 0, totalSize);
    if (!pBase) {
        ReleaseMutex(g_hSharedCacheMutex);
        return;
    }

    g_pSharedHeader = (SharedDnsCacheHeader*)pBase;
    g_pSharedCache  = (SharedDnsCacheEntry*)(pBase + sizeof(SharedDnsCacheHeader));

    if (isFirst) {
        memset(pBase, 0, totalSize);
        g_pSharedHeader->magic      = SHARED_DNS_CACHE_MAGIC;
        g_pSharedHeader->entry_count = SHARED_DNS_CACHE_ENTRIES;
        g_pSharedHeader->max_ttl_ms  = SHARED_DNS_CACHE_TTL_MS;
    } else {
        // Validate existing shared memory — reject old-format cache
        if (g_pSharedHeader->magic != SHARED_DNS_CACHE_MAGIC) {
            UnmapViewOfFile(pBase);
            CloseHandle(g_hSharedCacheMapping);
            g_pSharedCache = NULL;
            g_pSharedHeader = NULL;
            g_hSharedCacheMapping = NULL;
            ReleaseMutex(g_hSharedCacheMutex);
            return;
        }
    }

    ReleaseMutex(g_hSharedCacheMutex);
}

// Look up a domain in the shared DNS cache. Returns true and fills `results` on hit.
// Caller must NOT hold g_hSharedCacheMutex.
bool SharedDnsCacheLookup(const char* domain, std::vector<DWORD>& results) {
    if (!g_pSharedCache) return false;
    if (!domain) return false;

    DWORD hash = HashDomainForCache(domain);
    DWORD now  = GetTickCount();

    WaitForSingleObject(g_hSharedCacheMutex, INFINITE);

    for (DWORD i = 0; i < g_pSharedHeader->entry_count; i++) {
        if (g_pSharedCache[i].domain_hash == hash &&
            g_pSharedCache[i].expire_tick > now) {
            for (int j = 0; j < 4; j++) {
                if (g_pSharedCache[i].ips[j] == 0) break;
                results.push_back(g_pSharedCache[i].ips[j]);
            }
            g_pSharedCache[i].access_tick = now;
            ReleaseMutex(g_hSharedCacheMutex);
            NetLog("[DNS-Cache] HIT: %s (%d IPs)", domain, (int)results.size());
            return true;
        }
    }

    ReleaseMutex(g_hSharedCacheMutex);
    NetLog("[DNS-Cache] MISS: %s", domain);
    return false;
}

// Insert resolved IPs into the shared DNS cache.
void SharedDnsCacheInsert(const char* domain, const std::vector<DWORD>& ips) {
    if (!g_pSharedCache || ips.empty()) return;
    if (!domain) return;

    DWORD hash = HashDomainForCache(domain);
    DWORD now  = GetTickCount();
    DWORD expire = now + g_pSharedHeader->max_ttl_ms;

    WaitForSingleObject(g_hSharedCacheMutex, INFINITE);

    // Try to find an existing slot for this domain, or an empty slot
    int emptySlot = -1;
    DWORD lruTick  = 0xFFFFFFFF;
    int lruSlot    = 0;

    for (DWORD i = 0; i < g_pSharedHeader->entry_count; i++) {
        // Update existing entry
        if (g_pSharedCache[i].domain_hash == hash) {
            memset(g_pSharedCache[i].ips, 0, sizeof(g_pSharedCache[i].ips));
            for (size_t j = 0; j < ips.size() && j < 4; j++) {
                g_pSharedCache[i].ips[j] = ips[j];
            }
            strncpy_s(g_pSharedCache[i].domain, domain, sizeof(g_pSharedCache[i].domain) - 1);
            g_pSharedCache[i].expire_tick = expire;
            g_pSharedCache[i].access_tick = now;
            ReleaseMutex(g_hSharedCacheMutex);
            return;
        }

        // Track empty slot
        if (g_pSharedCache[i].domain_hash == 0 || g_pSharedCache[i].expire_tick <= now) {
            // Treat expired entries as empty
            if (emptySlot < 0) {
                emptySlot = i;
                // Clear it immediately
                g_pSharedCache[i].domain_hash = 0;
                g_pSharedCache[i].domain[0] = '\0';
                memset(g_pSharedCache[i].ips, 0, sizeof(g_pSharedCache[i].ips));
            }
        }

        // Track LRU (for fallback if no empty slot)
        if (g_pSharedCache[i].access_tick < lruTick) {
            lruTick = g_pSharedCache[i].access_tick;
            lruSlot = i;
        }
    }

    int slot = (emptySlot >= 0) ? emptySlot : lruSlot;
    g_pSharedCache[slot].domain_hash = hash;
    memset(g_pSharedCache[slot].ips, 0, sizeof(g_pSharedCache[slot].ips));
    for (size_t j = 0; j < ips.size() && j < 4; j++) {
        g_pSharedCache[slot].ips[j] = ips[j];
    }
    strncpy_s(g_pSharedCache[slot].domain, domain, sizeof(g_pSharedCache[slot].domain) - 1);
    g_pSharedCache[slot].expire_tick = expire;
    g_pSharedCache[slot].access_tick = now;

    ReleaseMutex(g_hSharedCacheMutex);
    NetLog("[DNS-Cache] INSERT: %s (%d IPs)", domain, (int)ips.size());
}
