#include <windows.h>
#include <stdio.h>
#include <string>
#include "utils.h"

// ---- Helper: find upstream by name or id ----
static json* FindUpstream(json& cfg, const std::string& nameOrId) {
    if (!cfg.contains("upstream") || !cfg["upstream"].is_array()) return nullptr;
    for (auto& u : cfg["upstream"]) {
        std::string n = u.value("name", "");
        std::string id = u.value("id", "");
        if (n == nameOrId || id == nameOrId) return &u;
    }
    return nullptr;
}

// ---- Helper: generate a unique upstream id ----
static std::string GenerateUpstreamId(const std::string& name) {
    // Simple: use hashed timestamp
    DWORD tick = GetTickCount();
    char buf[64];
    snprintf(buf, sizeof(buf), "node_%lu", tick);
    return buf;
}

// ---- cmd_config ----
int cmd_config(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: ghost-proxifier config <show|dns|upstream>\n");
        return 1;
    }

    std::wstring sub = argv[2];

    // config show
    if (sub == L"show") {
        json cfg = LoadConfig();
        printf("%s\n", cfg.dump(2).c_str());
        return 0;
    }

    // config dns <server>
    if (sub == L"dns") {
        if (argc < 4) {
            fprintf(stderr, "Usage: ghost-proxifier config dns <server>\n");
            return 1;
        }
        char server[256] = {};
        WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, server, 256, NULL, NULL);

        json cfg = LoadConfig();
        if (!cfg.contains("dns")) cfg["dns"] = json::object();
        cfg["dns"]["server"] = server;
        cfg["dns"]["enabled"] = true;
        SaveConfig(cfg);

        printf("DNS server set to: %s\n", server);
        return 0;
    }

    // config upstream ...
    if (sub == L"upstream") {
        if (argc < 4) {
            fprintf(stderr, "Usage: ghost-proxifier config upstream <add|rm|use> [...]\n");
            return 1;
        }

        std::wstring action = argv[3];

        // config upstream add <name> <addr>
        if (action == L"add") {
            if (argc < 6) {
                fprintf(stderr, "Usage: ghost-proxifier config upstream add <name> <addr>\n");
                return 1;
            }
            char name[256] = {}, addr[256] = {};
            WideCharToMultiByte(CP_UTF8, 0, argv[4], -1, name, 256, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, argv[5], -1, addr, 256, NULL, NULL);

            json cfg = LoadConfig();
            if (!cfg.contains("upstream")) cfg["upstream"] = json::array();

            // Check for duplicate name
            if (FindUpstream(cfg, name)) {
                fprintf(stderr, "Error: Upstream '%s' already exists\n", name);
                return 1;
            }

            json entry;
            entry["id"] = GenerateUpstreamId(name);
            entry["name"] = name;
            entry["addr"] = addr;
            entry["active"] = false;

            cfg["upstream"].push_back(entry);
            SaveConfig(cfg);

            printf("Added upstream: %s @ %s\n", name, addr);
            return 0;
        }

        // config upstream rm <name-or-id>
        if (action == L"rm") {
            if (argc < 5) {
                fprintf(stderr, "Usage: ghost-proxifier config upstream rm <name-or-id>\n");
                return 1;
            }
            char target[256] = {};
            WideCharToMultiByte(CP_UTF8, 0, argv[4], -1, target, 256, NULL, NULL);

            json cfg = LoadConfig();
            if (!cfg.contains("upstream") || !cfg["upstream"].is_array()) {
                fprintf(stderr, "Error: No upstreams configured\n");
                return 1;
            }

            json& upstreams = cfg["upstream"];
            bool removed = false;
            for (auto it = upstreams.begin(); it != upstreams.end(); ++it) {
                std::string n = (*it).value("name", "");
                std::string id = (*it).value("id", "");
                if (n == target || id == target) {
                    printf("Removed upstream: %s (%s)\n", n.c_str(), id.c_str());
                    upstreams.erase(it);
                    removed = true;
                    break;
                }
            }

            if (!removed) {
                fprintf(stderr, "Error: No upstream found matching '%s'\n", target);
                return 1;
            }

            SaveConfig(cfg);
            return 0;
        }

        // config upstream use <name-or-id>
        if (action == L"use") {
            if (argc < 5) {
                fprintf(stderr, "Usage: ghost-proxifier config upstream use <name-or-id>\n");
                return 1;
            }
            char target[256] = {};
            WideCharToMultiByte(CP_UTF8, 0, argv[4], -1, target, 256, NULL, NULL);

            json cfg = LoadConfig();
            if (!cfg.contains("upstream") || !cfg["upstream"].is_array()) {
                fprintf(stderr, "Error: No upstreams configured\n");
                return 1;
            }

            bool found = false;
            for (auto& u : cfg["upstream"]) {
                std::string n = u.value("name", "");
                std::string id = u.value("id", "");
                if (n == target || id == target) {
                    u["active"] = true;
                    found = true;
                    printf("Activated upstream: %s\n", n.c_str());
                } else {
                    u["active"] = false;
                }
            }

            if (!found) {
                fprintf(stderr, "Error: No upstream found matching '%s'\n", target);
                return 1;
            }

            SaveConfig(cfg);
            return 0;
        }

        fprintf(stderr, "Error: Unknown upstream action '%ls' (expected add, rm, use)\n", argv[3]);
        return 1;
    }

    fprintf(stderr, "Error: Unknown config command '%ls' (expected show, dns, upstream)\n", argv[2]);
    return 1;
}
