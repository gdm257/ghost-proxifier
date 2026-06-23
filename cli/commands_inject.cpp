#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include <tlhelp32.h>
#include <psapi.h>
#include "utils.h"

#pragma comment(lib, "psapi.lib")

// Get the directory where this exe lives
static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    std::wstring dir(buf);
    size_t pos = dir.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? dir.substr(0, pos + 1) : L".\\";
}

// Determine if target process is 64-bit
// On 64-bit Windows: check if process is NOT running under WOW64
static bool IsProcess64Bit(DWORD pid) {
#ifdef _WIN64
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        // Can't query — try native API as fallback using the PID itself.
        // On x64 Windows, if IsWow64Process fails, we can infer from the OS:
        // the system can create both x64 and x86 processes. Default to x64
        // for system/high-integrity processes, but x86 is also possible.
        return true; // best guess for system processes
    }
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(h, &isWow64)) {
        CloseHandle(h);
        return true; // Can't determine — assume native (x64)
    }
    CloseHandle(h);
    return !isWow64; // TRUE if native x64, FALSE if running under WOW64 (x86)
#else
    (void)pid;
    return false;
#endif
}

// Find PID by process name (exe name without path)
static std::vector<DWORD> FindPidsByName(const std::wstring& name) {
    std::vector<DWORD> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
                result.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return result;
}

// Resolve PIDs from argument (numeric PID or process name, may return multiple)
static bool ResolvePids(const wchar_t* arg, std::vector<DWORD>& outPids) {
    // Try numeric PID first
    wchar_t* end = nullptr;
    DWORD pid = wcstoul(arg, &end, 10);
    if (end && *end == 0 && pid > 0) {
        outPids.push_back(pid);
        return true;
    }

    // Process name lookup
    outPids = FindPidsByName(arg);
    if (!outPids.empty()) return true;

    fprintf(stderr, "Error: No process found matching '%ls'\n", arg);
    return false;
}

// Inject DLL into a single process using ghost_launcher.exe
static bool InjectOne(DWORD pid) {
    std::wstring exeDir = GetExeDir();
    bool target64 = IsProcess64Bit(pid);

    std::wstring launcherPath;
    std::wstring dllPath;

    if (target64) {
        launcherPath = exeDir + L"ghost_launcher_x64.exe";
        dllPath = exeDir + L"ghost_core_x64.dll";
    } else {
        launcherPath = exeDir + L"ghost_launcher_x86.exe";
        dllPath = exeDir + L"ghost_core_x86.dll";
    }

    // Check files exist
    if (GetFileAttributesW(launcherPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Error: Launcher not found: %ls\n", launcherPath.c_str());
        return false;
    }
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Error: DLL not found: %ls\n", dllPath.c_str());
        return false;
    }

    // Build command line: launcher.exe <pid> <dllPath>
    wchar_t cmdLine[1024];
    swprintf(cmdLine, 1024, L"\"%ls\" %lu \"%ls\"", launcherPath.c_str(), pid, dllPath.c_str());

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "Error: Failed to launch injector for PID %lu (error %lu)\n",
                pid, GetLastError());
        return false;
    }

    // Wait for launcher to complete
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode != 0) {
        const char* errMsg = "Unknown error";
        switch (exitCode) {
            case 2: errMsg = "Cannot open process (access denied)"; break;
            case 3: errMsg = "Cannot find LoadLibraryW address"; break;
            case 4: errMsg = "Cannot allocate memory in target process"; break;
            case 5: errMsg = "Cannot write DLL path to target process"; break;
            case 6: errMsg = "Cannot create remote thread"; break;
            case 7: errMsg = "Invalid PID (0)"; break;
            case 8: errMsg = "DLL load failed (LoadLibraryW returned NULL)"; break;
        }
        fprintf(stderr, "Error: Injection failed for PID %lu: %s (code %lu)\n",
                pid, errMsg, exitCode);
        return false;
    }

    printf("  Injected PID %lu (%s)\n", pid, target64 ? "x64" : "x86");
    return true;
}

// ---- cmd_inject ----
// Usage: inject <pid|name>          — inject single process
//        inject --tree <pid|name>   — inject process + all descendants

int cmd_inject(int argc, wchar_t* argv[]) {
    bool treeMode = false;
    int argIdx = 2;

    if (argc < 3) {
        fprintf(stderr, "Usage: ghost-proxifier inject [--tree] <pid|name>\n");
        return 1;
    }

    if (wcscmp(argv[2], L"--tree") == 0) {
        treeMode = true;
        argIdx = 3;
    }

    if (argc <= argIdx) {
        fprintf(stderr, "Usage: ghost-proxifier inject [--tree] <pid|name>\n");
        return 1;
    }

    std::vector<DWORD> targets;
    if (!ResolvePids(argv[argIdx], targets)) {
        return 1;
    }

    // Inject all resolved PIDs (by name may match multiple processes)
    std::vector<DWORD> pids;
    for (auto pid : targets) {
        pids.push_back(pid);
        if (treeMode) {
            auto children = GetProcessTree(pid);
            pids.insert(pids.end(), children.begin(), children.end());
        }
    }

    // Deduplicate (targets may overlap with children)
    std::sort(pids.begin(), pids.end());
    pids.erase(std::unique(pids.begin(), pids.end()), pids.end());

    printf(treeMode
           ? "Injecting %zu processes (%zu target(s) + trees)...\n"
           : "Injecting %zu process(es)...\n",
           pids.size(), targets.size());

    int successCount = 0;
    int failCount = 0;
    for (auto pid : pids) {
        if (InjectOne(pid))
            successCount++;
        else
            failCount++;
    }

    printf("Done: %d succeeded, %d failed\n", successCount, failCount);
    return failCount > 0 ? 1 : 0;
}

// ---- cmd_eject ----
// Usage: eject <pid>
// Unload ghost_core.dll from the target process via CreateRemoteThread(FreeLibrary)

int cmd_eject(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: ghost-proxifier eject <pid>\n");
        return 1;
    }

    DWORD pid = 0;
    std::vector<DWORD> ejectPids;
    if (!ResolvePids(argv[2], ejectPids)) {
        return 1;
    }

    // Eject from all matching processes
    int okCount = 0, failCount = 0;
    for (auto pid : ejectPids) {
        printf("Ejecting ghost_core from PID %lu...\n", pid);
        bool ok = false;

        HANDLE h = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ | PROCESS_VM_OPERATION,
            FALSE, pid);
        if (!h) {
            fprintf(stderr, "  Error: Cannot open process %lu (error %lu)\n", pid, GetLastError());
            failCount++;
            continue;
        }

        HMODULE mods[1024];
        DWORD needed = 0;
        bool found = false;

        if (EnumProcessModules(h, mods, sizeof(mods), &needed)) {
            DWORD count = needed / sizeof(HMODULE);
            if (count > 1024) count = 1024;

            for (DWORD i = 0; i < count; i++) {
                wchar_t name[MAX_PATH] = {};
                if (GetModuleBaseNameW(h, mods[i], name, MAX_PATH)) {
                    if (wcsstr(name, L"ghost_core")) {
                        printf("  Found: %ls at 0x%p\n", name, mods[i]);

                        LPTHREAD_START_ROUTINE freeLib =
                            (LPTHREAD_START_ROUTINE)GetProcAddress(
                                GetModuleHandleA("kernel32.dll"), "FreeLibrary");

                        if (!freeLib) {
                            fprintf(stderr, "  Error: Cannot find FreeLibrary address\n");
                            break;
                        }

                        HANDLE t = CreateRemoteThread(h, NULL, 0, freeLib,
                                                      mods[i], 0, NULL);
                        if (!t) {
                            fprintf(stderr, "  Error: Cannot create remote thread (error %lu)\n",
                                    GetLastError());
                            break;
                        }

                        WaitForSingleObject(t, 5000);
                        DWORD exitCode = 0;
                        GetExitCodeThread(t, &exitCode);
                        CloseHandle(t);

                        if (exitCode) {
                            printf("  Unloaded successfully\n");
                            found = true;
                            ok = true;
                        } else {
                            fprintf(stderr, "  Error: FreeLibrary returned NULL\n");
                        }
                        break;
                    }
                }
            }
        }

        CloseHandle(h);

        if (!found) {
            fprintf(stderr, "  Error: ghost_core.dll not found in process %lu\n", pid);
            failCount++;
        } else if (ok) {
            okCount++;
        } else {
            failCount++;
        }
    }

    printf("Eject done: %d succeeded, %d failed\n", okCount, failCount);
    return failCount > 0 ? 1 : 0;
}
