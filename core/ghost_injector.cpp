#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shellapi.h>
#include <algorithm>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")

#define GHOST_INJECTOR_EXPORTS
#include "ghost_injector.h"

static std::wstring GetSiblingExecutablePath(const wchar_t* exeName) {
    wchar_t modulePath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(NULL, modulePath, MAX_PATH)) {
        return exeName;
    }

    std::wstring path = modulePath;
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return exeName;
    }
    return path.substr(0, pos + 1) + exeName;
}

static bool RunLauncherInjector(DWORD pid, const wchar_t* dllPath, bool targetIsWow64, bool elevated) {
    std::wstring launcherPath = GetSiblingExecutablePath(targetIsWow64 ? L"ghost_launcher_x86.exe" : L"ghost_launcher_x64.exe");
    std::wstring params = std::to_wstring(pid) + L" \"" + dllPath + L"\"";

    if (elevated) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"runas";
        sei.lpFile = launcherPath.c_str();
        sei.lpParameters = params.c_str();
        sei.nShow = SW_HIDE;

        if (!ShellExecuteExW(&sei) || !sei.hProcess) {
            return false;
        }

        WaitForSingleObject(sei.hProcess, 3000);
        DWORD exitCode = 1;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);
        return exitCode == 0;
    }

    std::wstring cmd = L"\"" + launcherPath + L"\" " + params;
    std::vector<wchar_t> cmdBuffer(cmd.begin(), cmd.end());
    cmdBuffer.push_back(L'\0');

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(NULL, cmdBuffer.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, 2000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode == 0;
}

static bool DirectInjectDllW(DWORD pid, const wchar_t* dllPath) {
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) return false;

    void* loadLibraryAddr = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    if (!loadLibraryAddr) {
        CloseHandle(h);
        return false;
    }

    size_t pathLen = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* m = VirtualAllocEx(h, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!m) {
        CloseHandle(h);
        return false;
    }

    if (!WriteProcessMemory(h, m, (void*)dllPath, pathLen, NULL)) {
        VirtualFreeEx(h, m, 0, MEM_RELEASE);
        CloseHandle(h);
        return false;
    }

    HANDLE t = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, m, 0, NULL);
    if (t) {
        DWORD waitResult = WaitForSingleObject(t, 3000);
        DWORD loadResult = 0;
        bool ok = waitResult == WAIT_OBJECT_0 &&
                  GetExitCodeThread(t, &loadResult) &&
                  loadResult != 0;
        CloseHandle(t);
        VirtualFreeEx(h, m, 0, MEM_RELEASE);
        CloseHandle(h);
        return ok;
    }

    VirtualFreeEx(h, m, 0, MEM_RELEASE);
    CloseHandle(h);
    return false;
}

extern "C" {

GHOST_API bool IsDllLoadedW(DWORD pid, const wchar_t* dllName) {
    if (pid == 0 || pid == GetCurrentProcessId()) return false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    bool found = false;

    // Use EnumProcessModulesEx to handle both 32-bit and 64-bit modules
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName)/sizeof(wchar_t))) {
                std::wstring modName(szModName);
                std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
                
                std::wstring searchName(dllName);
                std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::tolower);

                // Check for both the requested name AND our common core names
                if (modName.find(searchName) != std::wstring::npos || 
                    modName.find(L"ghost_core_x64.dll") != std::wstring::npos ||
                    modName.find(L"ghost_core_x86.dll") != std::wstring::npos ||
                    modName.find(L"ghost_core.dll") != std::wstring::npos) {
                    found = true;
                    break;
                }
            }
        }
    }
    CloseHandle(hProcess);
    return found;
}

GHOST_API bool InjectDllW(DWORD pid, const wchar_t* dllPath) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return false;

    // Safety check: Don't inject into Ghost's own processes
    wchar_t processPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameExW(h, NULL, processPath, MAX_PATH)) {
        std::wstring wsPath = processPath;
        std::transform(wsPath.begin(), wsPath.end(), wsPath.begin(), ::tolower);
        if (wsPath.find(L"ghost-proxifier.exe") != std::wstring::npos) {
            CloseHandle(h);
            return false;
        }
    }

    BOOL isWow64 = FALSE;
    IsWow64Process(h, &isWow64);
    CloseHandle(h);

    if (isWow64) {
        return RunLauncherInjector(pid, dllPath, true, false) ||
               RunLauncherInjector(pid, dllPath, true, true);
    }

    return DirectInjectDllW(pid, dllPath) ||
           RunLauncherInjector(pid, dllPath, false, false) ||
           RunLauncherInjector(pid, dllPath, false, true);
}

GHOST_API int GetInjectedProcessesW(DWORD* pids, int maxCount, const wchar_t* dllName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    int count = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (IsDllLoadedW(pe.th32ProcessID, dllName)) {
                if (count < maxCount) {
                    pids[count] = pe.th32ProcessID;
                }
                count++;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return count;
}

} // extern "C"
