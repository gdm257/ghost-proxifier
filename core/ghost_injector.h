#pragma once
#include <windows.h>

#define GHOST_API 

extern "C" {
    GHOST_API bool IsDllLoadedW(DWORD pid, const wchar_t* dllName);
    GHOST_API bool InjectDllW(DWORD pid, const wchar_t* dllPath);
    GHOST_API int GetInjectedProcessesW(DWORD* pids, int maxCount, const wchar_t* dllName);
}
