#include "globals.h"

// ============================================================================
// SetThreadContext (EntryDetour) Shellcode
// ============================================================================
// Matches proxychains-windows' approach (hookdll_main.c:404-447):
//   x64: change RCX → shellcode, leave RIP at LdrInitializeThunk
//   x86: change Eax → shellcode, leave Eip at LdrInitializeThunk
//
// LdrInitializeThunk runs FIRST, initialises ALL DLLs (including cygwin1.dll),
// then transfers control to RCX/Eax (our shellcode).  The shellcode:
//   LoadLibraryW      → DllMain (minimal: just DisableThreadLibraryCalls)
//   GetProcAddress    → find GhostInit export
//   call GhostInit()  → SetupThreadInternal → MH_CreateHook + MH_EnableHook
//   WaitForSingleObject(hEvent, 5000)
//   jmp EXE entry point
//
// CRITICAL for Cygwin: GhostInit() runs in the FIRST thread (the entry-point
// thread that received DLL_PROCESS_ATTACH for cygwin1.dll).  MinHook patching
// ws2_32 from a later thread corrupts Cygwin's cygtls → SIGSEGV.
// ============================================================================

// === x64 Shellcode ===
// Data layout at offset 0x58:
//   [0x58] EXE entry point (saved RCX)   (8 bytes)
//   [0x60] LoadLibraryW                   (8 bytes)
//   [0x68] GetProcAddress                 (8 bytes)
//   [0x70] WaitForSingleObject            (8 bytes)
//   [0x78] hChildEvent                    (8 bytes)
//   [0x80] "GhostInit\0"                  (10 bytes)
//   [0x8A] DLL path (wide string)
const unsigned char kThreadCtxX64[] = {
    // Save origEntry (from RCX) and volatile regs
    0x48, 0x8B, 0x0D, 0x51, 0x00, 0x00, 0x00, // 00: mov rcx, [rip+0x51]
    0x51,                                     // 07: push rcx
    0x52,                                     // 08: push rdx
    0x41, 0x50,                               // 09: push r8
    0x41, 0x51,                               // 0B: push r9
    0x48, 0x83, 0xEC, 0x28,                   // 0D: sub rsp, 0x28
    // LoadLibraryW(dllpath)
    0x48, 0x8D, 0x0D, 0x72, 0x00, 0x00, 0x00, // 11: lea rcx, [rip+0x72]
    0x48, 0x8B, 0x05, 0x41, 0x00, 0x00, 0x00, // 18: mov rax, [rip+0x41]
    0xFF, 0xD0,                               // 1F: call rax
    // GetProcAddress(hModule, "GhostInit")
    0x48, 0x89, 0xC1,                         // 21: mov rcx, rax
    0x48, 0x8D, 0x15, 0x55, 0x00, 0x00, 0x00, // 24: lea rdx, [rip+0x55]
    0x48, 0x8B, 0x05, 0x36, 0x00, 0x00, 0x00, // 2B: mov rax, [rip+0x36]
    0xFF, 0xD0,                               // 32: call rax
    // call GhostInit() — synchronous hook init in FIRST thread
    0xFF, 0xD0,                               // 34: call rax
    // WaitForSingleObject(hEvent, 5000)
    0x48, 0x8B, 0x0D, 0x3B, 0x00, 0x00, 0x00, // 36: mov rcx, [rip+0x3B]
    0xBA, 0x88, 0x13, 0x00, 0x00,             // 3D: mov edx, 5000
    0x48, 0x8B, 0x05, 0x27, 0x00, 0x00, 0x00, // 42: mov rax, [rip+0x27]
    0xFF, 0xD0,                               // 49: call rax
    // Restore regs, jump to EXE entry point
    0x48, 0x83, 0xC4, 0x28,                   // 4B: add rsp, 0x28
    0x41, 0x59,                               // 4F: pop r9
    0x41, 0x58,                               // 51: pop r8
    0x5A,                                     // 53: pop rdx
    0x59,                                     // 54: pop rcx
    0xFF, 0xE1,                               // 55: jmp rcx
};

// === x86 Shellcode ===
// For x86 targets we fall back to CreateRemoteThread for now.
// x86 shellcode will follow the same pattern as x64 but uses
// call/pop-ebx for position-independent data access on x86.
// TODO: add x86 shellcode matching proxychains-windows' g_EntryDetourX86.
const unsigned char kThreadCtxX86[] = {};
