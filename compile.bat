@echo off
echo ========================================
echo  Ghost Proxifier - Build Script
echo ========================================
echo.

REM Init submodules
if not exist "minhook\include\MinHook.h" (
    echo [1/3] Initializing git submodules...
    git submodule update --init --recursive
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Failed to init submodules
        exit /b 1
    )
) else (
    echo [1/3] Submodules already initialized.
)

REM Build x64
echo.
echo [2/3] Building x64 Release...
mkdir build_x64 2>nul
cd build_x64
cmake .. -G "Visual Studio 17 2022" -A x64
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configure failed for x64
    cd ..
    exit /b 1
)
cmake --build . --config Release
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed for x64
    cd ..
    exit /b 1
)
cd ..

REM Build x86 (ghost_core_x86.dll + ghost_launcher_x86.exe)
echo.
echo [3/3] Building x86 Release...
mkdir build_x86 2>nul
cd build_x86
cmake .. -G "Visual Studio 17 2022" -A Win32
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configure failed for x86
    cd ..
    exit /b 1
)
cmake --build . --config Release
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed for x86
    cd ..
    exit /b 1
)
cd ..

echo.
echo ========================================
echo  Build complete!
echo.
echo  Outputs (bin/):
echo    ghost-proxifier.exe       (x64 CLI)
echo    ghost_core_x64.dll        (x64 proxy DLL)
echo    ghost_core_x86.dll        (x86 proxy DLL)
echo    ghost_launcher_x64.exe    (x64 injector)
echo    ghost_launcher_x86.exe    (x86 injector)
echo    ghost_dns_dump.exe        (DNS diag)
echo ========================================
