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

REM Build x86
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
echo  Outputs:
echo    build_x64\cli\Release\ghost-proxifier.exe
echo    build_x64\core\Release\ghost_core_x64.dll
echo    build_x64\core\Release\ghost_launcher_x64.exe
echo    build_x64\core\Release\ghost_dns_dump.exe
echo    build_x86\cli\Release\ghost-proxifier_x86.exe
echo    build_x86\core\Release\ghost_core_x86.dll
echo    build_x86\core\Release\ghost_launcher_x86.exe
echo ========================================
