@echo off
if exist build rd /s /q build
cmake -B build -A x64
cmake --build build --config Release
echo [DEPLOY] Copying new binaries...
if not exist bin mkdir bin
if exist build\Release\ghost_core.dll (
    copy /y build\Release\ghost_core.dll bin\ghost_core.dll
    echo [OK] ghost_core.dll copied to bin\.
)
if exist build\Release\ghost-proxifier.exe (
    copy /y build\Release\ghost-proxifier.exe bin\ghost-proxifier.exe
    echo [OK] ghost-proxifier.exe copied to bin\.
)
dir bin\
