@echo off
mkdir build_x64 2>nul
cd build_x64
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
cd ..

mkdir build_x86 2>nul
cd build_x86
cmake .. -G "Visual Studio 17 2022" -A Win32
cmake --build . --config Release
cd ..

echo Done.
