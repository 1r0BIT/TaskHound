#!/bin/bash

#
# TaskHound BOF Compilation Script
# Compiles the TaskHound Beacon Object File (BOF) for AdaptixC2
#

echo "[*] TaskHound BOF Compilation Script"
echo "======================================"

# Check if MinGW-w64 is available
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[-] MinGW-w64 cross-compiler not found!"
    echo "[!] Please install MinGW-w64:"
    echo "    macOS: brew install mingw-w64"
    echo "    Ubuntu/Debian: apt-get install gcc-mingw-w64"
    echo "    Arch: pacman -S mingw-w64-gcc"
    exit 1
fi

echo "[+] MinGW-w64 compiler found"
echo ""

# Compile AdaptixC2 BOF
echo "[*] Compiling AdaptixC2 version..."
cd "$(dirname "$0")/AdaptixC2" || exit 1

if x86_64-w64-mingw32-gcc -c taskhound.c -o taskhound.o -masm=intel -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -fno-asynchronous-unwind-tables -fno-builtin -Os; then
    echo "[+] AdaptixC2 BOF compiled successfully: AdaptixC2/taskhound.o"
    ls -la taskhound.o
else
    echo "[-] Failed to compile AdaptixC2 BOF"
    exit 1
fi

echo ""
echo "[+] BOF compilation completed successfully!"
echo ""
echo "Usage Instructions:"
echo "=================="
echo ""
echo "AdaptixC2:"
echo "  1. Load AdaptixC2/taskhound.axs script"
echo "  2. Use: taskhound <target> -u <username> -p <password> -save <directory> -unsaved-creds -grab-blobs"
echo ""
echo "Examples:"
echo "  taskhound 192.168.1.100"
echo "  taskhound DC -u domain\\admin -p P@ss -save C:\\Output"
echo "  taskhound DC -u domain\\admin -p P@ss -save C:\\Output -grab-blobs"
echo ""