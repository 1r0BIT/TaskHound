# Offline Analysis

Sometimes you don't have (or don't want) a live connection. Maybe you grabbed task XMLs during a prior engagement, maybe you're staring at a mounted VHDX at 2am. Either way, TaskHound can work with what you've got.

## Previously Collected XMLs

If you've already collected task XMLs (from a previous TaskHound run, or manually copied from `C:\Windows\System32\Tasks`), point TaskHound at the directory:

```bash
taskhound --offline /path/to/backups/HOSTNAME
```

The directory should contain task XML files. TaskHound will parse, classify, and report on them exactly like online mode, minus the network bits. No credentials needed, no SMB, no DNS headaches. It's honestly kind of relaxing.

SID resolution won't work without network access, so you'll see raw SIDs where names would normally be. You can work around this by combining with `--dc-ip` and credentials if the domain is reachable from your analysis box, but at that point you might as well run online mode.

## Mounted Disk Images

For forensic images or mounted VHDXs where you have the full Windows filesystem:

```bash
taskhound --offline-disk /mnt/disk
```

TaskHound will find `Windows\System32\Tasks` on its own, extract the hostname from the SYSTEM registry hive, and even pull the DPAPI system key from the hives for credential decryption. If hostname detection gets it wrong (it does sometimes), override it:

```bash
taskhound --offline-disk /mnt/disk --disk-hostname ACTUALNAME
```

You can't combine `--offline` and `--offline-disk`. Pick one. I know, how restrictive.

## Offline Service Enumeration

This is the newer addition. TaskHound can parse Windows service configurations directly from exported registry hives -- no network required.

It reads `CurrentControlSet\Services\*` from the SYSTEM hive, filters down to Win32 services (skipping kernel drivers and other noise), and classifies them the same way it handles online service enumeration.

Expected directory layout:

```
offline_dir/
  └── HOSTNAME/
      ├── SYSTEM       # Required: service configurations
      └── SECURITY     # Optional: LSA secrets (for --loot)
```

If you also have the SECURITY hive, TaskHound will attempt to extract LSA secrets -- specifically the `_SC_*` entries that hold service account credentials. This is the same data you'd get from `secretsdump.py`, just without needing to touch the network.

## Offline LSA Extraction

For credential recovery from registry hives without any network access:

```bash
taskhound --offline-disk /mnt/disk --loot
```

TaskHound extracts the boot key from the SYSTEM hive, decrypts LSA secrets from the SECURITY hive, and recovers stored service credentials. It's impacket's `winregistry` doing the heavy lifting here -- TaskHound just orchestrates it and maps the results back to service accounts.

This is particularly useful when you have a disk image from an incident response and want to know which service accounts had credentials baked into the box. The answer is usually "more than anyone expected."
