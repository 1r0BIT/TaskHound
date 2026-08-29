# OPSEC Considerations

## The default behavior is loud

Out of the box, TaskHound enables everything: LDAP queries, LSARPC lookups, remote
registry access, credential validation, DPAPI collection, and LSA extraction. This will
make any decent SOC light up like a Christmas tree. If you're in a red team engagement
with monitoring, read this page before you run anything.

## Pre-flight credential check

Before any targets are scanned, TaskHound makes one SMB authentication attempt against
the DC (or first target) to validate credentials. This prevents account lockout from
bad passwords hitting N targets simultaneously. It adds one SMB connection at startup.
If you're using separate LDAP credentials (`--ldap-user`), one additional LDAP bind is
also performed. See [authentication.md](authentication.md#pre-flight-credential-validation).

## Protocol impact

Every feature maps to specific network traffic. Here's what lights up and how to turn it off:

| Protocol | Used for | Named pipe / port | Disable flag |
|----------|----------|-------------------|-------------|
| SMB | Pre-flight credential validation | 445 | Skipped for `-d '.'` (local auth) |
| SMB | Task XML enumeration (share crawl) | 445 (IPC$, C$) | Cannot disable (core function) |
| SVCCTL RPC | Service enumeration | `\pipe\svcctl` | `--services` not set (off by default) |
| LSARPC | SID-to-name resolution | `\pipe\lsarpc` | `--no-rpc` |
| LDAP | SID resolution, tier-0 detection, gMSA check | 389 / 636 | `--no-ldap` |
| Remote Registry | LSA secret extraction (boot key + SECURITY hive) | `\pipe\winreg` | `--no-lsa` |
| Remote Registry | Credential Guard detection | `\pipe\winreg` | `--no-credguard` |
| Task Scheduler RPC | Credential validation (last run info) | `\pipe\atsvc` | `--no-validate-creds` |
| SMB file access | DPAPI credential blob collection | 445 (C$) | `--no-loot` |

## SID resolution chain

TaskHound resolves SIDs through multiple backends, falling through until one succeeds:

```
Default:        BloodHound API → SQLite cache → LSARPC → LDAP → Global Catalog
--no-ldap:      BloodHound API → SQLite cache → LSARPC
--no-rpc:       BloodHound API → SQLite cache → LDAP → Global Catalog
--opsec:        BloodHound API → SQLite cache
```

With `--opsec`, the only SID resolution source is BloodHound data and whatever is already
cached from previous runs. If you haven't populated the cache or don't have BloodHound,
you'll get raw SIDs instead of names. Pre-populate BloodHound before the engagement and
this works fine.

## --opsec mode

The nuclear option for stealth. Equivalent to:

```
--no-ldap --no-rpc --no-loot --no-credguard --no-validate-creds --threads 1
```

Forces sequential scanning (one host at a time) and limits SID resolution to BloodHound
data and local SQLite cache only. No LDAP, no RPC, no credential extraction, no registry
access. Just SMB share crawling for task XMLs.

```bash
# Quiet scan with jitter
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t targets.txt \
  --opsec --jitter 5

# Opsec mode + BloodHound for classification (recommended)
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t targets.txt \
  --opsec --jitter 5 \
  --bh-live --bhce --bh-api-key-id KEYID --bh-api-key SECRET
```

The `--jitter N` flag adds a random 0-N second delay between hosts. Not much, but it
breaks the pattern of rapid sequential connections that automated tools are known for.

## Individual disable flags

For when `--opsec` is too restrictive but you still want to reduce noise:

| Flag | What it disables | Impact |
|------|-----------------|--------|
| `--no-rpc` | LSARPC SID resolution, credential validation, CredGuard detection | Major noise reduction, lose name resolution and cred validation |
| `--no-ldap` | LDAP SID resolution, tier-0 group checks, gMSA detection | Lose accurate classification unless BloodHound is available |
| `--no-loot` | DPAPI blob collection AND LSA extraction | No credential material at all |
| `--no-lsa` | LSA secret extraction only (DPAPI collection still works) | Skip registry access, keep DPAPI blobs |
| `--no-credguard` | Credential Guard detection via remote registry | One less registry query |
| `--no-validate-creds` | Task Scheduler RPC credential validation | No last-run-time analysis |

Note: `--no-rpc` implies `--no-credguard` and `--no-validate-creds` since both require RPC.

## Specific warnings

### Credential Guard detection

CredGuard detection starts the RemoteRegistry service and queries a specific registry key.
Starting RemoteRegistry generates a System event log entry (Service Control Manager, Event
ID 7036). Some EDR products flag this specifically because it's a known precursor to
credential dumping. Use `--no-credguard` or `--no-rpc` to avoid it.

### LSA secret extraction

Same concern as CredGuard detection but more so. LSA extraction reads the SECURITY and
SYSTEM registry hives through Remote Registry. The upside over traditional secretsdump:
no files written to ADMIN$, no hive saves to disk. The downside: it still starts
RemoteRegistry and makes a distinctive pattern of registry reads that EDR can correlate.

Less IOC surface than `secretsdump.py`, but not zero. If you're worried, use `--no-lsa`
and extract credentials through a different channel.

## Best practices for stealth

1. **Pre-populate BloodHound** before the engagement. Run SharpHound or similar, ingest
   the data. Then TaskHound can classify everything from BH data without touching LDAP.

2. **Use `--opsec --jitter 5`** for initial reconnaissance. Get the task inventory first,
   decide what's worth looting later.

3. **Target selectively.** Don't scan the entire domain. Use `--opsec` against specific
   high-value hosts.

4. **Collect offline if possible.** If you have local admin on a host through other means,
   copy the `C:\Windows\System32\Tasks` directory and parse offline:
   ```bash
   taskhound --offline ./tasks_backup/
   ```
   Zero network traffic for the parsing step.

5. **Use a BOF.** For maximum stealth, use the BOF implementation -- it runs in-process
   and only touches SMB. Available in the [Adaptix Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit)
   under `SAR-BOF/taskhound/`.

6. **Separate noisy operations.** Do the quiet scan first (`--opsec`), then come back
   for credential extraction on specific targets with full features enabled. Two passes
   are more suspicious than one, but the first pass gives you time to assess the
   monitoring posture.
