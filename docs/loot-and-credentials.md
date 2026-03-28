# Loot and Credentials

## The point

Finding a scheduled task running as `CORP\svc_backup` is useful. Extracting
`svc_backup`'s actual password is more useful. TaskHound does both, and with the
LSA extraction addition, the whole pipeline is now automatic -- no more shelling
out to nxc or secretsdump as a separate step.

## Overview

`--loot` is enabled by default. It does two things:

1. **LSA secret extraction** -- pulls service account passwords and DPAPI keys from the registry
2. **DPAPI credential collection** -- downloads encrypted credential blobs from task XML data

Disable everything with `--no-loot`. Disable just LSA with `--no-lsa`. There is no
flag to disable just DPAPI collection without also disabling LSA, because that seemed
like an edge case nobody would actually want.

## LSA Secret Extraction

This is the new thing. Previously, getting service account passwords required a separate
tool (secretsdump, nxc `--lsa`, etc.). Now TaskHound extracts them inline using
impacket's regsecrets module.

### How it works

1. Starts the RemoteRegistry service on the target (if not already running)
2. Reads the SYSTEM registry hive via `\pipe\winreg` to get the boot key
3. Reads the SECURITY registry hive to decrypt LSA secrets
4. Restores RemoteRegistry to its original state (stopped if it was stopped)

All via Remote Registry RPC with `REG_OPTION_BACKUP_RESTORE` to bypass ACLs.
No files are written to disk -- no hive dumps to ADMIN$, no temp files on C$.
The only network traffic is `\pipe\svcctl` (to start RemoteRegistry) and `\pipe\winreg`
(the actual registry queries).

This is less noisy than traditional secretsdump, which saves hive files to the
ADMIN$ share. But "less noisy" is not "quiet" -- see the [opsec doc](opsec.md).

### What gets extracted

**Service credentials (`_SC_*` secrets):**
Each service running as a domain account has an `_SC_<ServiceName>` entry in LSA
containing the plaintext password. TaskHound matches these back to the service names
discovered during enumeration.

**DPAPI system keys (`DPAPI_SYSTEM`):**
The `dpapi_machinekey` and `dpapi_userkey` are extracted from the DPAPI_SYSTEM secret.
The userkey is the important one -- it's automatically fed into DPAPI decryption for
scheduled task credential blobs. This is the key improvement: previously you had to
run `nxc --lsa` separately, copy the hex key, and pass `--dpapi-key`. Now it just works.

### Disable it

```bash
# Disable LSA extraction specifically (still collect DPAPI blobs)
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 --no-lsa

# Disable all credential extraction
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 --no-loot
```

## DPAPI Credential Extraction

Scheduled tasks with stored credentials keep the password in a DPAPI-encrypted blob.
TaskHound collects these blobs and, if it has the DPAPI system key, decrypts them
on the spot.

### The auto-feed pipeline

This is how the pieces fit together now:

1. Enumerate services via SVCCTL (if `--services`)
2. Extract LSA secrets -- gets service passwords AND the DPAPI userkey
3. Enumerate scheduled tasks via SMB share crawling
4. Collect DPAPI credential blobs from task XML
5. Decrypt blobs using the auto-extracted DPAPI userkey

Steps 2 and 5 are the new connection. The DPAPI key extracted from LSA secrets is
automatically used for task credential decryption without any manual intervention.

### Manual key override

If you already have the key (or extracted it some other way), you can still pass it
manually. The manual key takes precedence over the auto-extracted one:

```bash
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 \
  --dpapi-key 0x51e43225a1b7b4c3...
```

### Collect now, decrypt later

Don't have the DPAPI key yet? TaskHound still collects the encrypted blobs:

```bash
# Collect blobs without decryption (no LSA, no manual key)
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 --no-lsa

# Later, decrypt offline with the key
taskhound --offline ./loot/ --dpapi-key 0x51e43225...
```

The blobs are saved to the output directory for later processing.

## Credential Validation

TaskHound checks whether stored credentials are still valid by querying the Task
Scheduler RPC for last run information and cross-referencing with AD metadata.

### The key insight

Windows validates credentials at task creation time. If you try to register a task
with `LogonType=Password` and wrong credentials, you get `ERROR_LOGON_FAILURE` and
the task is not created. Therefore: **if a task with stored credentials exists, the
password was valid when the task was created.** The question is whether it's still valid.

### Confidence levels

| Status | Meaning | Certainty |
|--------|---------|-----------|
| `confirmed_valid` | pwdLastSet < task creation, ran within schedule | High |
| `high_confidence` | pwdLastSet < task creation, schedule unknown | High |
| `likely_valid` | Ran recently within schedule | Medium |
| `definitely_stale` | pwdLastSet > LastRunTime (password changed after last run) | High |
| `possibly_stale` | Should have run but LastRunTime is old | Medium |
| `never_ran_likely_valid` | Never ran, but pwd unchanged since creation | Low-medium |
| `never_ran_possibly_stale` | Never ran, pwd changed since creation | Low-medium |
| `never_ran_unknown` | Never ran, no context available | Unknown |
| `unknown` | Cannot determine | Unknown |

A task that "never ran" isn't necessarily broken -- it might be disabled, waiting for
its trigger, or missing `SeBatchLogonRight`. The password could still be perfectly valid.

### Disable it

```bash
taskhound -u admin -p 'P@ss' -d corp.local -t 10.0.0.5 --no-validate-creds
```

This skips the Task Scheduler RPC queries, which reduces noise but means you lose the
confidence assessment.

## Limitations

- LSA extraction requires admin access (same as secretsdump -- there's no magic here)
- gMSA passwords are not in LSA secrets; they use a completely different key distribution protocol
- DPAPI decryption only works for SYSTEM-context credential blobs (user-context blobs need the user's master key, which is a different problem)
- Credential validation via RPC has a blind spot: Windows doesn't record failed authentication as task runs, so the absence of recent runs is ambiguous
