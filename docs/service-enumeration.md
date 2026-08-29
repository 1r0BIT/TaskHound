# Service Enumeration

## The problem

Scheduled tasks get all the attention, but Windows services are the same attack surface
with a different hat. Services running as domain accounts store their credentials in LSA
secrets -- the exact same credential material you'd go after with secretsdump. Every
domain has a handful of these hiding behind 300+ LocalSystem/NT SERVICE entries that
nobody looks at.

TaskHound now enumerates services alongside tasks because, honestly, it was weird that
it didn't already.

## How it works

TaskHound binds to `\pipe\svcctl` (the Service Control Manager RPC interface) on each
target using the existing SMB connection. Same pipe that `sc.exe` uses. It calls
`REnumServicesStatusW` to list everything, then `RQueryServiceConfigW` on each service
to grab the account, binary path, and start type.

The interesting part is what gets thrown away. A typical Windows 11 box has 300+ services.
Roughly 290 of those run as LocalSystem, NT AUTHORITY\NetworkService, NT AUTHORITY\LocalService,
or NT SERVICE\* virtual accounts. None of those store domain credentials. TaskHound filters
all of them and only reports services running as actual domain accounts -- usually somewhere
between 0 and 15 per host.

### Filtering rules

Built-in accounts (always excluded):
- LocalSystem, NT AUTHORITY\SYSTEM, and variants
- LocalService, NT AUTHORITY\LocalService, NT AUTHORITY\Local Service
- NetworkService, NT AUTHORITY\NetworkService, NT AUTHORITY\Network Service
- NT SERVICE\* (virtual service accounts -- one per service, no real credentials)
- Empty/null start_name (defaults to LocalSystem)

Local accounts are also excluded via SAMR enumeration of the host's local user database.

What remains: `SHINRA\svc_mako`, `svc_materia@shinra.local`, or bare usernames that aren't
in the local SAM. These are the ones with passwords in LSA secrets.

## Classification

Services use the same classification engine as scheduled tasks:

| Level | Meaning | Example |
|-------|---------|---------|
| TIER-0 | Domain Admin, Enterprise Admin, etc. | SHINRA\svc_mako (member of Domain Admins) |
| PRIV | High-value per BloodHound or custom list | SHINRA\svc_materia (marked HVT in BloodHound) |
| SERVICE | Normal domain account | SHINRA\svc_backup |

Same BloodHound data, same LDAP queries, same tier-0 detection. The only difference is
the label: SERVICE instead of TASK.

### gMSA detection

Accounts ending in `$` get flagged as `[gMSA]` -- Group Managed Service Accounts. These
use automatically rotated passwords managed by AD. Their passwords are stored in LSA
secrets under a different key format (`_SC_GMSA_{GUID}_<HMAC>`) that makes matching
them back to the account name non-trivial.

TaskHound extracts gMSA NTLM hashes from LSA secrets by computing the HMAC-SHA256 key
from the account name and matching it against the `_SC_GMSA_` entries. When a match is
found, the hash is associated with the corresponding service and displayed alongside it.
This works for gMSA accounts whose password has been fetched by the host (i.e., the
service has been started at least once -- Windows retrieves the gMSA password from AD
via GKDI at service start time and caches it in LSA).

## CLI flags

```bash
# Enumerate both tasks AND services (default is tasks only)
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local --services

# Services only, skip task enumeration entirely
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local --services-only

# Services + BloodHound integration for classification
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local --services \
  --bh-live --bhce --bh-api-key-id KEYID --bh-api-key SECRET

# Services + credential extraction (LSA secrets for service passwords)
taskhound -u cloud.strife -p 'Buster$word97!' -d shinra.local -t reactor01.shinra.local --services
# (--loot is on by default, extracts service passwords from LSA)
```

## Output

When `--services` is used, you get:
- Combined summary table showing both tasks and services
- Separate CSV files: `taskhound_results.csv` (tasks) and `taskhound_services.csv` (services)
- Separate OpenGraph files: `taskhound_opengraph.json` and `taskhound_services_opengraph.json`
- HTML report includes both (if enabled)

The separation exists because tasks and services have different schemas and different
graph relationships. Jamming them into one file felt wrong.

## Limitations

- Requires admin access to the target (SCM queries need it)
- Only enumerates Win32 services, not kernel/filesystem drivers (those don't run as user accounts)
- gMSA NTLM extraction only works if the host has fetched the gMSA password from AD at least once (i.e., the service was started). If a gMSA service was configured but never started, the password won't be in LSA secrets on that host
- Service binary path analysis is informational only -- TaskHound doesn't check for DLL hijacking or unquoted paths (yet)
