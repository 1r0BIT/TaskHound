# TaskHound

**Windows Privileged Scheduled Task Discovery Tool** for fun and profit.

TaskHound hunts for Windows scheduled tasks that run with privileged accounts and stored credentials. It enumerates tasks over SMB, parses XMLs, and identifies high-value attack opportunities through BloodHound support.

## Key Features

- **Tier 0 & High Value Detection**: Automatically identifies tasks running as classic Tier 0 and High Value users
- **BloodHound Integration**: Connect to your live BloodHound Instance or ingest exports
- **Password Analysis**: Analyzes password age relative to task creation date
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

# With live BloodHound connection (BHCE)
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.local' -t 'TARGET_HOST' --bh-live --bhce --bh-ip 127.0.0.1 --bh-user admin --bh-password 'password'

# With live BloodHound connection (Legacy)
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.local' -t 'TARGET_HOST' --bh-live --legacy --bh-ip 127.0.0.1 --bh-user neo4j --bh-password 'password'
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

> **Note**: I currently only have a somewhat 'hacky' solution for the TIER-0 vs. PRIV logic for BHCE that checks if the istierzero or highvalue attribute is set AND if the user is actually a member of default TIER-0 groups. This is because if you mark a user as highvalue in the bhce gui, the istierzero attribute get's changed aswell. At this point I don't know if I'm being stupid or if this is actually intended.

### Data Ingestion

TaskHound can connect directly to live BloodHound instances for real-time high-value user data. It also supports direct parsing of BloodHound Exports.

#### Live BloodHound Connection

**BHCE (Community Edition):**
```bash
taskhound -u user -p pass -t target --bh-live --bhce --bh-ip 127.0.0.1 --bh-user admin --bh-password password
```

**Legacy BloodHound:**
```bash
taskhound -u user -p pass -t target --bh-live --legacy --bh-ip 127.0.0.1 --bh-user neo4j --bh-password password
```

**Configuration File Support:**
```ini
[BloodHound]
ip = 127.0.0.1
username = admin
password = ${BH_PASSWORD}
type = bhce
```

If you don't need live data or your BloodHound instance is located in an unreachable network, you can generate ingestable data with the following queries:

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

### Credential Guard Detection

Checks remote registry for Credential Guard status to determine DPAPI dump feasibility. Results include `"credential_guard": true/false` in output.

### BOF Implementation
See [BOF/README.md](BOF/README.md) for a Beacon Object File implementation of the core collection functionality.

## Full Usage Reference

```
Usage: taskhound [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [--hashes HASHES] 
                 [-k] [-t TARGET] [--targets-file TARGETS_FILE] [--dc-ip DC_IP]
                 [--offline OFFLINE] [--bh-data BH_DATA] [--bh-live] [--bh-ip BH_IP]
                 [--bh-user BH_USER] [--bh-password BH_PASSWORD] [--bhce] [--legacy]
                 [--bh-save BH_SAVE] [--include-ms] [--include-local] [--include-all] 
                 [--unsaved-creds] [--no-ldap] [--credguard-detect] [--plain PLAIN] 
                 [--json JSON] [--csv CSV] [--backup BACKUP] [--no-summary] [--debug]

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

BloodHound Live Connection:
  --bh-live             Enable live BloodHound connection
  --bh-ip BH_IP         BloodHound server IP address
  --bh-user BH_USER     BloodHound username
  --bh-password BH_PASSWORD  BloodHound password
  --bhce                Use BHCE (Community Edition) connection
  --legacy              Use Legacy BloodHound (Neo4j) connection
  --bh-save BH_SAVE     Save retrieved BloodHound data to file

Task Filtering:
  --include-ms          Include \Microsoft tasks (WARNING: very slow)
  --include-local       Include local system accounts (NT AUTHORITY\SYSTEM, etc.)
  --include-all         Include ALL tasks (combines --include-ms, --include-local, 
                        --unsaved-creds - WARNING: very slow and noisy)
  --unsaved-creds       Show tasks without stored credentials
  --no-ldap             Disable LDAP queries for SID resolution
  --credguard-detect    EXPERIMENTAL: Detect Credential Guard via remote registry

Output:
  --plain PLAIN         Save plain text output per target
  --json JSON           Export results to JSON file  
  --csv CSV             Export results to CSV file
  --backup BACKUP       Save raw XML files for offline analysis
  --no-summary          Disable summary table (shown by default)
  --debug               Enable debug output and full stack traces
```

## OPSEC Considerations

TaskHound relies heavily on impacket for SMB/RPC/Kerberos operations. Standard impacket IOCs apply.
**If you really care about OPSEC**: Use the BOF implementation or collect tasks manually, then analyze offline.

## Roadmap

When caffeine intake and free time align:
- Dedicated NetExec module (PR in Review)
- Automated credential blob extraction for offline decryption
- Support custom Tier-0 mappings instead of just the default ones
- OpenGraph integration for attack path mapping  

## Disclaimer

TaskHound is strictly an **audit and educational tool**. Use only in environments you own or where you have explicit authorization to test. Seriously. Don't be a jerk.

## Acknowledgement

[Fortra/Impacket](https://github.com/fortra/impacket)

[SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound)

and every contributor to these projects for the amazing work they did for the community.

## Contributing

PRs welcome. Don't expect wonders though. Half of this was caffeine-induced vibe-coding.

## License

Use responsibly. No warranty provided. See `LICENSE` for details.
