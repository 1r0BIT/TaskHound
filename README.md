<p align="center">
  <img width="350" height="350" alt="TaskHound Logo" src="https://github.com/user-attachments/assets/325b57e9-b96a-4de7-9974-736fd58fa70c" />
</p>

<p align="center">
  <strong>Windows Privileged Scheduled Task Discovery Tool</strong> for fun and profit.
</p>
<hr />

TaskHound hunts for Windows scheduled tasks that run with privileged accounts and stored credentials. It enumerates tasks over SMB, parses XMLs, and identifies high-value attack opportunities through BloodHound support.

For Backstory/Lore, and more explanations: see my associated: [Blog Post](https://r0bit.io/posts/taskhound.html)

## Key Features

- **Tier 0 & High Value Detection**: Automatically identifies tasks running as classic Tier 0 and High Value users
- **BloodHound Integration**: Connect to your live BloodHound Instance or ingest exports
- **OpenGraph Support**: Visualize tasks as graph entities in BloodHound
- **DPAPI Support**: Collect and decrypt DPAPI blobs from scheduled tasks
- **SID Resolution**: Supports LDAP for SID lookups when encountered in tasks
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
taskhound -u homer.simpson -p P@ssw0rd -d thesimpsons.local -t moe.thesimpsons.local
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
        Trigger : Calendar (starts 2025-09-18 23:00, every 1 day, daily)
        Reason  : AdminSDHolder; TIER0 Group Membership
        Password Analysis : Password changed BEFORE task creation, password is valid!
        Next Step: Try DPAPI Dump / Task Manipulation

[PRIV] Windows\System32\Tasks\MaintenanceTask
        Enabled : True
        RunAs   : THESIMPSONS\marge.simpson
        What    : C:\Tools\cleanup.exe
        Author  : THESIMPSONS\Administrator
        Date    : 2025-09-18T23:05:43.0854575
        Trigger : Calendar (starts 2025-09-19 02:00, every 6 hours, daily)
        Reason  : High Value match found
        Password Analysis : Password changed AFTER task creation, Password could be stale
        Next Step: Try DPAPI Dump / Task Manipulation

[TASK] Windows\System32\Tasks\SIDTask  
        Enabled : True
        RunAs   : Administrator (S-1-5-21-3211413907-14631080-1147255650-500)
        What    : C:\Windows\System32\cmd.exe /c backup
        Author  : SYSTEM
        Date    : 2025-09-15T08:15:22.1234567
        Trigger : Time at 2025-09-16 03:00

[TASK] Windows\System32\Tasks\UserTask
        Enabled : False
        RunAs   : THESIMPSONS\bart.simpson
        What    : C:\Windows\System32\notepad.exe
        Author  : THESIMPSONS\bart.simpson
        Date    : 2025-09-18T12:30:15.1234567
        Trigger : Logon

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
taskhound -u homer.simpson -p pass -t moe.thesimpsons.local --bh-live --bhce --bh-connector http://127.0.0.1:8080 --bh-user admin --bh-password password
```

**Legacy BloodHound:**
```bash
taskhound -u homer.simpson -p pass -t moe.thesimpsons.local --bh-live --legacy --bh-connector bolt://127.0.0.1:7687 --bh-user neo4j --bh-password password
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
If there is no data found or wasn't supplied, taskhound will then try to look up the SID via LDAP unless supressed with `--no-ldap`.

### Dedicated LDAP Credentials

When using NTLM hashes for main authentication, you can provide separate credentials for LDAP SID resolution:

```bash
# Main auth with NTLM hash, separate LDAP credentials for SID resolution
taskhound -u homer.simpson --hashes :5d41402abc4b2a76b9719d911017c592 -d thesimpsons.local -t moe.thesimpsons.local --ldap-user marge.simpson --ldap-password M@rg3P@ss --ldap-domain thesimpsons.local

# Or when you only have local admin access via LAPS Password or SAMDumps (domain='.')
taskhound -u Administrator -p L0c@lAdm1n! -d . -t moe.thesimpsons.local --ldap-user bart.simpson --ldap-password B@rtP@ss --ldap-domain thesimpsons.local
```

**Why separate LDAP credentials?**
- The ldap3 library doesn't support NTLM hash authentication in current versions
- You might only have local admin access but need domain LDAP for SID resolution
- Allows using lower-privilege accounts specifically for SID lookups

> **NOTE**: To use this reliably with kerberos auth you need a working krb5.conf.

## EXPERIMENTAL Features

> **WARNING**  
> Features in this section are **UNSAFE** for production environments. Limited testing has been done in lab environments. Don't blame me if something blows up your op or gets you busted. You have been warned.

### OpenGraph Attack Path Visualization (BHCE Only)

![1761663911331](https://github.com/user-attachments/assets/7cde5d08-24e8-49f8-9964-ba8e18864550)

TaskHound integrates with BloodHound Community Edition's **OpenGraph** platform to visualize scheduled tasks as first-class graph entities. This enables attack path analysis showing how privileged tasks create escalation opportunities.

**What You Get:**
- **Custom Nodes**: `ScheduledTask` with 19+ properties (credentials, triggers, password analysis)
- **Custom Edges**: 
  - `HasTask` / `HasTaskWithStoredCreds`: Computer → Task relationships
  - `RunsAs`: Task → User/Group execution context
- **Attack Paths**: `(Owned User) → AdminTo → (Computer) → HasTask → (Task) → RunsAs → (Privileged User)`

**Quick Start:**

```bash
# Collect and auto-upload in one command (bh_connector.config is preferred)
taskhound -u homer.simpson -p pass -t moe.thesimpsons.local -d thesimpsons.local --bh-set-icon

# Manual generation (no upload)
taskhound -u homer.simpson -p pass -d thesimpsons.local -t moe.thesimpsons.local --bh-opengraph --bh-output ./opengraph --bh-no-upload
```

**Features:**
- Auto-detects config and enables OpenGraph
- Uploads directly to BloodHound CE
- Custom icon support (`--bh-set-icon`)
- Local backup always saved

> **Full documentation, abuse scenarios, and Cypher queries coming in separate docs** (currently being finalized for the merge)

### DPAPI Credential Extraction

TaskHound can extract and decrypt Task Scheduler credentials stored by Windows using DPAPI. This feature supports two workflows:

**Online Mode: Live Collection & Decryption**
```bash
# First, obtain DPAPI_SYSTEM userkey via LSA dump:
nxc smb moe.thesimpsons.local -u homer.simpson -p pass --lsa

# Option 1: Collect only (saves to dpapi_loot/moe.thesimpsons.local/)
taskhound -t moe.thesimpsons.local -u homer.simpson -p pass -d thesimpsons.local --loot

# Option 2: Collect + decrypt immediately (credentials shown inline with tasks)
taskhound -t moe.thesimpsons.local -u homer.simpson -p pass -d thesimpsons.local --loot --dpapi-key 0x51e43225...

# Option 3: Collect from multiple targets (WITHOUT --dpapi-key)
taskhound --targets-file hosts.txt -u homer.simpson -p pass -d thesimpsons.local --loot
# Then decrypt each target offline with its specific key
```

**Offline Mode: Decrypt Previously Collected Files**
```bash
# Decrypt files collected earlier with --loot:
taskhound --offline dpapi_loot/moe.thesimpsons.local --dpapi-key 0x51e43225...
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
                 [--offline OFFLINE] [--bh-data BH_DATA] [--bh-live] [--bh-connector BH_CONNECTOR]
                 [--bh-user BH_USER] [--bh-password BH_PASSWORD] [--bhce] [--legacy]
                 [--bh-save BH_SAVE] [--bh-opengraph] [--bh-output BH_OUTPUT] 
                 [--bh-no-upload] [--bh-set-icon] [--bh-force-icon] [--bh-icon BH_ICON] 
                 [--bh-color BH_COLOR] [--include-ms] [--include-local] [--include-all] 
                 [--unsaved-creds] [--no-ldap] [--ldap-user LDAP_USER] 
                 [--ldap-password LDAP_PASSWORD] [--ldap-domain LDAP_DOMAIN]
                 [--credguard-detect] [--loot] [--dpapi-key DPAPI_KEY]
                 [--plain PLAIN] [--json JSON] [--csv CSV] [--opengraph OPENGRAPH]
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

BloodHound Live Connection:
  --bh-live             Enable live BloodHound connection
  --bh-connector BH_CONNECTOR  
                        BloodHound connector URI (default: http://127.0.0.1:8080)
                        Examples: localhost, http://localhost:8080, https://bh.domain.com,
                                 bolt://neo4j.local:7687
                        Supports both BHCE (http/https) and Legacy (bolt) protocols
  --bh-user BH_USER     BloodHound username
  --bh-password BH_PASSWORD  BloodHound password
  --bhce                Use BHCE (Community Edition) connection
  --legacy              Use Legacy BloodHound (Neo4j) connection
  --bh-save BH_SAVE     Save retrieved BloodHound data to file

BloodHound OpenGraph Integration (BHCE ONLY):
  --bh-opengraph        Generate BloodHound OpenGraph JSON files (auto-enabled if 
                        bh_connector.config has valid BHCE credentials)
  --bh-output BH_OUTPUT Directory to save OpenGraph files (default: ./opengraph)
  --bh-no-upload        Generate OpenGraph files but skip automatic upload
  --bh-set-icon         Automatically set custom icon for ScheduledTask nodes
  --bh-force-icon       Force icon update even if icon already exists
  --bh-icon BH_ICON     Font Awesome icon name (default: heart)
  --bh-color BH_COLOR   Hex color code for icon (default: #8B5CF6)

LDAP/SID Resolution:
  --ldap-user LDAP_USER     Separate username for LDAP SID resolution
  --ldap-password LDAP_PASSWORD  Separate password for LDAP SID resolution  
  --ldap-domain LDAP_DOMAIN     Separate domain for LDAP SID resolution
  --no-ldap             Disable LDAP queries for SID resolution

Task Filtering:
  --include-ms          Include \Microsoft tasks (WARNING: very slow)
  --include-local       Include local system accounts (NT AUTHORITY\SYSTEM, etc.)
  --include-all         Include ALL tasks (combines --include-ms, --include-local, 
                        --unsaved-creds - WARNING: very slow and noisy)
  --unsaved-creds       Show tasks without stored credentials
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
  --opengraph OPENGRAPH Generate BloodHound OpenGraph JSON files (same as --bh-opengraph)
                        Directory path where files will be saved
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
### definitely on the list
- **Abuse Info Integration**: Add MITRE ATT&CK techniques and OPSEC notes to BloodHound nodes
- **OpenGraph Optimization**: Switch from name-based to ID-based node matching for reliable BloodHound integration
- **Node Caching System**: Multi-tier caching to reduce API calls by 80% and speed up repeated runs
- **API Key Authentication**: Support for BloodHound API tokens instead of username/password
- **Enhanced SID Resolution**: Improved fallback chain combining BloodHound, LDAP, and local SID databases
- **Unreachable Hosts Tracking**: Show failed connections in summary with detailed error reasons

### when i find time
- **Asynchronous Processing**: Multi-threaded target processing for 10x speedup on large environments
- **LAPS Support**: Automatic Local Administrator Password Solution integration like NetExec
- **Cross Domain Authentication**: Support for multi-domain environments with trust relationships
- **Custom Tier-0 Mappings**: Support for user-defined TIER-0 targets beyond standard groups

### nice to have
- **Colored Terminal Output**: Rich formatting with progress bars and status indicators
- **WMI Password Validation**: Check if stored task passwords are still valid via WMI queries
- **Automatic Script Grabbing**: Download task executables for offline analysis with restore functionality
- **Blue Team Audit Mode**: HTML reports with remediation guidance, etc.  

## Disclaimer

TaskHound is strictly an **audit and educational tool**. Use only in environments you own or where you have explicit authorization to test. Seriously. Don't be a jerk.

## Acknowledgement

[Fortra/Impacket](https://github.com/fortra/impacket) - SMB/RPC/Kerberos operations

[SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) - Active Directory attack path analysis

[Podalirius/bh-opengraph](https://github.com/Podalirius/bh-opengraph) - OpenGraph integration inspiration and implementation guidance

[tijldeneut/DPAPIck3](https://github.com/tijldeneut/DPAPIck3) - DPAPI decryption implementation reference

[Pupy Project](https://github.com/n1nj4sec/pupy) - DPAPI SYSTEM masterkey decryption techniques

[gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) - DPAPI operations and LSA secrets extraction research

and every contributor to these projects for the amazing work they did for the community.

## Contributing

PRs welcome. Don't expect wonders though. Half of this was caffeine-induced vibe-coding.

## License

Use responsibly. No warranty provided. See `LICENSE` for details.
