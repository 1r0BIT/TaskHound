# OpenGraph Nodes and Edges Reference

This document describes every custom node kind and edge kind that TaskHound creates
in BloodHound CE via OpenGraph. It follows the BloodHound
[extension best practices](https://bloodhound.specterops.io/opengraph/developer/best-practices)
format: General, Abuse Info, Remediation, OPSEC, References, and Properties.

---

## Nodes

### TH_ScheduledTask

**Kinds**: `TH_ScheduledTask`, `Base`, `TaskHound`

#### General

Represents a Windows scheduled task discovered on a remote host via SMB share crawling
(`C$\Windows\System32\Tasks`). TaskHound parses each task XML to extract the RunAs
principal, logon type, command line, trigger schedule, and credential storage hints.

A TH_ScheduledTask node appears in BloodHound when TaskHound processes a target with
`--bh-opengraph` enabled. Tasks running as local system accounts (NT AUTHORITY\SYSTEM,
LOCAL SERVICE, NETWORK SERVICE) are excluded from the graph -- only tasks running as
domain principals generate nodes and edges.

The node's `tasktype` property reflects TaskHound's classification:
- **TIER-0**: Runs as a domain admin, enterprise admin, or other Tier-0 principal
- **PRIV**: Runs as a high-value account (per BloodHound HVT data or custom lists)
- **TASK**: Normal domain account

#### Abuse Info

**Stored credential extraction**: If `credentialsstored` is true, the task was created
with the "store password" option (logon type `Password`). The password is stored as a
DPAPI-encrypted blob under `C:\Windows\System32\config\systemprofile\AppData\
Local\Microsoft\Credentials\`. TaskHound can extract and decrypt these blobs with
`--loot` when running as a local administrator on the target. The decrypted password
appears in the `password` property.

Note: `S4U` (Service for User to Self) tasks do **not** store credentials. S4U uses
Kerberos S4U2Self to obtain a local-only token without persisting the password. These
tasks are limited to local resources (no network access) and are not exploitable
through credential extraction.

**Command hijack**: If the task's `command` points to a writable path or uses an
unquoted service path, an attacker with write access to that location can replace
the binary. The task runs with the privileges of the `runas` principal on its next
trigger.

**Task replacement**: With write access to the Tasks share (typically requires local
admin), an attacker can replace the task XML to change the command while preserving
the stored credential. The credential remains valid for the original RunAs account.

**Lateral movement**: A task running as `DOMAIN\svc_backup` with stored credentials
on HOST-A means those credentials can be recovered. If `svc_backup` has admin rights
on HOST-B (visible through BloodHound's existing attack paths from the User node),
the recovered password enables lateral movement to HOST-B.

#### Remediation

1. **Respect tiering boundaries**: Tier-0 accounts (Domain Admins, Enterprise
   Admins, DC machine accounts) must never run tasks on Tier-1 or Tier-2 assets.
   A Domain Admin task on a member server means that compromising that one server
   -- a Tier-1 asset -- gives the attacker a direct path to Tier-0. This is the
   single most impactful finding TaskHound surfaces. If you fix nothing else, fix
   these. Move the task to a Tier-0 host, or (better) reduce the account's
   privileges so it no longer needs Tier-0 access.

2. **Use Group Managed Service Accounts (gMSA)** instead of domain accounts with
   stored passwords. gMSA's primary security benefit is that each account gets a
   unique, machine-generated 240-byte password that is never shared or reused.
   When an attacker extracts a human-chosen password from a task, that password
   often works on other systems, VPNs, email, or personal accounts -- the blast
   radius of a single credential is unpredictable. A gMSA password is useless
   anywhere except as that specific account's NTLM hash. Automatic rotation
   (default 30 days) further limits the window of opportunity.

   Note: gMSA does NOT prevent credential extraction -- the NTLM hash is still
   recoverable from LSA secrets on the host (the same LSA dump needed for DPAPI
   extraction also contains `_SC_<ServiceName>` secrets). gMSA eliminates password
   reuse risk and limits credential lifetime, but it is not a substitute for
   proper tiering. Scheduled tasks with gMSA require Windows Server 2012+ and the
   `sMSA` logon type.

3. **Audit stored credentials**: Run TaskHound periodically to identify tasks with
   `credentialsstored: true`. These are the highest-priority findings after
   tiering violations.

4. **Remove stale tasks**: The `passwordanalysis` property flags tasks with stale
   credentials (password changed after task creation, or task not run in a long
   time). A stale task is likely abandoned -- question whether it is still needed
   at all. Removing unnecessary tasks eliminates the attack surface entirely,
   which is better than refreshing credentials on a task nobody remembers creating.

5. **Use Credential Guard**: Credential Guard prevents DPAPI credential extraction
   on the host. TaskHound detects Credential Guard via `--credguard` (enabled by
   default) and reports it in the `passwordanalysis` property.

#### OPSEC

**Detection when enumerating tasks** (TaskHound's collection phase):
- SMB connections to `C$` and `IPC$` shares generate standard logon events
  (Event ID 4624, Logon Type 3). This is indistinguishable from normal file
  server traffic in most environments.
- LSARPC SID resolution (named pipe `\pipe\lsarpc`) may trigger alerts in
  environments monitoring named pipe access. Disable with `--no-rpc`.
- See [opsec.md](opsec.md) for the full protocol impact table.

**Detection when abusing extracted credentials**:
- Using a recovered password for interactive logon generates Event ID 4624
  (Logon Type 10 for RDP, Type 3 for network logon).
- Pass-the-hash with an NTLM hash generates Event ID 4624 with Logon Type 9
  (NewCredentials) or Type 3, depending on the tool.
- Overpass-the-hash / Kerberos TGT request with a password generates standard
  Kerberos events (Event ID 4768, 4769).

**Detection when hijacking task commands**:
- Modifying files under `C:\Windows\System32\Tasks` generates NTFS audit events
  if object access auditing is enabled (Event ID 4663).
- Task Scheduler logs task execution to `Microsoft-Windows-TaskScheduler/Operational`
  (Event ID 200 = action started, 201 = action completed).

#### References

- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/) -- Scheduled Task/Job: Scheduled Task
- [MITRE ATT&CK T1003.004](https://attack.mitre.org/techniques/T1003/004/) -- OS Credential Dumping: LSA Secrets (DPAPI extraction)
- [MITRE ATT&CK T1078.002](https://attack.mitre.org/techniques/T1078/002/) -- Valid Accounts: Domain Accounts (credential reuse)
- [Microsoft: Task Scheduler Security](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-security) -- Task creation permissions and logon types
- [Microsoft: DPAPI](https://learn.microsoft.com/en-us/windows/win32/seccrypto/cng-dpapi) -- Data Protection API overview
- [Microsoft: gMSA](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts-overview) -- Group Managed Service Accounts

#### Properties

| Property | Type | Always Present | Description |
|---|---|---|---|
| `name` | string | Yes | Task name stripped of root path (e.g., `Avalanche_Trigger`) |
| `hostname` | string | Yes | FQDN of the host (e.g., `DC01.DOMAIN.LAB`) |
| `runas` | string | Yes | Principal the task runs as (e.g., `DOMAIN\svc_backup`, `user@domain.lab`) |
| `enabled` | boolean | Yes | Whether the task is enabled |
| `command` | string | Yes | Full command line including arguments |
| `logontype` | string | Yes | Logon type: `Password`, `S4U`, `InteractiveToken`, `ServiceAccount`, or `Unknown` |
| `credentialsstored` | boolean | Yes | True if the task stores credentials (logon type Password) |
| `author` | string | No | Task author from XML metadata |
| `date` | string | No | Task creation date |
| `triggertype` | string | No | Trigger type: `Time`, `Calendar`, `Boot`, `Logon`, etc. |
| `startboundary` | string | No | First trigger start time |
| `interval` | string | No | Repetition interval |
| `duration` | string | No | Repetition duration |
| `daysinterval` | string | No | Days between executions |
| `passwordanalysis` | string | No | Credential freshness analysis (e.g., `Password could be stale`) |
| `password` | string | Yes | Decrypted password or `none` |
| `tasktype` | string | No | Classification: `TIER-0`, `PRIV`, or `TASK` |
| `classification` | string | No | Classification reason (e.g., `TIER0 Group Membership; AdminSDHolder`) |

---

### TH_WindowsService

**Kinds**: `TH_WindowsService`, `Base`, `TaskHound`

#### General

Represents a Windows service running under a domain account, discovered via the
Service Control Manager RPC interface (`\pipe\svcctl`). TaskHound enumerates services
with `--services` and filters out those running as local system accounts, keeping
only services that authenticate as domain principals.

All domain-account services store credentials -- Windows encrypts the service password
using LSA secrets and stores it in the SECURITY registry hive. This is distinct from
scheduled task credential storage (DPAPI).

The `isgmsa` property indicates whether the service uses a Group Managed Service
Account. gMSA services have their password managed by Active Directory, but the
current NTLM hash can still be extracted from LSA secrets if the attacker has local
admin access.

#### Abuse Info

**LSA secret extraction**: Every domain-account service stores its password as an
LSA secret (`_SC_<ServiceName>`). With local admin access, these secrets can be
extracted via registry reads (TaskHound does this automatically as part of
`--loot`) or via tools like `nxc smb <target> --lsa` and `secretsdump.py`. The
`password` property shows the extracted credential
(plaintext for regular accounts, NTLM hash for gMSA accounts).

**Binary path hijack**: If `binarypath` contains an unquoted path with spaces
(e.g., `C:\Program Files\App\service.exe`), Windows may execute a binary placed at
`C:\Program.exe` or `C:\Program Files\App\service.exe` depending on the path
resolution order. Check for unquoted paths in the `binarypath` property.

**Service reconfiguration**: With `SC_MANAGER_ALL_ACCESS` or the service's specific
DACL allowing it, an attacker can change the service binary path to a payload and
restart the service. The payload runs as the service account.

**gMSA NTLM extraction**: Even though gMSA passwords are 240+ character random
blobs, the NTLM hash is extractable from LSA secrets. This hash is usable for
pass-the-hash attacks. The `password` property shows the hash as `NTLM:<hash>`.

**Lateral movement**: Same pattern as TH_ScheduledTask -- recover credentials from
a service on HOST-A, use them to authenticate to HOST-B where the service account
has privileges.

#### Remediation

1. **Respect tiering boundaries**: Tier-0 service accounts must only run on Tier-0
   hosts. A service running as a Domain Admin on a member server breaks the
   security boundary -- compromising that Tier-1 host gives the attacker Tier-0
   credentials directly from LSA secrets. Services classified as TIER-0 on
   non-Tier-0 hosts are the most critical finding TaskHound surfaces.

2. **Use gMSA where possible**: gMSA's primary value is eliminating password reuse
   risk. Each gMSA gets a unique, machine-generated 240-byte password that is
   never shared across systems or reused by humans elsewhere. When an attacker
   extracts a human-chosen service password, that password may work on other
   systems, VPNs, or personal accounts -- the blast radius is unpredictable.
   A gMSA credential is only useful as that account's NTLM hash. Automatic
   rotation (default 30 days) further limits the validity window.

   Note: gMSA does not prevent extraction -- the NTLM hash lives in LSA secrets
   (`_SC_<ServiceName>`) and is recoverable with local admin access. gMSA
   eliminates password reuse and limits credential lifetime, but it is not a
   substitute for proper tiering.

3. **Audit service accounts**: Run TaskHound with `--services` to enumerate all
   domain-account services. Prioritize tiering violations (TIER-0 on non-Tier-0
   hosts), then services with static passwords.

4. **Quote binary paths**: Ensure all service binary paths are properly quoted in
   the registry. Use `sc qc <service>` to check.

5. **Restrict service configuration ACLs**: Use `sc sdshow <service>` to audit the
   service DACL. Remove unnecessary write permissions.

6. **Enable Credential Guard**: Prevents LSA secret extraction (though TaskHound's
   registry-based approach may still work in some configurations -- check the
   `passwordanalysis` property for details).

7. **Monitor service account usage**: Alert on interactive logon (Event ID 4624,
   Type 10) for accounts that should only perform network logon (Type 3).

#### OPSEC

**Detection when enumerating services** (TaskHound's collection phase):
- SVCCTL RPC via `\pipe\svcctl` (named pipe). Some EDR products monitor named pipe
  access patterns -- rapid enumeration of all services looks different from normal
  service management. Service enumeration is off by default (`--services` opt-in).
- See [opsec.md](opsec.md) for the full protocol impact table.

**Detection when extracting LSA secrets** (TaskHound's `--loot` phase, or `nxc --lsa`):
- Remote Registry service start generates Event ID 7036 (Service Control Manager).
  Some EDR products specifically alert on RemoteRegistry starts.
- Registry reads to `SECURITY` and `SYSTEM` hives create a distinctive access
  pattern. TaskHound uses registry-only extraction (no files written to ADMIN$),
  which has fewer IOCs than traditional `secretsdump.py`, but is still detectable.
- See [opsec.md](opsec.md#lsa-secret-extraction) for details.

**Detection when abusing extracted credentials**:
- Same as TH_ScheduledTask -- credential reuse generates standard authentication events.
- Pass-the-hash with extracted gMSA NTLM generates Event ID 4624 with NtLmSsp
  authentication package.

**Detection when hijacking service binaries**:
- File creation/modification under `C:\Program Files` generates NTFS audit events
  (Event ID 4663) if object access auditing is enabled.
- Service start/stop events logged as Event ID 7036 and 7045 (new service installed).

#### References

- [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/) -- Create or Modify System Process: Windows Service
- [MITRE ATT&CK T1003.004](https://attack.mitre.org/techniques/T1003/004/) -- OS Credential Dumping: LSA Secrets
- [MITRE ATT&CK T1574.009](https://attack.mitre.org/techniques/T1574/009/) -- Hijack Execution Flow: Unquoted Service Path
- [MITRE ATT&CK T1078.002](https://attack.mitre.org/techniques/T1078/002/) -- Valid Accounts: Domain Accounts
- [Microsoft: Service Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Microsoft: gMSA](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts-overview)

#### Properties

| Property | Type | Always Present | Description |
|---|---|---|---|
| `name` | string | Yes | Service name (e.g., `TH_gMSA_Cloud_Svc`) |
| `hostname` | string | Yes | FQDN of the host |
| `servicename` | string | Yes | Service name (same as `name`) |
| `displayname` | string | No | Human-readable display name |
| `startname` | string | No | Service account (e.g., `DOMAIN\svc_account`) |
| `binarypath` | string | No | Service binary path and arguments |
| `starttype` | string | No | Start type: `Auto`, `Manual`, `Disabled`, `DelayedAuto` |
| `servicetype` | string | No | Service type: `Win32OwnProcess`, `Win32ShareProcess`, etc. |
| `state` | string | No | Current state: `Running`, `Stopped`, `StartPending`, etc. |
| `credentialsstored` | boolean | Yes | Always `true` for domain-account services |
| `isgmsa` | boolean | Yes | Whether the account is a Group Managed Service Account |
| `passwordanalysis` | string | No | Credential freshness or extraction analysis |
| `password` | string | Yes | Extracted password, NTLM hash (`NTLM:<hash>`), or `none` |
| `serviceclassification` | string | No | Classification: `TIER-0`, `PRIV`, or `SERVICE` |
| `classification` | string | No | Classification reason |

---

## Edges

### TH_HasTask

**Direction**: `Computer` -> `TH_ScheduledTask`

**Traversable**: No. This edge is declared **non-traversable** in TaskHound's v9
extension schema and is deliberately excluded from BloodHound Pathfinding / Attack
Paths. Because these tasks store no credentials, there is no recoverable secret to
pivot on, so including them in pathfinding would generate false attack paths. The
edge is still visible in raw Cypher (`MATCH ()-[:TH_HasTask]->()`).

#### General

Indicates that a scheduled task exists on the computer but does **not** store
credentials. The task uses logon type `InteractiveToken` (runs only when the user
is already logged in) or `ServiceAccount` (uses the machine's service ticket).

These tasks are less immediately exploitable than `TH_HasTaskWithStoredCreds` because
there is no password to extract, but they still reveal which privileged accounts
are configured to run automated tasks on which hosts.

#### Abuse Info

Without stored credentials, the primary attack vector is **command hijacking**:
replace the task's executable with a payload. When the task triggers and the RunAs
user is logged in (for InteractiveToken), the payload executes in their security
context.

For ServiceAccount tasks, the task runs as the computer account. This is relevant
if the computer account has been delegated privileges (constrained/unconstrained
delegation).

#### Remediation

- Restrict write access to task binary paths
- Audit task creation permissions via Group Policy
- Monitor for task XML modifications (Event ID 4663 on `C:\Windows\System32\Tasks`)

#### OPSEC

Same as TH_ScheduledTask node OPSEC -- the edge itself doesn't create additional IOCs.

#### References

- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/) -- Scheduled Task/Job: Scheduled Task

---

### TH_HasTaskWithStoredCreds

**Direction**: `Computer` -> `TH_ScheduledTask`

**Traversable**: Yes. This edge is declared **traversable** in TaskHound's v9
extension schema, so it appears in BloodHound Pathfinding / Attack Paths (not just
raw Cypher). Together with `TH_RunsAs` it forms the real
`Computer -> TH_ScheduledTask -> RunAs principal` attack path that pathfinding can
discover automatically. On pre-v9 BloodHound the schema install no-ops and the edge
remains generic / Cypher-only.

#### General

Indicates that a scheduled task on this computer stores the RunAs account's password
(DPAPI-encrypted). This is the highest-value edge type for tasks -- the presence of
stored credentials means the password is recoverable with local admin access.

Created when the task's logon type is `Password`. (S4U tasks do not store
credentials -- they use Kerberos S4U2Self for local-only access without persisting
a password, so they get a `TH_HasTask` edge instead.)

#### Abuse Info

This edge represents a direct credential recovery opportunity:

1. Gain local admin on the Computer (start node)
2. Use TaskHound `--loot` or manual DPAPI extraction to recover the stored password
3. Authenticate as the RunAs user (end node's `runas` property -> follow the `TH_RunsAs` edge)
4. From the User node, follow existing BloodHound attack paths to escalate further

#### Remediation

- Migrate to gMSA or InteractiveToken logon types where possible
- Enable Credential Guard to protect DPAPI secrets
- Run TaskHound regularly to detect new tasks with stored credentials
- See TH_ScheduledTask node remediation for full guidance

#### OPSEC

- DPAPI extraction (`--loot`) accesses files under `C$\Windows\System32\config\
  systemprofile\` which may trigger file access alerts
- LSA extraction (part of `--loot`, disable with `--no-lsa`) accesses the SECURITY registry hive -- see
  [opsec.md](opsec.md#lsa-secret-extraction)

#### References

- [MITRE ATT&CK T1003.004](https://attack.mitre.org/techniques/T1003/004/) -- OS Credential Dumping: LSA Secrets
- [Microsoft: DPAPI](https://learn.microsoft.com/en-us/windows/win32/seccrypto/cng-dpapi)

---

### TH_HasServiceWithStoredCreds

**Direction**: `Computer` -> `TH_WindowsService`

**Traversable**: Yes. This edge is declared **traversable** in TaskHound's v9
extension schema, so it appears in BloodHound Pathfinding / Attack Paths (not just
raw Cypher). Together with `TH_RunsAs` it forms the real
`Computer -> TH_WindowsService -> RunAs principal` attack path that pathfinding can
discover automatically. On pre-v9 BloodHound the schema install no-ops and the edge
remains generic / Cypher-only.

#### General

Indicates that a Windows service on this computer runs as a domain account. All
domain-account services inherently store credentials as LSA secrets -- unlike
scheduled tasks, there is no "without stored creds" variant for services.

#### Abuse Info

This edge represents a direct credential recovery opportunity:

1. Gain local admin on the Computer (start node)
2. Extract LSA secrets (TaskHound does this via `--loot`, or use `nxc smb <target> --lsa` / `secretsdump.py`)
3. The service password appears as `_SC_<ServiceName>` in the LSA dump
4. Authenticate as the service account (follow the `TH_RunsAs` edge to the User node)
5. Pivot through BloodHound's existing attack paths from that User

For gMSA services (`isgmsa: true`), the extracted credential is an NTLM hash
rather than a plaintext password. This hash is directly usable for pass-the-hash.

#### Remediation

- Enforce tiering: Tier-0 service accounts must not run on Tier-1/Tier-2 hosts.
  This is the highest-priority fix -- it eliminates the cross-tier escalation path
- Use gMSA to eliminate password reuse risk and limit credential lifetime, but note
  this does not prevent extraction -- it eliminates the chance the password works
  elsewhere
- Restrict local admin access to hosts running privileged services
- Enable Credential Guard
- See TH_WindowsService node remediation for full guidance

#### OPSEC

- LSA secret extraction requires starting RemoteRegistry (Event ID 7036)
- Registry hive reads create a detectable pattern
- See [opsec.md](opsec.md#lsa-secret-extraction) for details

#### References

- [MITRE ATT&CK T1003.004](https://attack.mitre.org/techniques/T1003/004/) -- OS Credential Dumping: LSA Secrets
- [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/) -- Windows Service

---

### TH_RunsAs

**Direction**: `TH_ScheduledTask` -> `User` or `TH_WindowsService` -> `User`

**Traversable**: Yes. This edge is declared **traversable** in TaskHound's v9
extension schema and is the hinge of the attack path -- it carries pathfinding from
TaskHound's custom nodes onto BloodHound's native User node. Combined with
`TH_HasTaskWithStoredCreds` / `TH_HasServiceWithStoredCreds`, the full
`Computer -> TH_ScheduledTask|TH_WindowsService -> User` chain now surfaces in
BloodHound Pathfinding / Attack Paths. On pre-v9 BloodHound the schema install
no-ops and the edge remains generic / Cypher-only.

#### General

Links a scheduled task or Windows service to the domain principal it authenticates
as. This is the critical edge for attack path analysis -- it connects TaskHound's
custom nodes into BloodHound's existing graph of User/Group/Computer relationships.

The User node at the end of this edge is matched by SID (objectId) when available,
falling back to name-based matching. SID-based matching is more reliable as it
works across domain renames and avoids ambiguity with duplicate names.

#### Abuse Info

This edge maps "this task/service authenticates as this user." Because it is
traversable, the chain below is now discoverable directly in BloodHound Pathfinding
rather than only via hand-written Cypher:

1. Extract credentials from the task/service (via `TH_HasTaskWithStoredCreds` or
   `TH_HasServiceWithStoredCreds`)
2. Follow this `TH_RunsAs` edge to identify the compromised User
3. From the User node, use BloodHound's standard pathfinding to find escalation
   paths (MemberOf, AdminTo, HasSession, GenericAll, etc.)

The combination of `TH_HasTaskWithStoredCreds → TH_ScheduledTask → TH_RunsAs → User →
MemberOf → Domain Admins` represents a complete privilege escalation path from
"local admin on one host" to "domain admin" -- and since `TH_HasTaskWithStoredCreds`
and `TH_RunsAs` are both traversable, BloodHound stitches it into Attack Paths
automatically.

#### Remediation

- Principle of least privilege: ensure the RunAs account only has the permissions
  the task/service actually needs
- TIER-0 accounts should not run tasks/services on non-Tier-0 hosts
- Monitor for lateral movement from the User node using BloodHound's attack path
  analysis

#### OPSEC

This edge is informational and does not correspond to any network activity.

#### References

- [MITRE ATT&CK T1078.002](https://attack.mitre.org/techniques/T1078/002/) -- Valid Accounts: Domain Accounts
