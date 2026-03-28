# Changelog

All notable changes to TaskHound will be documented in this file.

---

## [1.1.5] - 2026-03-28

### Highlights

The SID resolver — previously a 2841-line monolith — has been fully replaced by a clean, modular `resolver/` package. This release also introduces SAMR-based local account discovery, credential confidence scoring, and a wave of reliability fixes hardened through live Active Directory lab testing.

---

### New Features

- **Dynamic local account discovery via SAMR** — Enumerates local users/groups through SAMR to correctly classify bare-name task principals instead of guessing
- **Credential confidence levels** — Never-run tasks with stored credentials now show a confidence indicator to distinguish validated from unvalidated findings
- **Default thread count raised to 10** — OPSEC mode still enforces sequential scanning; new `--jitter` flag adds random delay between targets
- **`-T` short flag for `--targets-file`** — Convenience alias for specifying target lists

### Refactors

- **Replaced legacy `utils/sid_resolver.py`** (2841 lines removed) — Four-phase migration to the new `resolver/` package: structure → implementation → consumer migration → test migration → legacy deletion
- **Credential validation heuristics restructured** — Empirical testing against live AD revealed edge cases; validation logic rewritten to match real-world behavior
- **`extract_domain_sid_from_hv` moved from constants to backends** — Domain SID extraction now lives with the BloodHound backend where it belongs
- **Type safety improvements across codebase** — Fixes for mypy strict mode compliance

### Fixes

- **SAMR enumeration infinite loop and CredGuard pipe handle leak** — SAMR queries could hang indefinitely; named pipe handles were leaked when Credential Guard was detected
- **UPN format handling in highvalue/tier0 checks** — `user@domain` format was not recognized, causing missed classifications
- **SMB connections leaked on early return paths** — `process_target()` now closes SMB connections in all exit paths
- **Paged LDAP search for LAPS queries** — Large environments hit `sizeLimitExceeded`; switched to paged results
- **OpenGraph compatibility with BloodHound v8.9.0+** — Dropped `objectid` from node properties which BH no longer accepts
- **Credential Guard detection for LsaCfgFlags values 1 and 2** — Previously only detected value 2; value 1 (UEFI lock) was missed
- **LDAP credential precedence** — `--ldap-*` CLI args now correctly override default credentials
- **Deduplicate Tier-0 accounts in HTML report** — Same account appearing via multiple group memberships was listed multiple times
- **NoneType.strip() errors in OpenGraph and highvalue modules** — Null principal names no longer crash the pipeline

---

## [1.1.0] - 2026-01-02

### Highlights

This is a major feature release with **125 commits** bringing significant improvements to performance, OPSEC controls, SID resolution, and user experience.

**Key Features:**
- **Auto-Targets**: Enumerate domain computers from BloodHound or LDAP instead of manual target lists
- **Credential Guard Detection**: Detect hosts with Credential Guard enabled (DPAPI extraction will fail)
- **OPSEC Controls**: Fine-grained control over noisy operations with `--opsec` and `--no-*` flags
- **Parallel Scanning**: Multi-threaded scanning with `--threads` for large networks
- **LAPS Integration**: Full LAPS support including Windows LAPS encrypted password decryption
- **RPC Credential Validation**: Validate stored credentials via Task Scheduler RPC
- **Rich Terminal UI**: Modern colored output with progress bars and panels

---

### Added

#### Target Discovery and Scanning

- **Auto-Targets Mode** (`--auto-targets`)
  - Enumerate domain computers from BloodHound (preferred) or LDAP
  - Filter by preset: `--ldap-filter servers` or `--ldap-filter workstations`
  - Filter by raw LDAP query: `--ldap-filter "(operatingSystem=*Server*)"`
  - Exclude stale accounts: `--stale-threshold 90` (days)

- **Parallel Scanning** (`--threads N`)
  - Thread-safe concurrent target processing
  - Rate limiting with `--rate-limit` (targets/second)
  - Dual-homed host deduplication (same FQDN, different IPs)
  - Progress tracking with `[Progress] X/Y (Z%)` status

- **CIDR Target Notation**
  - Specify targets as `10.0.0.0/24` for subnet scanning
  - Combine with `--threads` for efficient large-scale scans

#### OPSEC and Security

- **Credential Guard Detection** (`--credguard-detect`, enabled by default)
  - Checks `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags`
  - Uses RemoteRegistry service with automatic start/stop
  - OPSEC warning prompt before noisy registry operations

- **OPSEC Mode** (`--opsec`)
  - Disables all noisy operations in one flag
  - Granular control with `--no-credguard`, `--no-validate-creds`
  - Session-wide setting that propagates to all operations

- **OPSEC Warning Prompt**
  - Interactive confirmation before noisy operations
  - Can be bypassed with `--no-confirm` for automation

#### Credential Handling

- **LAPS Integration** (`--laps`)
  - Legacy LAPS (`ms-Mcs-AdmPwd`) support
  - Windows LAPS (`msLAPS-Password`, `msLAPS-EncryptedPassword`) with MS-GKDI decryption
  - LAPS credential caching for multi-target scans
  - `--laps-user` to override default Administrator username
  - `--force-laps` to override OPSEC restrictions

- **RPC Credential Validation** (`--validate-creds`)
  - Query Task Scheduler RPC for last run results
  - Detect invalid passwords, expired passwords, disabled accounts
  - Human-readable return code translation (70+ Windows error codes)

- **AES Key Authentication** (`--aes-key`)
  - Kerberos authentication using AES keys
  - Alternative to password/hash authentication

#### Classification and Analysis

- **LDAP-Based Tier-0 Detection** (`--ldap-tier0`)
  - Classify tasks without BloodHound using LDAP group membership
  - Queries Domain Admins, Enterprise Admins, Schema Admins, etc.
  - Results cached for performance

- **Offline Disk Analysis** (`--offline-disk`)
  - Analyze mounted Windows filesystems (VHDX, forensic images, etc.)
  - Note: Mounting the filesystem is outside the scope of this tool
  - Automatic DPAPI file discovery and extraction
  - Registry hive parsing for DPAPI keys

- **gMSA Detection Hint**
  - Detects gMSA accounts (username ends with `$`)
  - Displays hint about LSA secrets availability

- **Account Disabled Detection**
  - Shows `[DISABLED]` indicator for disabled accounts
  - Helps identify stale scheduled tasks

#### SID Resolution

- **Multi-Chain SID Resolution**
  - Chain 0: Static well-known SIDs (instant, 40+ entries)
  - Chain 1: Local domain (Cache -> BloodHound -> BH API -> LSARPC -> LDAP)
  - Chain 2: Same-forest foreign domains (Global Catalog on 3268/3269)
  - Chain 3: External trusts (UNKNOWN\<name> fallback)

- **Global Catalog Support** (`--gc-server`)
  - Auto-discovery via DNS SRV records (`_gc._tcp.<domain>`)
  - Resolves cross-domain SIDs within the same forest
  - Falls back to explicit server if auto-discovery fails

- **Unknown Domain SID Detection**
  - Caches known domain SID prefixes from BloodHound/LDAP
  - Maps well-known RIDs: `UNKNOWN\Administrator`, `UNKNOWN\Guest`
  - Avoids wasted network calls for local machine SIDs

- **Trust-Aware Resolution**
  - Detects foreign domain SIDs and routes to Global Catalog
  - Lazy NETBIOS-to-FQDN resolution for trusted domains
  - BloodHound edge data for cross-forest trust detection

- **LRU Cache for `is_sid()`**
  - Performance optimization for repeated SID format checks
  - Reduces regex overhead in large scans

#### User Interface

- **Rich Terminal UI**
  - Colored output with `rich` library
  - Progress bars during parallel scans
  - Spinner for BloodHound uploads
  - Unified Panel styling for all summary sections
  - Task type color coding: `[TIER-0]` red, `[PRIV]` yellow, `[TASK]` green

- **Rich CLI Help**
  - Table-based help with grouped options
  - Cleaner formatting with `rich-argparse`

- **Human-Readable Error Messages**
  - Windows Task Scheduler return codes decoded
  - LAPS failure reasons cleaned up
  - Connection errors with actionable hints

#### Output and Reporting

- **Unified Output Flag** (`-o/--output`)
  - Comma-separated format list: `--output plain,json,csv,html`
  - HTML audit report with severity grouping and statistics
  - All outputs go to `--output-dir` with type-specific subdirectories

- **Output Directory Auto-Creation**
  - `./output/` directory created automatically
  - Backup XMLs stored in `./output/raw_backups/`

#### Configuration

- **New TOML Options**
  - `gc_server` - Custom Global Catalog server
  - `credguard_detect` - Enable/disable Credential Guard detection
  - `validate_creds` - Enable/disable RPC validation
  - `auto_targets` - Enable auto-target enumeration
  - `stale_threshold` - Stale account filtering (days)
  - `no_confirm` - Skip OPSEC warning prompts

- **DNS over TCP** (`--dns-tcp`)
  - Force DNS queries over TCP
  - Required for SOCKS proxy compatibility

---

### Changed

#### Default Behavior

- Credential Guard detection enabled by default (use `--no-credguard` to disable)
- BloodHound connection auto-enabled when connector is specified
- Output directory defaults to `./output/`

#### CLI Changes

- Removed standalone `--opengraph` flag (OpenGraph always generated with `--bh-opengraph`)
- Removed `--bh-set-icon` flag (icon always set on upload)
- Renamed `--allow-orphans` to `--bh-allow-orphans` for naming consistency

#### Architecture Refactoring

- Split `engine.py` into `engine/` package (online, offline, async_runner, helpers)
- Split `laps.py` into `laps/` package (models, query, decryption, exceptions)
- Added `AuthContext` dataclass for authentication bundling
- Added `TaskRow` dataclass replacing `Dict[str, Any]`
- Added `ConnectionContext` and `ProcessingContext` dataclasses
- Extracted `classification.py` from engine
- Extracted `utils/credentials.py` for credential matching

#### Code Quality

- Consolidated duplicate `is_guid()` functions into `utils/helpers.py`
- Consolidated duplicate `parse_ntlm_hashes()` functions
- Improved exception handling with specific exception types
- Added `contextlib.suppress()` where appropriate
- Removed 1000+ lines of dead code

---

### Fixed

#### Critical Bugs

- **Double-Counting in Credential Validation** - Tasks were counted twice in validation summary due to duplicate storage in result dictionary

- **Summary Table Wrong Counting** - Hosts with 0 interesting tasks were incorrectly counted as "skipped" instead of "succeeded (0 tasks)". Added `TaskType.SKIPPED` for proper dual-homed detection

- **LDAP Hash Authentication** - `--hashes` parameter was not passed to LDAP validation. Fixed credential flow in `verify_ldap_connection()`

- **SQLite Cache Thread Safety** - "SQLite objects created in a thread..." errors with `--threads`. Implemented per-thread connections with `threading.local()`

- **Foreign Domain SID Resolution** - SIDs from trusted domains caused retry loops. Added `is_foreign_domain_sid()` check to skip LSARPC for cross-domain SIDs

- **Empty Domain LDAP Bug** - Empty domain string caused `invalidDNSyntax` errors. Added domain validation before LDAP queries

#### Other Fixes

- **Password Age Data Not Displayed** - Timezone mismatch between LDAP and task dates. Added `tz=timezone.utc` to datetime creation

- **TaskCount Shows Raw Count** - Now shows filtered count: "15 domain tasks (120 total)" for clearer representation of actual findings

- **SID Resolution Before Filtering** - Wasted cycles resolving SIDs for filtered tasks. Added early skip for well-known local SIDs

- **SID Resolution Race Condition** - Concurrent access to global state in multi-threaded mode. Added proper locking and thread-safe patterns

- **OpenGraph Upload Structure** - Incorrect nested graph structure check. Fixed to handle flat node/edge lists

- **LDAPS Connection Failure** - Added DC auto-discovery when LDAPS fails with better error messages for SSL issues

- **Stale Credential Warning** - Don't show stale warning when credentials are validated to avoid confusion

- **Tier-0 Classification** - AdminSDHolder alone no longer triggers TIER-0. Must be member of actual Tier-0 group

- **HTML Report Generation** - Handle None values gracefully to prevent crash on missing optional fields

---

### Removed

- Removed `output/opengraph.py` (1081 lines of dead code)
- Removed deprecated `--bh-set-icon` flag
- Removed standalone `--opengraph` flag (merged into `--bh-opengraph` workflow)
- Removed legacy 2-item tuple cache compatibility
- Removed BOF directory (moved to Extension-Kit repository)
- Removed `ldap3` dependency (using Impacket's LDAP)

---

### Performance

- **Parallel Processing** - 10x+ speedup with `--threads 10` on large networks with thread-safe result aggregation

- **SID Resolution Caching** - SQLite-backed persistent cache, LRU cache for `is_sid()` regex checks, negative caching for failed lookups

- **Early Skip Optimization** - Skip SID resolution for tasks that will be filtered, reducing unnecessary network calls

- **BloodHound Prefetch** - Pre-load user/computer data before scanning to avoid per-task API queries

---

### Documentation

- Updated README.md with new features
- Added TOML configuration examples
- Added troubleshooting section
- Updated acknowledgements

## [1.0.0] and below

Initial / Beta release.

---

[1.1.5]: https://github.com/1r0BIT/TaskHound/compare/v1.1.0...v1.1.5
[1.1.0]: https://github.com/1r0BIT/TaskHound/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/1r0BIT/TaskHound/releases/tag/v1.0.0
