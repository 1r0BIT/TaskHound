# Architecture

**Analysis Date:** 2026-02-06

## Pattern Overview

**Overall:** Layered monolithic architecture with plugin-style resolver backends.

**Key Characteristics:**
- Multi-stage processing pipeline: discovery → enumeration → classification → resolution → export
- Pluggable credential resolution with fallback chains (BloodHound → LDAP → LSARPC → SMB)
- Single entry point (`cli.py`) orchestrating multiple execution modes (online, offline, offline-disk)
- Dataclass-driven data model for type safety and export consistency
- Rich CLI framework with configuration file support

## Layers

**CLI / Orchestration Layer:**
- Purpose: Parse arguments, load configuration, orchestrate workflows
- Location: `taskhound/cli.py`, `taskhound/config.py`, `taskhound/config_model.py`
- Contains: Argument parser, config file loading, CLI validation logic
- Depends on: All other layers (orchestrates execution)
- Used by: `__main__.py` entry point

**Engine Layer:**
- Purpose: Core task enumeration and processing logic
- Location: `taskhound/engine/`
- Contains:
  - `online.py`: SMB enumeration for live targets
  - `offline.py`: XML parsing for offline exports
  - `async_runner.py`: Parallel execution for multiple targets
  - `helpers.py`: Task processing utilities (classification, credential validation, DPAPI)
- Depends on: Auth context, models, resolver, parsers, SMB layer
- Used by: CLI orchestration in `cli.py`

**Data Model Layer:**
- Purpose: Structured representations of core entities
- Location: `taskhound/models/`
- Contains: `task.py` (TaskRow dataclass, TaskType enum)
- Depends on: None (lowest level)
- Used by: All processing layers

**Resolution Layer:**
- Purpose: SID ↔ Name conversion, Tier-0 detection, domain trust resolution
- Location: `taskhound/resolver/`
- Contains:
  - `sid_to_name.py`: Main SID resolution entry point with fallback chains
  - `name_to_sid.py`: Username/hostname to SID conversion
  - `tier0.py`: Privileged account detection
  - `trusts.py`: Trust chain and cross-domain SID handling
  - `netbios.py`: NetBIOS name caching
  - `backends/`: Pluggable backends (BloodHound, LDAP, LSARPC, GC, SMB)
- Depends on: Auth context, logging, utils (networking, credentials)
- Used by: Engine layer for task enrichment

**Credential Storage Layer:**
- Purpose: DPAPI decryption, LAPS password querying, credential validation
- Location: `taskhound/dpapi/`, `taskhound/laps/`, `taskhound/smb/task_rpc.py`
- Contains:
  - DPAPI key extraction and credential blob decryption
  - LAPS password retrieval from AD with caching
  - Task Scheduler RPC for credential validation
  - Credential Guard detection
- Depends on: Auth context, SMB connections
- Used by: Engine layer helpers

**SMB / Network Layer:**
- Purpose: Low-level Windows protocol communication
- Location: `taskhound/smb/`
- Contains:
  - `connection.py`: SMB connection management, FQDN resolution via DNS/SMB
  - `tasks.py`: Remote task directory crawling
  - `task_rpc.py`: Task Scheduler RPC operations
  - `credguard.py`: Credential Guard detection via RPC
- Depends on: Impacket library, auth context
- Used by: Engine layer, credential storage layer

**Output Layer:**
- Purpose: Format and write results in multiple formats
- Location: `taskhound/output/`
- Contains:
  - `printer.py`: Console output formatting
  - `writer.py`: CSV, JSON, plain text export
  - `html_report.py`: HTML report generation
  - `summary.py`: Summary table and statistics
  - `bloodhound.py`: BloodHound OpenGraph integration
- Depends on: Task models, logging
- Used by: CLI orchestration

**Parsing Layer:**
- Purpose: Extract task data from XML and high-value exports
- Location: `taskhound/parsers/`
- Contains:
  - `task_xml.py`: Windows scheduled task XML parsing
  - `highvalue.py`: BloodHound high-value target loading
- Depends on: Models, logging
- Used by: Engine layer

**Authentication & Config Layer:**
- Purpose: Centralize credential and configuration management
- Location: `taskhound/auth/`, `taskhound/config.py`, `taskhound/config_model.py`
- Contains:
  - `auth/context.py`: AuthContext dataclass
  - Config file parsing (TOML)
  - BloodHound configuration model
- Depends on: None (foundational)
- Used by: CLI layer, engine layer

**Classification Layer:**
- Purpose: Determine task privilege level (TIER-0, PRIV, TASK)
- Location: `taskhound/classification.py`
- Contains: Task classification logic using high-value data and tier-0 detection
- Depends on: Resolver layer, logging, models
- Used by: Engine layer

**Utility Layer:**
- Purpose: Shared helpers and abstractions
- Location: `taskhound/utils/`
- Contains:
  - `logging.py`: Rich logging (good, info, warn, debug, status)
  - `ldap.py`: LDAP query utilities
  - `credentials.py`: Credential matching and validation
  - `cache_manager.py`: SID resolution caching with TTL
  - `bh_api.py`: BloodHound API queries
  - `network.py`, `dns.py`: Network utilities
  - `helpers.py`: General utilities
- Depends on: External libraries (ldap3, impacket, requests)
- Used by: All layers

**BloodHound Connector Layer:**
- Purpose: Live BloodHound connection and querying
- Location: `taskhound/connectors/`
- Contains: `bloodhound.py` (BHCE API client)
- Depends on: Auth context, logging, HTTP requests
- Used by: CLI orchestration for live data fetching

## Data Flow

**Online (Live SMB) Flow:**

1. CLI parses args and loads config
2. CLI initializes BloodHound (if --bh-live) or high-value file (if --bh-data)
3. CLI fetches domain SIDs via LDAP (if no BH data)
4. CLI pre-caches computer SIDs for targets
5. CLI initiates parallel or sequential target scanning
6. Engine: `process_target()` for each target:
   - SMB connect with LAPS credentials (if LAPS mode)
   - Crawl `C:\Windows\System32\Tasks` directory
   - Parse each task XML
   - Classify tasks (TIER-0/PRIV/TASK) using high-value data
   - Resolve SID → Name via fallback chain (BH → LDAP → LSARPC → SMB)
   - Validate credentials via Task Scheduler RPC (if enabled)
   - Detect Credential Guard (if enabled)
   - Collect DPAPI blobs (if --loot)
   - Generate TaskRow objects
7. CLI aggregates results from all targets
8. CLI generates outputs (JSON, CSV, plain, HTML)
9. CLI generates BloodHound OpenGraph (if --bh-opengraph)
10. CLI uploads to BloodHound (if credentials available)

**Offline (XML Export) Flow:**

1. CLI points to directory with previously exported XMLs
2. Engine: `process_offline_directory()`:
   - Scan for task XML files recursively
   - Parse each task XML
   - Classify tasks using high-value data (from file or --bh-live)
   - Resolve SIDs via LDAP only (no SMB access available)
   - No credential validation or DPAPI looting (requires live access)
3. CLI generates outputs

**Offline Disk (Mounted Filesystem) Flow:**

1. CLI points to mounted Windows filesystem (VHDX, forensic image)
2. Engine: `disk_loader.extract_dpapi_key_from_registry()`:
   - Extract SYSTEM registry hive
   - Query LSA secrets for DPAPI_SYSTEM key
3. Engine: `load_from_disk()`:
   - Locate task XML files in mounted filesystem
   - Back up files if --backup enabled
4. Follows offline processing with extracted DPAPI key

**State Management:**

- **Cache**: SID resolution results cached in SQLite (TTL configurable)
- **BloodHound Data**: In-memory HighValueLoader or connector
- **Domain SIDs**: Cache of domain → domain_sid mappings (in-memory)
- **LAPS Passwords**: In-memory LAPSCache with decrypted passwords
- **Tier-0 Membership**: In-memory cache per LDAP session
- **DPAPI Decryption**: Runtime only, credentials not persisted

## Key Abstractions

**TaskRow:**
- Purpose: Type-safe representation of scheduled task data
- Location: `taskhound/models/task.py`
- Pattern: Dataclass with 40+ fields (host, path, runas, command, classification, etc.)
- Usage: All processing layers work with TaskRow instances; exported to JSON/CSV

**AuthContext:**
- Purpose: Centralize authentication parameters (eliminate 8+ parameter functions)
- Location: `taskhound/auth/context.py`
- Pattern: Dataclass with primary + LDAP-specific credentials
- Usage: Passed to process_target and resolution functions

**HighValueLoader:**
- Purpose: Load and cache high-value targets from BloodHound exports or live API
- Location: `taskhound/parsers/highvalue.py`
- Pattern: Loader class with hv_users, hv_sids, hv_computers, hv_domain_sids dicts
- Usage: Engine classification and SID resolution fallback

**ClassificationResult:**
- Purpose: Encapsulate task classification decision
- Location: `taskhound/classification.py`
- Pattern: Dataclass with task_type, reason, password_analysis, should_include
- Usage: Returned by classify_task() to engine

**LAPSCache:**
- Purpose: Manage per-host LAPS passwords with decryption
- Location: `taskhound/laps/__init__.py`
- Pattern: Cache class with get_password(hostname) method
- Usage: Optional credential source when LAPS mode enabled

**AsyncTaskHound:**
- Purpose: Parallel target processing with rate limiting and jitter
- Location: `taskhound/engine/async_runner.py`
- Pattern: Thread pool executor with progress bar and error aggregation
- Usage: Invoked when --threads > 1 or --jitter specified

**Resolver Backends (Plugin Pattern):**
- Purpose: Pluggable SID resolution strategies
- Location: `taskhound/resolver/backends/`
- Backends:
  - BloodHound: Query cached BloodHound data
  - LDAP: Query Active Directory via ldap3
  - LSARPC: RPC call to LsarLookupSids
  - GC: Global Catalog queries for cross-forest SIDs
  - SMB: Fallback to SMB API calls
- Usage: Resolver layer tries in priority order

## Entry Points

**CLI Entry Point:**
- Location: `taskhound/__main__.py`
- Triggers: `python -m taskhound` or `taskhound` (installed)
- Responsibilities: Import and call main()

**Main Orchestration:**
- Location: `taskhound/cli.py:main()`
- Triggers: Called from __main__.py
- Responsibilities:
  - Print banner
  - Parse arguments
  - Validate arguments
  - Initialize cache, logging, BloodHound
  - Route to online/offline/offline-disk processing
  - Handle LAPS initialization
  - Aggregate results
  - Generate exports
  - Upload to BloodHound

**Online Processing Entry:**
- Location: `taskhound/engine/online.py:process_target()`
- Triggers: Called for each target in online mode
- Responsibilities:
  - SMB connection management
  - Task enumeration and parsing
  - Task classification
  - Credential resolution and validation
  - DPAPI looting
  - TaskRow generation

**Offline Processing Entry:**
- Location: `taskhound/engine/offline.py:process_offline_directory()`
- Triggers: Called in offline or offline-disk modes
- Responsibilities:
  - Directory scanning for XML files
  - Task parsing and classification
  - LDAP-only resolution
  - TaskRow generation

## Error Handling

**Strategy:** Non-fatal error propagation with detailed logging.

**Patterns:**

1. **SMB Operations**: Exceptions logged, per-host errors don't abort global scan
   - File read failure → skip file, continue crawl
   - Connection timeout → mark target failed, continue
   - Permission denied → log warning, return empty task list

2. **LDAP/RPC Queries**: Fallback to lower-priority resolution methods
   - LSARPC fails → try SMB API
   - LDAP fails → try LSARPC
   - Resolution completely fails → use raw SID string

3. **DPAPI Decryption**: Partial success (some creds decrypted, some fail)
   - Malformed blob → log, skip
   - Missing DPAPI key → collect for offline decryption
   - Decryption error → mark as encrypted in output

4. **BloodHound Integration**: Graceful degradation
   - BH query fails → log warning, continue with LDAP
   - Upload fails → log, files still saved locally
   - Missing nodes for OpenGraph edges → create orphaned edges if --bh-allow-orphans

5. **LAPS**: Connection errors are fatal (configured as --laps mode)
   - Connection fails → sys.exit(1)
   - Query returns no results → sys.exit(1)
   - Specific host fails → added to laps_failures, scan continues

## Cross-Cutting Concerns

**Logging:**
- Framework: Rich console with color coding
- Levels: good (✓ success), info, status (*), warn (!), debug
- Approach: Hierarchical prefixing (host/task context)

**Validation:**
- Task rule filters: include_ms, include_local, unsaved_creds, include_all
- Credential validation: Task Scheduler RPC queries (can be disabled with --no-validate-creds)
- FQDN resolution: Verified before SMB connection

**Authentication:**
- Primary auth: NTLM password, NTLM hash, Kerberos (+ccache), Kerberos+AES
- LDAP override: Separate credentials for SID resolution (--ldap-* flags)
- LAPS mode: Per-target local admin passwords from AD
- Fallback precedence: LDAP credentials > main credentials (explicitly defined in code)

**Caching:**
- SID resolution: SQLite backend with configurable TTL (default 24h)
- Computer SIDs: Pre-fetched before scan to avoid per-host LDAP calls
- LAPS passwords: In-memory with statistics tracking
- BloodHound data: Loaded once at startup

**OPSEC Considerations:**
- --opsec flag disables: LDAP, RPC, DPAPI looting, credguard detection, cred validation
- --jitter: Random delay between target enumeration
- --rate-limit: Throttle target enumeration speed
- --threads 1: Sequential mode (default parallel is --threads 10)
- --dns-tcp: Force DNS over TCP for proxy tunneling

---

*Architecture analysis: 2026-02-06*
