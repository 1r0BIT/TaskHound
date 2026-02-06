# Codebase Structure

**Analysis Date:** 2026-02-06

## Directory Layout

```
taskhound/                           # Main package root
├── __init__.py                      # Package initialization
├── __main__.py                      # Entry point (python -m taskhound)
├── cli.py                           # CLI orchestration and main() function
├── config.py                        # Argument parser and config file loading
├── config_model.py                  # BloodHoundConfig dataclass
├── classification.py                # Task privilege classification logic
├── auth/                            # Authentication management
│   ├── __init__.py
│   └── context.py                   # AuthContext dataclass
├── engine/                          # Core processing pipelines
│   ├── __init__.py
│   ├── online.py                    # Live SMB enumeration (process_target)
│   ├── offline.py                   # Offline XML processing (process_offline_directory)
│   ├── disk_loader.py               # Offline disk extraction (mounted filesystems)
│   ├── async_runner.py              # Parallel target processing
│   └── helpers.py                   # Engine utilities (DPAPI, credential validation, etc.)
├── models/                          # Data structures
│   ├── __init__.py
│   └── task.py                      # TaskRow dataclass, TaskType enum
├── resolver/                        # SID/Name resolution and Tier-0 detection
│   ├── __init__.py                  # Public API re-exports
│   ├── sid_to_name.py               # Main SID resolution entry point
│   ├── name_to_sid.py               # Name/hostname to SID conversion
│   ├── tier0.py                     # Privileged account detection
│   ├── trusts.py                    # Domain trust and cross-domain handling
│   ├── netbios.py                   # NetBIOS name caching/resolution
│   ├── constants.py                 # Well-known SIDs and RID mappings
│   └── backends/                    # Pluggable resolution strategies
│       ├── __init__.py
│       ├── bloodhound.py            # BloodHound data queries
│       ├── ldap.py                  # LDAP queries (ldap3 backend)
│       ├── lsarpc.py                # LSARPC RPC calls
│       ├── gc.py                    # Global Catalog queries
│       └── (smb backend used via SMB layer)
├── smb/                             # Windows protocol operations
│   ├── __init__.py
│   ├── connection.py                # SMB connection, FQDN resolution
│   ├── tasks.py                     # Remote task directory crawling
│   ├── task_rpc.py                  # Task Scheduler RPC operations
│   └── credguard.py                 # Credential Guard detection
├── dpapi/                           # DPAPI credential decryption
│   ├── __init__.py
│   ├── decryptor.py                 # DPAPI decryption logic
│   ├── looter.py                    # Collect credential blobs
│   └── parser.py                    # Parse credential files
├── laps/                            # LAPS password management
│   ├── __init__.py
│   ├── models.py                    # LAPS data structures
│   ├── parsing.py                   # Parse LAPS attributes
│   ├── decryption.py                # MS-GKDI decryption
│   ├── query.py                     # LDAP queries for LAPS
│   ├── exceptions.py                # LAPS-specific exceptions
│   └── helpers.py                   # LAPS utilities
├── parsers/                         # Input data parsing
│   ├── __init__.py
│   ├── task_xml.py                  # Windows scheduled task XML parser
│   └── highvalue.py                 # BloodHound high-value export loader
├── connectors/                      # External service integrations
│   ├── __init__.py
│   └── bloodhound.py                # BloodHound CE API client
├── opengraph/                       # BloodHound OpenGraph generation
│   ├── __init__.py
│   ├── builder.py                   # Build OpenGraph JSON structure
│   └── writer.py                    # Write OpenGraph files
├── output/                          # Result export and formatting
│   ├── __init__.py
│   ├── printer.py                   # Console output formatting
│   ├── writer.py                    # JSON, CSV, plain text export
│   ├── html_report.py               # HTML report generation
│   ├── summary.py                   # Summary tables and statistics
│   └── bloodhound.py                # BloodHound upload integration
└── utils/                           # Shared utilities
    ├── __init__.py
    ├── logging.py                   # Rich logging functions (good, info, warn, debug, status)
    ├── console.py                   # Console UI helpers (banners, panels)
    ├── cache_manager.py             # SID resolution cache with TTL
    ├── credentials.py               # Credential matching and finding
    ├── ldap.py                      # LDAP query helpers
    ├── laps.py                      # LAPS password retrieval
    ├── bh_api.py                    # BloodHound API queries
    ├── bh_auth.py                   # BloodHound authentication
    ├── dns.py                       # DNS utilities
    ├── network.py                   # Network connectivity checks
    ├── pwd_resolver.py              # Password age analysis
    ├── sid_resolver.py              # SID resolution wrapper
    ├── date_parser.py               # Date/timestamp parsing
    └── helpers.py                   # General utilities
```

## Directory Purposes

**taskhound/**
- Purpose: Main package root
- Contains: Package initialization, entry points, top-level orchestration
- Key files: `__init__.py`, `__main__.py`, `cli.py`, `config.py`

**taskhound/auth/**
- Purpose: Authentication credential management
- Contains: AuthContext dataclass bundling all credential parameters
- Key files: `context.py`

**taskhound/engine/**
- Purpose: Core enumeration and processing pipelines
- Contains: Online/offline mode handlers, async execution, processing helpers
- Key files: `online.py`, `offline.py`, `async_runner.py`, `helpers.py`

**taskhound/models/**
- Purpose: Type-safe data structures
- Contains: TaskRow dataclass (central task representation), TaskType enum
- Key files: `task.py`

**taskhound/resolver/**
- Purpose: SID ↔ Name conversion and privilege detection
- Contains: Multi-tier resolution chains, Tier-0 detection, trust handling
- Key files: `sid_to_name.py`, `name_to_sid.py`, `tier0.py`, `backends/`

**taskhound/smb/**
- Purpose: Windows protocol operations (SMB, RPC)
- Contains: SMB connection management, task crawling, RPC operations
- Key files: `connection.py`, `tasks.py`, `task_rpc.py`, `credguard.py`

**taskhound/dpapi/**
- Purpose: DPAPI credential decryption
- Contains: Blob decryption, credential parsing, key extraction
- Key files: `decryptor.py`, `looter.py`, `parser.py`

**taskhound/laps/**
- Purpose: LAPS password management and decryption
- Contains: LDAP queries, MS-GKDI decryption, caching
- Key files: `query.py`, `decryption.py`, `models.py`

**taskhound/parsers/**
- Purpose: Parse input data (XML, CSV/JSON exports)
- Contains: Task XML parser, high-value target loader
- Key files: `task_xml.py`, `highvalue.py`

**taskhound/connectors/**
- Purpose: External service APIs
- Contains: BloodHound API client
- Key files: `bloodhound.py`

**taskhound/opengraph/**
- Purpose: BloodHound OpenGraph integration
- Contains: Build and write OpenGraph JSON
- Key files: `builder.py`, `writer.py`

**taskhound/output/**
- Purpose: Result export and presentation
- Contains: Multiple export formats, HTML reports, summaries
- Key files: `writer.py`, `html_report.py`, `summary.py`

**taskhound/utils/**
- Purpose: Shared utilities and helpers
- Contains: Logging, caching, LDAP helpers, credentials, networking
- Key files: `logging.py`, `cache_manager.py`, `ldap.py`, `credentials.py`

## Key File Locations

**Entry Points:**
- `taskhound/__main__.py`: Python module entry point
- `taskhound/cli.py:main()`: Primary orchestration function (560+ lines)
- `taskhound/config.py:build_parser()`: CLI argument parser setup

**Configuration:**
- `taskhound/config.py`: Config file loading (TOML), argument validation
- `taskhound/config_model.py`: BloodHoundConfig dataclass
- `taskhound/auth/context.py`: AuthContext dataclass

**Core Logic:**
- `taskhound/engine/online.py`: Live SMB enumeration (process_target)
- `taskhound/engine/offline.py`: Offline XML processing
- `taskhound/classification.py`: Task privilege classification
- `taskhound/resolver/sid_to_name.py`: Main SID resolution (with fallback chains)

**Data Models:**
- `taskhound/models/task.py`: TaskRow dataclass (40+ fields)
- `taskhound/resolver/constants.py`: Well-known SIDs, RID mappings

**SMB/Network:**
- `taskhound/smb/connection.py`: SMB connection management, FQDN resolution
- `taskhound/smb/tasks.py`: Remote directory crawling
- `taskhound/smb/task_rpc.py`: Task Scheduler RPC wrapper

**Credential/DPAPI:**
- `taskhound/dpapi/decryptor.py`: DPAPI decryption (CNG interface)
- `taskhound/laps/decryption.py`: MS-GKDI key derivation
- `taskhound/smb/credguard.py`: Credential Guard detection

**Parsing:**
- `taskhound/parsers/task_xml.py`: Windows Task XML parser
- `taskhound/parsers/highvalue.py`: BloodHound export loader

**Resolution Backends:**
- `taskhound/resolver/backends/bloodhound.py`: BloodHound data queries
- `taskhound/resolver/backends/ldap.py`: LDAP queries
- `taskhound/resolver/backends/lsarpc.py`: LSARPC RPC calls
- `taskhound/resolver/backends/gc.py`: Global Catalog queries

**Output:**
- `taskhound/output/writer.py`: CSV, JSON, plain text export
- `taskhound/output/html_report.py`: HTML report generation
- `taskhound/output/summary.py`: Summary statistics and tables
- `taskhound/output/printer.py`: Console formatting

**Utilities:**
- `taskhound/utils/logging.py`: Rich logging (good, info, warn, debug, status)
- `taskhound/utils/cache_manager.py`: SID resolution cache with TTL
- `taskhound/utils/ldap.py`: LDAP query wrappers
- `taskhound/utils/credentials.py`: Credential matching
- `taskhound/utils/console.py`: CLI UI helpers (banners, panels)

## Naming Conventions

**Files:**
- Module names: `lowercase_with_underscores.py`
- Package names: `lowercase` directories
- Test files: `test_*.py` (co-located in tests/ directory)

**Directories:**
- Public packages: `lowercase` (e.g., `resolver`, `engine`, `smb`)
- Subpackages: `lowercase` (e.g., `backends/`)
- Private modules: start with underscore (rarely used)

**Functions:**
- Public: `snake_case`
- Entry points: `main()`, `process_target()`, `process_offline_directory()`
- Helpers: `_private_helper()` prefix for internal functions
- Async tasks: `run()` method in classes like `AsyncTaskHound`

**Classes:**
- PascalCase: `TaskRow`, `AuthContext`, `HighValueLoader`, `AsyncTaskHound`
- Enum classes: `TaskType`, `CredentialStatus`
- Config classes: `BloodHoundConfig`

**Variables:**
- Local: `snake_case`
- Constants: `UPPERCASE_WITH_UNDERSCORES` (e.g., `WELL_KNOWN_SIDS`, `TASK_ROOT`)
- Private module vars: `_leading_underscore`

## Where to Add New Code

**New Feature (Task Processing):**
- Primary code: `taskhound/engine/online.py` or `offline.py`
- Tests: `tests/test_engine_*.py`
- Models: Add fields to `taskhound/models/task.py` if needed

**New Component/Module (Credential Type, New Protocol):**
- Implementation: Create new directory under `taskhound/` (e.g., `taskhound/kerberos/`)
- Export API: Add to package `__init__.py`
- Tests: `tests/test_<component>.py`
- Integration: Import in `taskhound/cli.py` orchestration

**Utilities/Helpers:**
- Shared helpers: `taskhound/utils/helpers.py` or new module in `taskhound/utils/`
- Logging: Use existing `taskhound/utils/logging.py` functions
- Network operations: Add to `taskhound/utils/network.py` or `dns.py`
- Credential utilities: `taskhound/utils/credentials.py`

**New Resolver Backend:**
- Implementation: `taskhound/resolver/backends/<name>.py`
- Register in: `taskhound/resolver/__init__.py` exports
- Integration: Import in `taskhound/resolver/sid_to_name.py` resolution chain

**New Output Format:**
- Implementation: `taskhound/output/<format>.py`
- Export function: Register in `taskhound/output/writer.py`
- CLI integration: Add to argument parser in `taskhound/config.py`

**New OPSEC/Credential Mode:**
- Configuration: Add to `taskhound/config.py` argument group
- Auth logic: Update `taskhound/auth/context.py` if credential-related
- Processing: Add handling in `taskhound/engine/online.py` process_target()
- Tests: `tests/test_<mode>.py`

## Special Directories

**tests/**
- Purpose: Test files for all modules
- Generated: No
- Committed: Yes
- Organization: One test file per module (test_*.py)
- Key files: `conftest.py` (pytest fixtures), `test_engine_online.py`, `test_sid_resolver.py`

**config/**
- Purpose: Example configuration files
- Generated: No
- Committed: Yes
- Key files: `taskhound.toml` (example configuration)

**htmlcov/**
- Purpose: Code coverage reports
- Generated: Yes (by pytest --cov)
- Committed: No

DistSources:

**dist/**
- Purpose: Built distribution (wheel, source tarball)
- Generated: Yes (by setuptools)
- Committed: No

**taskhound.egg-info/**
- Purpose: Egg distribution metadata
- Generated: Yes (by setuptools)
- Committed: No

**.planning/codebase/**
- Purpose: GSD codebase analysis documents
- Generated: Yes (by gsd:map-codebase)
- Committed: No (local planning directory)

## Module Dependencies

**Dependency Graph (simplified):**

```
cli.py (main)
├── config.py, config_model.py
├── auth/context.py
├── engine/
│   ├── online.py
│   │   ├── smb/connection.py, tasks.py, task_rpc.py, credguard.py
│   │   ├── parsers/task_xml.py
│   │   ├── classification.py
│   │   ├── resolver/sid_to_name.py
│   │   ├── dpapi/, laps/
│   │   └── output/
│   ├── offline.py
│   │   ├── parsers/task_xml.py
│   │   ├── classification.py
│   │   ├── resolver/
│   │   └── output/
│   ├── disk_loader.py
│   │   └── dpapi/
│   └── async_runner.py
│       └── online.py
├── parsers/highvalue.py
├── resolver/
│   ├── sid_to_name.py
│   │   ├── backends/bloodhound.py, ldap.py, lsarpc.py, gc.py
│   │   └── constants.py
│   ├── name_to_sid.py
│   ├── tier0.py
│   └── trusts.py
├── connectors/bloodhound.py
├── opengraph/builder.py, writer.py
└── utils/
    ├── logging.py
    ├── cache_manager.py
    ├── ldap.py
    ├── credentials.py
    └── ...

No circular dependencies detected.
```

## Import Patterns

**Absolute imports (standard):**
```python
from taskhound.auth import AuthContext
from taskhound.models.task import TaskRow
from taskhound.resolver import resolve_sid
from taskhound.utils.logging import good, info
```

**Relative imports (within package):**
```python
from .auth import AuthContext  # from taskhound/engine/online.py
from ..resolver import resolve_sid  # from taskhound/smb/connection.py
```

**Re-exports (api.py pattern):**
- `taskhound/resolver/__init__.py`: Re-exports all public resolver functions
- `taskhound/engine/__init__.py`: Re-exports process_target, process_offline_directory, AsyncTaskHound
- `taskhound/laps/__init__.py`: Re-exports LAPS classes and functions

**Third-party:**
- `impacket`: SMB/RPC operations
- `ldap3`: LDAP queries
- `rich`: Console formatting and logging
- `cryptography`: DPAPI decryption
- `requests`: BloodHound API
- `dnspython`: DNS queries

---

*Structure analysis: 2026-02-06*
