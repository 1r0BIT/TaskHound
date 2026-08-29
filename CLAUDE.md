# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is TaskHound

TaskHound is a Python pentesting tool that discovers Windows scheduled tasks running with privileged accounts and stored credentials. It enumerates tasks over SMB, parses task XMLs, classifies privilege levels (TIER-0/PRIV/TASK), resolves SIDs, and optionally integrates with BloodHound for attack path visualization via OpenGraph.

## Commands

```bash
# Setup
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"

# Run the tool
taskhound -u user -p pass -d domain.local -t target

# Tests
make test                              # Full suite with coverage (--cov-fail-under=50)
make test-fast                         # Skip slow/live tests
pytest tests/test_classification.py    # Single test file
pytest tests/test_classification.py::test_name -x  # Single test, stop on failure
pytest -m "not live"                   # CI mode (excludes live lab tests)

# Code quality
make lint                              # ruff check
make format                            # ruff format + fix
make type-check                        # mypy
```

## Architecture

### Entry point and flow

`cli.py:main()` → parse args via `config.py:build_parser()` → authenticate → enumerate targets → process each target → output results.

Two processing modes:
- **Online** (`engine/online.py:process_target()`): SMB connect → crawl task XMLs → parse → classify → resolve SIDs → optionally loot DPAPI creds. This function is atomic per host — SMB connection couples collect+resolve+classify+loot together.
- **Offline** (`engine/offline.py` / `engine/disk_loader.py`): Parse XMLs from mounted disk images or previously collected backups.

Multi-target scanning uses `engine/async_runner.py:AsyncTaskHound` with `ThreadPoolExecutor` (not asyncio — SMB/RPC are blocking I/O).

### SID resolution chain

`resolver/` is the modular SID resolution package (the legacy 2841-line `utils/sid_resolver.py` has been removed). It provides multi-tier resolution:

**SID → Name**: BloodHound API → SQLite cache → LSARPC (target's LSA) → LDAP → Global Catalog
**Name → SID**: `resolver/name_to_sid.py`
**NETBIOS → FQDN**: `resolver/netbios.py`
**Tier-0 detection**: `resolver/tier0.py` (group membership queries)

Resolution backends live in `resolver/backends/` (bloodhound, gc, ldap, lsarpc).

### Task classification

`classification.py:classify_task()` determines privilege level: TIER-0 (domain admin, enterprise admin), PRIV (high-value per BloodHound/custom lists), or TASK (normal). Used by both online and offline engines.

The `models/task.py:TaskRow` dataclass is the structured representation of a task result (replaces older Dict approach).

### Authentication

`auth/context.py:AuthContext` bundles all credential parameters (password, NTLM hash, Kerberos, AES key, LDAP-specific overrides) into a single dataclass passed through the codebase.

### Key subsystems

- **LAPS** (`laps/`): Retrieves and decrypts Local Administrator Password Solution credentials for per-host auth
- **DPAPI** (`dpapi/`): Downloads and decrypts DPAPI credential blobs containing stored task passwords
- **SMB** (`smb/`): Connection management, task enumeration via share crawling, Credential Guard detection, task RPC for credential validation
- **OpenGraph** (`opengraph/`): Generates BloodHound CE graph nodes/edges for visualizing scheduled task attack paths
- **Output** (`output/`): HTML report, BloodHound upload, CSV/JSON/plain text writers, summary tables

### Config precedence

CLI args > Environment variables > Local `taskhound.toml` > `~/.config/taskhound/taskhound.toml` > Defaults. See `config/taskhound.toml.example` for all options.

## Conventions

- Python 3.12+ required, line length 120, ruff for linting/formatting
- Double quotes for strings (`ruff.toml` quote-style)
- impacket uses mixed-case function names — ruff rules N802/N806 are suppressed for compatibility
- Tests are in flat `tests/` directory with `test_` prefix; `conftest.py` has an autouse fixture that cleans up the global SQLite cache after each test
- Test markers: `unit`, `integration`, `slow`, `live` (live requires `tests/live_test_config.json` from lab environment)
- Module-level globals (caches like `_netbios_cache`, `_ldap_creds`, `_external_trust_prefixes`) can vanish between invocations — be aware when testing or modifying resolver state

## Active refactor

The codebase is being modularized from a monolithic CLI into a stage-based pipeline (warmup → collect → report). The SID resolver migration is complete — the legacy `utils/sid_resolver.py` has been removed and all consumers use the new `resolver/` package.
