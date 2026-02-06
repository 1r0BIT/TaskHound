# Technology Stack

**Analysis Date:** 2026-02-06

## Languages

**Primary:**
- Python 3.11+ - All core application code, CLI, scanning logic

**Secondary:**
- None detected - Pure Python project

## Runtime

**Environment:**
- Python 3.11+ (enforced via `pyproject.toml` `requires-python = ">=3.11"`)

**Package Manager:**
- pip - Primary package management
- Lockfile: requirements.txt and requirements-dev.txt present (not a lock format like poetry.lock)

## Frameworks

**Core:**
- impacket 0.11.0+ - Windows/AD protocol support (SMB, RPC, LDAP, DCE/RPC, Kerberos)
- requests 2.25.0+ - HTTP client for BloodHound API connectivity
- neo4j 5.0.0+ - Optional Neo4j Bolt driver for Legacy BloodHound (bolt:// protocol)
- bhopengraph 1.1.0+ - BloodHound OpenGraph serialization library

**CLI & Output:**
- rich 13.0.0+ - Terminal UI: tables, panels, progress bars, colored output
- rich-argparse 1.0.0+ - Rich-formatted CLI help and argument display
- argparse - Built-in: CLI argument parsing via `taskhound.config` module

**Cryptography & Encoding:**
- pycryptodome 3.15.0+ - DPAPI decryption, crypto operations for LAPS decryption
- pyasn1 0.5.0+ - ASN.1 parsing for LAPS encrypted password decryption
- pyasn1-modules 0.3.0+ - PKCS#7/CMS support for LAPS decryption

**DNS & Network:**
- dnspython 2.0.0+ - DNS SRV record discovery for Domain Controller and Global Catalog discovery

**File Handling:**
- python-registry 1.3.1+ - Windows registry hive parsing for `--offline-disk` hostname detection

## Key Dependencies

**Critical:**
- impacket - Primary dependency for Windows AD enumeration: SMB connections (`taskhound/smb/connection.py`), LDAP queries (`taskhound/utils/ldap.py`), RPC/DCE-RPC task enumeration (`taskhound/smb/task_rpc.py`), Kerberos authentication
- bhopengraph - BloodHound OpenGraph node/edge building and serialization (`taskhound/opengraph/builder.py`, `taskhound/opengraph/writer.py`)
- neo4j - Legacy BloodHound support via Neo4j Bolt protocol (`taskhound/connectors/bloodhound.py`)
- requests - HTTP connectivity for BHCE (BloodHound Community Edition) REST API (`taskhound/connectors/bloodhound.py`, `taskhound/utils/bh_auth.py`)

**Infrastructure:**
- dnspython - DC/GC discovery via DNS SRV records (`taskhound/utils/dns.py`)
- pycryptodome - DPAPI/LAPS credential decryption (`taskhound/laps/decryption.py`, `taskhound/dpapi/decryptor.py`)
- pyasn1 + pyasn1-modules - Legacy LAPS encrypted password parsing

## Configuration

**Environment:**
- No `.env` file detected
- Configuration via TOML file: `taskhound.toml` (optional, in working directory or `~/.config/taskhound/`)
- CLI arguments (highest priority override)
- Environment variables (e.g., `${BH_API_KEY}` referenced in example config)

**Build:**
- `setup.cfg` handled by setuptools (via `pyproject.toml` `[build-system]`)
- Entry point: `taskhound = "taskhound.cli:main"` (defined in `pyproject.toml`)
- Package discovery: `taskhound*` (in `pyproject.toml` `[tool.setuptools.packages.find]`)

## Platform Requirements

**Development:**
- Python 3.11+ virtual environment
- Supported on Windows, macOS, Linux for running TaskHound
- Windows targets required for scanning (SMB/RPC enumeration)

**Production:**
- Local deployment: CLI executable via `pip install .`
- No server mode - command-line tool
- BloodHound CE/Legacy (remote) - optional, not required
- Windows Domain Controller or workstation - optional, for LDAP queries
- Cache: SQLite database (persistent, auto-created if caching enabled)

## Code Quality Tools

**Linting:**
- ruff 0.1.0+ - Fast Python linter (`taskhound/`, `tests/` scoped)
- Configuration: `ruff.toml`

**Type Checking:**
- mypy 1.5.0+ - Optional type checking (dev dependency)
- types-requests - Type stubs for requests library

**Testing:**
- pytest 7.4.0+ - Test runner
- pytest-cov 4.1.0+ - Coverage reporting
- pytest-mock 3.11.0+ - Mocking support
- Configuration: `pytest.ini`

## Version Info

**Current Release:** 1.1.0 (from `pyproject.toml`)

**License:** MIT

**Python Support:** 3.11+

---

*Stack analysis: 2026-02-06*
