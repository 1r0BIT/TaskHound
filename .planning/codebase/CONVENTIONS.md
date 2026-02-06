# Coding Conventions

**Analysis Date:** 2026-02-06

## Naming Patterns

**Files:**
- Module files use lowercase with underscores: `cache_manager.py`, `task_xml.py`, `bloodhound.py`
- Package directories use lowercase with underscores: `taskhound/`, `connectors/`, `parsers/`, `utils/`, `laps/`
- Test files follow pattern: `test_<module_name>.py` (e.g., `test_sid_resolver.py`, `test_cache_manager.py`)

**Functions:**
- Lowercase with underscores: `parse_task_xml()`, `get_laps_passwords()`, `classify_task()`, `normalize_targets()`
- Private/internal functions prefixed with underscore: `_get_task_date_for_analysis()`, `_analyze_password_age()`, `_add_account_status()`
- Helper/utility functions clearly named: `looks_like_domain_user()`, `is_sid()`, `sanitize_json_string()`

**Variables:**
- Lowercase with underscores: `computer_sids`, `task_date`, `hv_loaded`, `laps_cache`, `all_rows`
- Boolean flags prefixed implicitly with `is_`, `has_`, `no_`, `enable_`: `has_stored_creds`, `is_tier0`, `no_ldap`, `enable_cache`
- Cache-related variables: `session_cache`, `pwd_cache`, `tier0_cache`, `netbios_cache`

**Types & Classes:**
- Classes use PascalCase: `TaskRow`, `ClassificationResult`, `AuthContext`, `HighValueLoader`, `LAPSCache`, `AsyncTaskHound`
- Enums use PascalCase with UPPERCASE values: `TaskType.TIER0`, `TaskType.PRIV`, `TaskType.TASK`, `TaskType.FAILURE`
- Exception classes end with `Error` or `Exception`: `LAPSError`, `LAPSConnectionError`, `LAPSPermissionError`, `LAPSEmptyCacheError`
- Type aliases use snake_case: `PwdLastSetCache`, `Tier0Cache`

**Dictionary/Config Keys:**
- Lowercase with underscores: `"username"`, `"dc_ip"`, `"target"`, `"output_dir"`, `"bh_connector"`
- CLI argument destinations use underscores: `args.username`, `args.dc_ip`, `args.targets_file`, `args.no_ldap`

## Code Style

**Formatting:**
- Tool: Ruff (both formatter and linter)
- Line length: 120 characters (`line-length = 120` in ruff.toml)
- Quotes: Double quotes for strings (`quote-style = "double"`)
- Indentation: Spaces (4 spaces, `indent-style = "space"`)
- Line endings: Auto-detected (`line-ending = "auto"`)

**Linting:**
- Tool: Ruff with comprehensive rule sets enabled
- Rules enabled: E (pycodestyle errors), W (warnings), F (pyflakes), I (isort imports), N (pep8-naming), UP (pyupgrade), B (flake8-bugbear), C4 (comprehensions), SIM (simplify)
- Notable exclusions:
  - E501: Line too long (handled by formatter)
  - N802, N806: Impacket library uses mixed case, excluded for compatibility
  - SIM102, SIM105, SIM108, SIM117: Prefer explicit code for readability in tests

**Type Checking:**
- Tool: Optional mypy (`mypy taskhound/ --ignore-missing-imports`)
- Type hints used on function parameters and return values: `def classify_task(...) -> ClassificationResult:`
- Optional types annotated: `Optional[str]`, `Optional[Any]`, `Optional[Dict]`
- Union types for alternatives: `Union[str, bytes]`

## Import Organization

**Order:**
1. Standard library imports: `import os`, `import json`, `from pathlib import Path`, `from datetime import datetime`
2. Third-party imports: `import requests`, `from rich.console import Console`, `from impacket.ldap import ldap`
3. Local/relative imports: `from .config import build_parser`, `from ..utils.logging import debug`

**Path Aliases:**
- Relative imports within package: `from .models.task import TaskRow`, `from .resolver import is_sid`
- Parent package imports: `from ..auth import AuthContext`, `from ..utils.logging import debug, warn`
- TYPE_CHECKING pattern for circular imports: `if TYPE_CHECKING: from .models.task import TaskRow`

**Barrel Files:**
- Used in package `__init__.py` files to re-export public APIs:
  - `taskhound/auth/__init__.py`: `from .context import AuthContext; __all__ = ["AuthContext"]`
  - `taskhound/connectors/__init__.py`: `from .bloodhound import connect_bloodhound; __all__ = ["connect_bloodhound"]`
- Parsers package: `__all__ = []` pattern (selective re-export via documentation)

## Error Handling

**Patterns:**
- Custom exceptions inherit from base exception: `class LAPSError(Exception)` with specific subclasses
- Exception chaining with context: `except ExceptionType as e:` followed by context-aware error message
- Defensive checks before operations: `if not os.path.exists(path):` before file operations
- Optional returns for non-fatal errors: Functions return `Optional[T]` to signal missing/invalid data
- Try-except with logging instead of silent failures:
  ```python
  try:
      result = risky_operation()
  except SpecificException as e:
      debug(f"Operation failed: {e}")
      return None
  ```

**Logging on Errors:**
- Use logging functions for all error/warning cases
- Debug level for diagnostic info: `debug(f"Cache miss for {key}")`
- Warning level for recoverable issues: `warn(f"BloodHound data is {data_age_days} days old")`
- Error level for user-facing issues (printed to stderr)

## Logging

**Framework:** Custom logging module delegating to Rich console

**Patterns:**
- Import from `taskhound.utils.logging`: `from .utils.logging import debug, good, info, status, warn`
- Log levels:
  - `status(msg)`: Always printed (concise output) - for user-facing progress
  - `good(msg)`: Success messages, only in verbose/debug mode
  - `info(msg)`: Informational, verbose-only by default
  - `warn(msg, verbose_only=False)`: Warnings (always printed unless verbose_only)
  - `error(msg)`: Error messages (user-facing)
  - `debug(msg)`: Debug output (debug mode only)
- Control verbosity: `set_verbosity(args.verbose, args.debug)`
- Rich formatting in messages: `status("[+] Processing {hostname}")`

**Context Usage:**
- LAPS operations: Use `status()` for progress
- SID resolution: Use `debug()` for each lookup
- Configuration: Use `good()` for successful loads
- Warnings: `warn()` for potentially risky operations

## Comments

**When to Comment:**
- Complex algorithms: Document the "why" not the "what"
- Non-obvious logic: Explain edge cases or workarounds
- Business logic: Why certain decisions were made (e.g., "LAPS requires LDAP fallback because...")
- Data structure assumptions: "username -> pwdLastSet datetime"

**Docstrings:**
- Module docstrings describe file purpose (2-3 lines at top)
- Class docstrings explain role and usage
- Function docstrings include:
  - One-line summary
  - Longer description (if complex)
  - Args section with types
  - Returns section with type
  - Raises section for exceptions

**Example from codebase:**
```python
def classify_task(
    row: "TaskRow",
    meta: Dict[str, Any],
    runas: str,
    rel_path: str,
    ...
) -> ClassificationResult:
    """
    Classify a task as TIER-0, PRIV, or TASK based on the runas account.

    This is the single source of truth for task classification logic,
    used by both online and offline processing modes.

    Args:
        row: TaskRow instance (modified in place with type/reason/password_analysis)
        meta: Parsed task XML metadata
        ...

    Returns:
        ClassificationResult with task_type, reason, password_analysis, should_include
    """
```

## Function Design

**Size:** Functions are typically 30-100 lines; larger functions broken into helpers
- Complex logic extracted to `_helper_function_name()`
- Single responsibility principle: One function does one thing well
- Private helpers prefixed with underscore for internal-only functions

**Parameters:**
- Maximum ~8-10 parameters; excess parameters bundled into dataclass/config objects
- Example: `auth` parameter groups authentication details instead of `username, password, domain, hashes, kerberos, ...`
- Required parameters first, optional with defaults after
- Type hints on all parameters

**Return Values:**
- Simple returns: Direct value (e.g., `bool`, `str`, `Dict`)
- Multiple related values: Return dataclass or tuple with type hints
- Optional results: Use `Optional[T]` for "not found" cases
- Status + data: Tuple patterns like `(success: bool, data: Optional[Dict])`
- Example: `def parse_mslaps_password(...) -> tuple[str, str, bool]:`

## Module Design

**Exports:**
- Public functions/classes listed in docstring or `__all__`
- Private functions/classes prefixed with underscore
- Clear distinction between public API and internal helpers

**Organization:**
- Constants at module top (after imports)
- Dataclasses/Enums before functions
- Helper functions (_prefix) after main functions
- Configuration/setup code at bottom or in separate config module

**Example structure (`taskhound/laps/__init__.py`):**
```python
# Exceptions (re-exported from .exceptions)
# Classes (LAPSCache, LAPSCredential, etc.)
# Main functions (get_laps_passwords, print_laps_summary)
# Utilities (get_laps_credential_for_host)
# __all__ declaration
```

## Special Patterns

**Dataclass Usage:**
- Used extensively for structured data: `TaskRow`, `AuthContext`, `ClassificationResult`
- Advantages: Type hints, IDE autocomplete, easy dict conversion with `asdict()`
- Mutable by default; marked with `frozen=True` only when immutability needed
- Field defaults via `field(default=...)` and `field(default_factory=...)`

**Optional/Union Handling:**
- Function parameter: `password: Optional[str] = None`
- Check before use: `if password is not None:`
- Explicit False checks: `if enabled is False:` (not `is not True`) to distinguish from None

**Caching Pattern:**
- Session cache: In-memory dict per run
- Persistent cache: SQLite via CacheManager
- Lazy loading: Query only if not in cache
- Example: `_sid_lookup_cache` populated during scan, reused by classification

---

*Conventions analysis: 2026-02-06*
