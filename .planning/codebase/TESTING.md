# Testing Patterns

**Analysis Date:** 2026-02-06

## Test Framework

**Runner:**
- pytest >= 7.4.0
- Config: `pytest.ini` at project root
- Test discovery: `testpaths = tests`
- File naming: `test_*.py` (required for auto-discovery)
- Class naming: `Test*` for test classes
- Function naming: `test_*` for test functions

**Assertion Library:**
- Built-in assert statements (pytest provides rich output)
- No special assertion library dependency

**Run Commands:**
```bash
pytest                    # Run full test suite with coverage (default)
pytest -m "not slow and not live"  # Skip slow/live tests (test-fast)
pytest -v                 # Verbose mode (already default in pytest.ini with --verbose)
pytest --cov=taskhound --cov-report=term-missing  # Coverage report
pytest --cov-report=html  # HTML coverage report to htmlcov/
pytest -k "test_sid"      # Run specific tests by pattern
```

## Test File Organization

**Location:**
- Co-located with source: Test files in `tests/` directory (not alongside source)
- Test data: `tests/data/` subdirectory for fixtures and test data
- Shared fixtures: `tests/conftest.py` for pytest fixtures

**Naming:**
- Test file: `test_<module_name>.py` (e.g., `test_sid_resolver.py` for `taskhound/resolver.py`)
- Test class: `Test<FunctionName>` or `Test<ClassName>` (e.g., `TestIsSid`, `TestCacheManagerInit`)
- Test method: `test_<what_is_being_tested>` (e.g., `test_valid_domain_sid`, `test_session_hit_increments_stats`)

**Structure:**
```
tests/
├── conftest.py                 # Pytest fixtures and shared setup
├── data/                       # Test data files (XML, JSON, etc.)
│   ├── live_test_config.json.example
│   └── ...
├── test_bh_auth.py            # BloodHound auth tests
├── test_cache_manager.py       # Cache manager tests
├── test_engine_async.py        # Async engine tests
├── test_sid_resolver.py        # SID resolver tests
├── test_tier0_detection.py     # Tier-0 detection tests
└── ... (65+ test files total)
```

## Test Structure

**Suite Organization:**
```python
"""
Tests for SID resolver utilities.
"""
import pytest
from taskhound.resolver import is_sid, sid_to_binary


class TestIsSid:
    """Tests for is_sid function"""

    def test_valid_domain_sid(self):
        """Should recognize valid domain SID"""
        sid = "S-1-5-21-123456789-123456789-123456789-1001"
        assert is_sid(sid) is True

    def test_empty_string_returns_false(self):
        """Should return False for empty string"""
        assert is_sid("") is False
```

**Patterns:**
- Module docstring at top (3-5 lines, describes what module tests)
- One test class per function/class being tested
- Class docstring explains what's being tested
- Each test method: One assertion or logical group
- Test name describes expected behavior, not implementation
- Docstring explains why test matters (not how it works)

## Mocking

**Framework:** pytest-mock (pytest plugin wrapping unittest.mock)

**Usage Pattern:**
```python
from unittest.mock import MagicMock

class TestBloodHoundFeature:
    def test_resolves_sid_from_bloodhound(self):
        """Should resolve SID using BloodHound data"""
        mock_loader = MagicMock()
        mock_loader.loaded = True
        mock_loader.hv_sids = {"S-1-5-21-123-123-123-500": {"sam": "Administrator"}}

        result = resolve_sid_from_bloodhound("S-1-5-21-123-123-123-500", mock_loader)

        assert result == "Administrator"
```

**Patterns:**
- Import: `from unittest.mock import MagicMock, patch, Mock`
- Create mocks for external dependencies: BloodHound connectors, LDAP connections
- Set up mock attributes before calling function under test
- Verify mock was called if needed: `mock_loader.is_account_enabled.assert_called_once_with("user")`

**What to Mock:**
- Network calls (LDAP, BloodHound API, DNS)
- File I/O operations
- System operations (subprocess, registry access)
- External library functions (impacket, requests)

**What NOT to Mock:**
- Functions being tested directly (test actual behavior)
- Pure utility functions (no side effects)
- Data structures/models (unless testing with specific data)
- Internal helper functions (test via public interface)

## Fixtures and Factories

**Test Data:**
```python
@pytest.fixture
def test_data_dir():
    """Return path to test data directory."""
    return Path(__file__).parent / "data"

@pytest.fixture
def cleanup_cache():
    """
    Automatically clean up the global cache after each test.
    This prevents ResourceWarning: unclosed database errors.
    """
    yield  # Let the test run

    from taskhound.utils.cache_manager import get_cache
    cache = get_cache()
    if cache:
        cache.close()
```

**Location:**
- `tests/conftest.py`: Shared fixtures used across multiple test files
- `tests/test_<module>.py`: Module-specific fixtures at top of file after imports
- `tests/data/`: Static test data files (XML, JSON, CSV)

**Scope:**
- `function` (default): Fresh fixture per test
- `module`: Shared across all tests in one file
- `session`: Shared across entire test suite (use sparingly)
- Example: `@pytest.fixture(scope="module") def live_config():`

## Coverage

**Requirements:** Minimum 50% code coverage enforced
- Config in pytest.ini: `--cov-fail-under=50`
- Coverage calculated via pytest-cov

**View Coverage:**
```bash
pytest --cov=taskhound --cov-report=term-missing
# Shows missing lines in terminal

pytest --cov=taskhound --cov-report=html
# Generates htmlcov/index.html for visual inspection
```

**Exclusion Rules:**
- Lines excluded in pytest.ini coverage report:
  - `pragma: no cover` comments
  - `def __repr__`
  - `raise AssertionError`
  - `raise NotImplementedError`
  - `if __name__ == "__main__":`
  - `if TYPE_CHECKING:` blocks

**Coverage Gaps:**
- Live tests (network-dependent) marked with `@pytest.mark.live` - skipped by default
- Integration tests marked with `@pytest.mark.integration`
- Slow tests marked with `@pytest.mark.slow`
- Fast test run: `pytest -m "not slow and not live"` excludes marked tests

## Test Types

**Unit Tests:**
- Scope: Single function or method in isolation
- Mocking: All external dependencies mocked
- Speed: Should complete in <1s per test
- Examples: `test_is_sid_format()`, `test_cache_set_and_get()`, `test_sanitize_json_string()`
- Located in: `tests/test_utils.py`, `tests/test_sid_resolver.py`

**Integration Tests:**
- Scope: Multiple components working together
- Mocking: External network services mocked, internal components real
- Speed: 1-5 seconds per test
- Marked with: `@pytest.mark.integration`
- Examples: Test LDAP query with cache, classification with BloodHound data
- Located in: `tests/test_engine_*.py`, `tests/test_ldap_utils.py`

**E2E/Live Tests:**
- Scope: Full end-to-end with real systems
- Mocking: Minimal; prefer real network calls
- Speed: 10+ seconds (slow)
- Marked with: `@pytest.mark.live`
- Configuration: Requires `tests/live_test_config.json` (based on example)
- Skipped by default if config missing
- Examples: Real LDAP connection, real BloodHound API queries
- Located in: `tests/test_engine_online.py`

## Common Patterns

**Async Testing:**
```python
# Not used in current codebase (pytest-asyncio not configured)
# Async code tested via sync test runners
# Example pattern if needed:
# @pytest.mark.asyncio
# async def test_async_function():
#     result = await async_function()
#     assert result == expected
```

**Error Testing:**
```python
def test_sid_to_binary_returns_none_for_invalid_sid(self):
    """Should return None for invalid SID"""
    assert sid_to_binary("invalid") is None
    assert sid_to_binary("") is None
    assert sid_to_binary("S-1") is None

def test_raises_exception_on_bad_input(self):
    """Should raise ValueError for malformed input"""
    with pytest.raises(ValueError):
        dangerous_function("bad data")
```

**Parametrized Tests:**
```python
# Pattern: Test same function with multiple inputs
@pytest.mark.parametrize("input_val,expected", [
    ("S-1-5-18", True),       # SYSTEM
    ("S-1-5-19", True),       # Local Service
    ("invalid", False),
])
def test_is_sid_various_inputs(input_val, expected):
    """Test is_sid with various valid/invalid inputs"""
    assert is_sid(input_val) is expected
```

**Fixture Usage in Tests:**
```python
def test_uses_cache_fixture(self, test_data_dir):
    """Test using injected fixture"""
    config_file = test_data_dir / "test_config.json"
    assert config_file.exists()
```

## Test Markers

**Defined in pytest.ini:**
```python
markers =
    unit: Unit tests (fast, no I/O)
    integration: Integration tests (may use network/files)
    slow: Slow tests (skip with -m "not slow")
    live: Tests requiring live external systems (skip with -m "not live")
```

**Usage:**
```python
@pytest.mark.slow
def test_large_dataset_processing():
    """This test takes >5 seconds"""
    ...

@pytest.mark.live
@pytest.mark.integration
def test_real_bloodhound_connection(live_config):
    """Requires real BloodHound instance"""
    ...

@pytest.mark.unit
def test_utility_function():
    """Fast unit test"""
    ...
```

**Running with Markers:**
```bash
pytest -m "unit"                    # Only unit tests
pytest -m "not slow"                # Skip slow tests
pytest -m "live and integration"    # Only live integration tests
pytest -m "not live and not slow"   # Default fast suite
```

## Conftest and Setup

**Global Fixtures in `tests/conftest.py`:**
```python
@pytest.fixture(autouse=True)
def cleanup_cache():
    """Automatically clean up global cache after each test."""
    yield  # Let test run
    from taskhound.utils.cache_manager import get_cache
    cache = get_cache()
    if cache:
        cache.close()

@pytest.fixture
def test_data_dir():
    """Return path to test data directory."""
    return Path(__file__).parent / "data"

@pytest.fixture(scope="module")
def live_config():
    """Load live test configuration from file."""
    config_file = Path(__file__).parent / "live_test_config.json"
    if not config_file.exists():
        pytest.skip("Live test config not found")
    with open(config_file) as f:
        return json.load(f)
```

**Setup/Teardown Pattern:**
- Fixture with `yield`: Code before `yield` runs setup, after runs teardown
- `autouse=True`: Automatically applied to all tests in scope
- `scope="module"`: Fixture created once per test file

## Test Class Organization

**Class-based tests (pytest convention):**
```python
class TestCacheManagerInit:
    """Tests for CacheManager initialization"""

    def test_uses_provided_cache_file(self):
        """Should use provided cache file path"""
        # Arrange
        cache_file = Path(tmpdir) / "test_cache.db"

        # Act
        cache = CacheManager(cache_file=cache_file, enabled=True)

        # Assert
        assert cache.cache_file == cache_file
        cache.close()
```

**Arrange-Act-Assert (AAA) Pattern:**
- Arrange: Set up test data
- Act: Call function being tested
- Assert: Verify result

## Test Naming Convention

**Descriptive names explain the behavior:**
- `test_valid_domain_sid` - tests valid SID format
- `test_empty_string_returns_false` - tests edge case with empty input
- `test_sets_ttl_hours` - tests parameter assignment
- `test_session_hit_increments_stats` - tests side effect

**Anti-patterns (not used):**
- `test_1`, `test_a`, `test_foo` (not descriptive)
- `test_thing_works` (too vague)

---

*Testing analysis: 2026-02-06*
