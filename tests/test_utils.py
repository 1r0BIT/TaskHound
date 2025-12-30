"""
Test utility functions in taskhound.utils.
"""

from unittest.mock import MagicMock

from taskhound.utils.helpers import normalize_targets, sanitize_json_string
from taskhound.resolver import extract_domain_sid_from_hv, looks_like_domain_user


class TestHelpers:
    def test_sanitize_json_string_basic(self):
        """Test basic string sanitization."""
        assert sanitize_json_string("normal string") == "normal string"
        assert sanitize_json_string("") == ""

    def test_sanitize_json_string_escapes(self):
        """Test escaping of backslashes."""
        # Single backslash should be escaped
        assert sanitize_json_string(r"DOMAIN\User") == r"DOMAIN\\User"

        # Already escaped backslash should be preserved
        assert sanitize_json_string(r"DOMAIN\\User") == r"DOMAIN\\User"

        # Mixed content
        assert sanitize_json_string(r"CN=Name\, First,OU=Groups") == r"CN=Name\\, First,OU=Groups"

    def test_sanitize_json_string_special_chars(self):
        """Test preservation of special JSON characters."""
        # Newlines, tabs, quotes should be preserved if already escaped
        input_str = r'Line1\nLine2\t"Quote"'
        assert sanitize_json_string(input_str) == input_str

    def test_normalize_targets(self):
        """Test target normalization."""
        targets = ["192.168.1.1", "host1", "host2.corp.local", "  ", "10.0.0.1  "]
        domain = "corp.local"

        normalized = normalize_targets(targets, domain)

        assert "192.168.1.1" in normalized
        assert "host1.corp.local" in normalized
        assert "host2.corp.local" in normalized
        assert "10.0.0.1" in normalized
        assert len(normalized) == 4


class TestSidResolver:
    def test_looks_like_domain_user_sids(self):
        """Test SID detection."""
        # Domain SID
        assert looks_like_domain_user("S-1-5-21-123456789-123456789-123456789-1001") is True

        # Local/Well-known SIDs
        assert looks_like_domain_user("S-1-5-18") is False  # SYSTEM
        assert looks_like_domain_user("S-1-5-19") is False  # Local Service
        assert looks_like_domain_user("S-1-5-20") is False  # Network Service

    def test_looks_like_domain_user_names(self):
        """Test username detection."""
        # Domain formats
        assert looks_like_domain_user("DOMAIN\\User") is True
        assert looks_like_domain_user("user@domain.com") is True

        # Local formats
        assert looks_like_domain_user("User") is False
        assert looks_like_domain_user(".\\User") is False
        assert looks_like_domain_user("LOCALHOST\\User") is False

        # Well-known local accounts
        assert looks_like_domain_user("NT AUTHORITY\\SYSTEM") is False
        assert looks_like_domain_user("NT AUTHORITY\\NETWORK SERVICE") is False
        assert (
            looks_like_domain_user("BUILTIN\\Administrators") is True
        )  # Technically domain-like syntax but local group

    def test_extract_domain_sid_from_hv(self):
        """Test extracting domain SID from HighValueLoader."""
        mock_loader = MagicMock()
        mock_loader.loaded = True

        # Case 1: Found in hv_sids
        mock_loader.hv_sids = {"S-1-5-21-111-222-333-1001": {"name": "User1"}}
        assert extract_domain_sid_from_hv(mock_loader) == "S-1-5-21-111-222-333-500"

        # Case 2: Found in hv_users
        mock_loader.hv_sids = {}
        mock_loader.hv_users = {"user2": {"objectid": "S-1-5-21-444-555-666-1002"}}
        assert extract_domain_sid_from_hv(mock_loader) == "S-1-5-21-444-555-666-500"

        # Case 3: Not found
        mock_loader.hv_users = {}
        assert extract_domain_sid_from_hv(mock_loader) is None
