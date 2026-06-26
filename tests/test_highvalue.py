"""Tests for taskhound/parsers/highvalue.py - HighValueLoader and related functions."""

import json
import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from taskhound.parsers.highvalue import (
    TIER0_SIDS,
    HighValueLoader,
    _analyze_password_freshness,
)


class TestAnalyzePasswordFreshness:
    """Tests for _analyze_password_freshness function."""

    def test_missing_task_date(self):
        """Returns UNKNOWN when task_date is None."""
        pwd_change_date = datetime.now(timezone.utc)
        status, explanation = _analyze_password_freshness(None, pwd_change_date)
        assert status == "UNKNOWN"
        assert "Insufficient" in explanation

    def test_missing_password_date(self):
        """Returns UNKNOWN when pwd_change_date is None."""
        status, explanation = _analyze_password_freshness("2025-01-15T10:00:00", None)
        assert status == "UNKNOWN"
        assert "Insufficient" in explanation

    def test_both_dates_missing(self):
        """Returns UNKNOWN when both dates are missing."""
        status, explanation = _analyze_password_freshness(None, None)
        assert status == "UNKNOWN"

    def test_password_changed_before_task(self):
        """Returns GOOD when password was changed before task creation."""
        pwd_change_date = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        task_date = "2025-06-15T10:00:00"  # After password change
        status, explanation = _analyze_password_freshness(task_date, pwd_change_date)
        assert status == "GOOD"
        assert "BEFORE" in explanation

    def test_password_changed_after_task(self):
        """Returns BAD when password was changed after task creation."""
        pwd_change_date = datetime(2025, 12, 1, 12, 0, 0, tzinfo=timezone.utc)
        task_date = "2025-01-15T10:00:00"  # Before password change
        status, explanation = _analyze_password_freshness(task_date, pwd_change_date)
        assert status == "BAD"
        assert "AFTER" in explanation

    def test_invalid_task_date_format(self):
        """Returns UNKNOWN when task_date format is invalid."""
        pwd_change_date = datetime.now(timezone.utc)
        status, explanation = _analyze_password_freshness("not-a-date", pwd_change_date)
        assert status == "UNKNOWN"

    def test_task_date_with_microseconds(self):
        """Handles task dates with microseconds."""
        pwd_change_date = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        task_date = "2025-06-15T10:00:00.1234567"
        status, _ = _analyze_password_freshness(task_date, pwd_change_date)
        assert status == "GOOD"


class TestHighValueLoaderInit:
    """Tests for HighValueLoader initialization."""

    def test_init_sets_path(self):
        """Constructor sets path attribute."""
        loader = HighValueLoader("/path/to/file.json")
        assert loader.path == "/path/to/file.json"

    def test_init_empty_users(self):
        """Constructor initializes empty hv_users dict."""
        loader = HighValueLoader("/path/to/file.json")
        assert loader.hv_users == {}

    def test_init_empty_sids(self):
        """Constructor initializes empty hv_sids dict."""
        loader = HighValueLoader("/path/to/file.json")
        assert loader.hv_sids == {}

    def test_init_not_loaded(self):
        """Constructor sets loaded to False."""
        loader = HighValueLoader("/path/to/file.json")
        assert loader.loaded is False

    def test_init_unknown_format(self):
        """Constructor sets format_type to unknown."""
        loader = HighValueLoader("/path/to/file.json")
        assert loader.format_type == "unknown"


class TestHasFields:
    """Tests for HighValueLoader._has_fields static method."""

    def test_empty_headers(self):
        """Returns False for empty headers."""
        assert HighValueLoader._has_fields([]) is False
        assert HighValueLoader._has_fields(None) is False

    def test_traditional_format_with_sid(self):
        """Returns True for SamAccountName + sid."""
        headers = ["SamAccountName", "sid", "other"]
        assert HighValueLoader._has_fields(headers) is True

    def test_traditional_format_with_objectid(self):
        """Returns True for SamAccountName + objectid."""
        headers = ["SamAccountName", "objectid", "extra"]
        assert HighValueLoader._has_fields(headers) is True

    def test_lazy_query_format(self):
        """Returns True for SamAccountName + all_props."""
        headers = ["SamAccountName", "all_props", "groups"]
        assert HighValueLoader._has_fields(headers) is True

    def test_case_insensitive(self):
        """Header matching is case insensitive."""
        headers = ["SAMACCOUNTNAME", "SID"]
        assert HighValueLoader._has_fields(headers) is True

    def test_whitespace_handling(self):
        """Headers with whitespace are handled."""
        headers = ["  SamAccountName  ", "  sid  "]
        assert HighValueLoader._has_fields(headers) is True

    def test_missing_required_field(self):
        """Returns False when required fields are missing."""
        headers = ["groups", "pwdlastset"]
        assert HighValueLoader._has_fields(headers) is False


class TestParseListField:
    """Tests for HighValueLoader._parse_list_field method."""

    def test_none_returns_empty_list(self):
        """Returns empty list for None input."""
        loader = HighValueLoader("/test.json")
        assert loader._parse_list_field(None) == []

    def test_empty_string_returns_empty_list(self):
        """Returns empty list for empty string."""
        loader = HighValueLoader("/test.json")
        assert loader._parse_list_field("") == []

    def test_list_input(self):
        """Handles list input directly."""
        loader = HighValueLoader("/test.json")
        result = loader._parse_list_field(["group1", "group2"])
        assert result == ["group1", "group2"]

    def test_json_array_string(self):
        """Parses JSON array string."""
        loader = HighValueLoader("/test.json")
        result = loader._parse_list_field('["Domain Admins", "Enterprise Admins"]')
        assert result == ["Domain Admins", "Enterprise Admins"]

    def test_quoted_json_array(self):
        """Handles quoted JSON array string."""
        loader = HighValueLoader("/test.json")
        result = loader._parse_list_field('"["Domain Admins"]"')
        assert result == ["Domain Admins"]

    def test_simple_string(self):
        """Treats simple string as single item."""
        loader = HighValueLoader("/test.json")
        result = loader._parse_list_field("Domain Admins")
        assert result == ["Domain Admins"]

    def test_list_with_none_items(self):
        """Filters out None items from list."""
        loader = HighValueLoader("/test.json")
        result = loader._parse_list_field(["group1", None, "group2"])
        assert result == ["group1", "group2"]

    def test_invalid_json_fallback(self):
        """Falls back to stripped string for invalid JSON."""
        loader = HighValueLoader("/test.json")
        result = loader._parse_list_field("[not valid json")
        # The method strips only closing bracket, so leading [ remains
        assert result == ["[not valid json"]


class TestLoadUnsupportedFormat:
    """Tests for HighValueLoader.load with unsupported formats."""

    def test_unsupported_extension(self):
        """Returns False for unsupported file extensions."""
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            f.write(b"<root></root>")
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.warn"):
                result = loader.load()
            assert result is False
            assert loader.loaded is False
        finally:
            os.unlink(temp_path)

    def test_nonexistent_file(self):
        """Returns False for nonexistent files."""
        loader = HighValueLoader("/nonexistent/file.json")
        with patch("taskhound.parsers.highvalue.warn"):
            result = loader.load()
        assert result is False


class TestLoadCSV:
    """Tests for HighValueLoader loading CSV files."""

    def test_load_basic_csv(self):
        """Loads basic CSV with SamAccountName and sid."""
        csv_content = "SamAccountName,sid\nadmin,S-1-5-21-1234-5678-9012-500\n"
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, encoding="utf-8") as f:
            f.write(csv_content)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.warn"):
                result = loader.load()
            assert result is True
            assert "admin" in loader.hv_users
            assert "S-1-5-21-1234-5678-9012-500" in loader.hv_sids
        finally:
            os.unlink(temp_path)

    def test_load_csv_with_objectid(self):
        """Loads CSV using objectid instead of sid."""
        csv_content = "SamAccountName,objectid\ntest_user,S-1-5-21-111-222-333-1001\n"
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, encoding="utf-8") as f:
            f.write(csv_content)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.warn"):
                result = loader.load()
            assert result is True
            assert "test_user" in loader.hv_users
        finally:
            os.unlink(temp_path)

    def test_load_csv_domain_prefix(self):
        """Handles DOMAIN\\user format in SamAccountName."""
        csv_content = "SamAccountName,sid\nDOMAIN\\admin,S-1-5-21-1234-5678-9012-500\n"
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, encoding="utf-8") as f:
            f.write(csv_content)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.warn"):
                result = loader.load()
            assert result is True
            assert "admin" in loader.hv_users  # Domain prefix stripped
        finally:
            os.unlink(temp_path)

    def test_load_csv_with_groups(self):
        """Loads CSV with group information."""
        csv_content = 'SamAccountName,sid,groups\nadmin,S-1-5-21-1234-5678-9012-500,"S-1-5-21-1234-5678-9012-512"\n'
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, encoding="utf-8") as f:
            f.write(csv_content)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.warn"):
                result = loader.load()
            assert result is True
            user_data = loader.hv_users.get("admin", {})
            assert "S-1-5-21-1234-5678-9012-512" in user_data.get("groups", [])
        finally:
            os.unlink(temp_path)

    def test_load_csv_invalid_schema(self):
        """Returns False for CSV without required fields."""
        csv_content = "username,password\nadmin,secret\n"
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False, encoding="utf-8") as f:
            f.write(csv_content)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.warn"):
                result = loader.load()
            assert result is False
        finally:
            os.unlink(temp_path)

    def test_load_csv_utf8_bom(self):
        """Handles UTF-8 BOM in CSV files."""
        csv_content = "SamAccountName,sid\nadmin,S-1-5-21-1234-5678-9012-500\n"
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="wb", delete=False) as f:
            f.write(b"\xef\xbb\xbf")  # UTF-8 BOM
            f.write(csv_content.encode("utf-8"))
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.warn"):
                result = loader.load()
            assert result is True
            assert "admin" in loader.hv_users
        finally:
            os.unlink(temp_path)


class TestLoadJSON:
    """Tests for HighValueLoader loading JSON files."""

    def test_load_legacy_json(self):
        """Loads legacy BloodHound JSON format."""
        data = [
            {"SamAccountName": "admin", "sid": "S-1-5-21-1234-5678-9012-500"},
            {"SamAccountName": "svc_account", "sid": "S-1-5-21-1234-5678-9012-1001"},
        ]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.good"):
                result = loader.load()
            assert result is True
            assert loader.format_type == "legacy"
            assert "admin" in loader.hv_users
            assert "svc_account" in loader.hv_users
        finally:
            os.unlink(temp_path)

    def test_load_json_with_objectid(self):
        """Loads JSON using objectid instead of sid."""
        data = [{"SamAccountName": "test", "objectid": "S-1-5-21-111-222-333-1001"}]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.good"):
                result = loader.load()
            assert result is True
            assert "test" in loader.hv_users
        finally:
            os.unlink(temp_path)

    def test_load_empty_json(self):
        """Returns False for empty JSON array."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump([], f)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            result = loader.load()
            assert result is False
        finally:
            os.unlink(temp_path)

    def test_load_json_invalid_schema(self):
        """Returns False for JSON with invalid schema."""
        data = [{"username": "admin", "password": "secret"}]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.warn"):
                result = loader.load()
            assert result is False
        finally:
            os.unlink(temp_path)


class TestLoadBHCE:
    """Tests for HighValueLoader loading BHCE format."""

    def test_load_bhce_format(self):
        """Loads BloodHound Community Edition format."""
        data = {
            "nodes": {
                "node1": {
                    "kind": "User",
                    "objectId": "S-1-5-21-1234-5678-9012-500",
                    "label": "ADMIN@DOMAIN.LOCAL",
                    "isTierZero": True,
                    "properties": {
                        "samaccountname": "admin",
                        "pwdlastset": 1704067200.0,
                    },
                }
            },
            "edges": [],
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.good"):
                result = loader.load()
            assert result is True
            assert loader.format_type == "bhce"
            assert "admin" in loader.hv_users
        finally:
            os.unlink(temp_path)

    def test_bhce_extracts_sam_from_label(self):
        """Extracts SAM from BHCE label format USER@DOMAIN."""
        data = {
            "nodes": {
                "node1": {
                    "kind": "User",
                    "objectId": "S-1-5-21-1234-5678-9012-1001",
                    "label": "SVCACCOUNT@CORP.LOCAL",
                    "isTierZero": False,
                    "properties": {},
                }
            },
            "edges": [],
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.good"):
                loader.load()
            assert "svcaccount" in loader.hv_users
        finally:
            os.unlink(temp_path)

    def test_bhce_skips_non_users(self):
        """Skips non-User nodes in BHCE format."""
        data = {
            "nodes": {
                "node1": {
                    "kind": "Group",
                    "objectId": "S-1-5-21-1234-5678-9012-512",
                    "label": "DOMAIN ADMINS@DOMAIN.LOCAL",
                    "isTierZero": True,
                    "properties": {},
                },
                "node2": {
                    "kind": "User",
                    "objectId": "S-1-5-21-1234-5678-9012-500",
                    "label": "ADMIN@DOMAIN.LOCAL",
                    "isTierZero": True,
                    "properties": {},
                },
            },
            "edges": [],
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.good"):
                loader.load()
            # Should only have the user, not the group
            assert len(loader.hv_users) == 1
            assert "admin" in loader.hv_users
        finally:
            os.unlink(temp_path)

    def test_bhce_processes_membership_edges(self):
        """Processes MemberOf edges to build group membership."""
        data = {
            "nodes": {
                "user1": {
                    "kind": "User",
                    "objectId": "S-1-5-21-1234-5678-9012-1001",
                    "label": "TESTUSER@DOMAIN.LOCAL",
                    "isTierZero": False,
                    "properties": {},
                },
                "group1": {
                    "kind": "Group",
                    "objectId": "S-1-5-21-1234-5678-9012-512",
                    "label": "DOMAIN ADMINS@DOMAIN.LOCAL",
                    "isTierZero": True,
                    "properties": {
                        "objectid": "S-1-5-21-1234-5678-9012-512",
                        "name": "Domain Admins",
                    },
                },
            },
            "edges": [
                {"kind": "MemberOf", "source": "user1", "target": "group1"},
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            loader = HighValueLoader(temp_path)
            with patch("taskhound.parsers.highvalue.good"):
                loader.load()
            user_data = loader.hv_users.get("testuser", {})
            assert "S-1-5-21-1234-5678-9012-512" in user_data.get("groups", [])
        finally:
            os.unlink(temp_path)


class TestCheckHighvalue:
    """Tests for HighValueLoader.check_highvalue method."""

    @pytest.fixture
    def loaded_loader(self):
        """Create a loader with pre-loaded user data."""
        loader = HighValueLoader("/test.json")
        loader.hv_users = {
            "admin": {"sid": "S-1-5-21-1234-5678-9012-500"},
            "svc_backup": {"sid": "S-1-5-21-1234-5678-9012-1001"},
        }
        loader.hv_sids = {
            "S-1-5-21-1234-5678-9012-500": {"sam": "admin"},
            "S-1-5-21-1234-5678-9012-1001": {"sam": "svc_backup"},
        }
        loader.loaded = True
        return loader

    def test_empty_runas(self, loaded_loader):
        """Returns False for empty runas."""
        assert loaded_loader.check_highvalue("") is False
        assert loaded_loader.check_highvalue(None) is False

    def test_bare_name_not_matched(self, loaded_loader):
        """Bare names (no domain prefix) never match domain data.

        Per LookupAccountName() resolution order, bare names resolve to local
        accounts before domain accounts. We require an explicit qualifier.
        """
        assert loaded_loader.check_highvalue("admin") is False
        assert loaded_loader.check_highvalue("svc_backup") is False

    def test_bare_administrator_not_matched(self, loaded_loader):
        """Bare 'Administrator' must not match even if domain Administrator is in BH data."""
        loaded_loader.hv_users["administrator"] = {"sid": "S-1-5-21-1234-5678-9012-500"}
        assert loaded_loader.check_highvalue("Administrator") is False
        assert loaded_loader.check_highvalue("administrator") is False

    def test_match_by_domain_sam(self, loaded_loader):
        """Matches user by DOMAIN\\sam format (explicit qualifier required)."""
        assert loaded_loader.check_highvalue("DOMAIN\\admin") is True
        assert loaded_loader.check_highvalue("CORP\\svc_backup") is True

    def test_match_by_sid(self, loaded_loader):
        """Matches user by SID."""
        assert loaded_loader.check_highvalue("S-1-5-21-1234-5678-9012-500") is True
        assert loaded_loader.check_highvalue("S-1-5-21-1234-5678-9012-1001") is True

    def test_sid_case_insensitive(self, loaded_loader):
        """SID matching is case insensitive."""
        assert loaded_loader.check_highvalue("s-1-5-21-1234-5678-9012-500") is True

    def test_no_match(self, loaded_loader):
        """Returns False for unknown users."""
        assert loaded_loader.check_highvalue("unknown_user") is False
        assert loaded_loader.check_highvalue("S-1-5-21-999-999-999-999") is False

    def test_check_highvalue_bare_matches(self, loaded_loader):
        """check_highvalue_bare() matches a bare sAMAccountName directly (guard bypassed)."""
        assert loaded_loader.check_highvalue_bare("admin") is True
        assert loaded_loader.check_highvalue_bare("ADMIN") is True  # case-insensitive
        assert loaded_loader.check_highvalue_bare("unknown_user") is False

    def test_check_highvalue_bare_empty(self, loaded_loader):
        """check_highvalue_bare() returns False for empty input."""
        assert loaded_loader.check_highvalue_bare("") is False
        assert loaded_loader.check_highvalue_bare(None) is False


class TestCheckTier0:
    """Tests for HighValueLoader.check_tier0 method."""

    @pytest.fixture
    def loaded_loader(self):
        """Create a loader with Tier 0 user data."""
        loader = HighValueLoader("/test.json")
        loader.format_type = "legacy"

        # Domain admin with Tier 0 group membership
        loader.hv_users = {
            "domain_admin": {
                "sid": "S-1-5-21-1234-5678-9012-500",
                "groups": ["S-1-5-21-1234-5678-9012-512"],  # Domain Admins
                "group_names": ["Domain Admins"],
            },
            "admin_sd_holder": {
                "sid": "S-1-5-21-1234-5678-9012-1001",
                "groups": [],
                "group_names": [],
                "admincount": "1",
            },
            "regular_user": {
                "sid": "S-1-5-21-1234-5678-9012-1002",
                "groups": [],
                "group_names": [],
            },
            "enterprise_admin": {
                "sid": "S-1-5-21-1234-5678-9012-1003",
                "groups": ["S-1-5-21-1234-5678-9012-519"],  # Enterprise Admins
                "group_names": ["Enterprise Admins"],
            },
        }

        loader.hv_sids = {
            "S-1-5-21-1234-5678-9012-500": dict(loader.hv_users["domain_admin"], sam="domain_admin"),
            "S-1-5-21-1234-5678-9012-1001": dict(loader.hv_users["admin_sd_holder"], sam="admin_sd_holder"),
            "S-1-5-21-1234-5678-9012-1002": dict(loader.hv_users["regular_user"], sam="regular_user"),
            "S-1-5-21-1234-5678-9012-1003": dict(loader.hv_users["enterprise_admin"], sam="enterprise_admin"),
        }
        loader.loaded = True
        return loader

    def test_empty_runas(self, loaded_loader):
        """Returns (False, []) for empty runas."""
        is_tier0, reasons = loaded_loader.check_tier0("")
        assert is_tier0 is False
        assert reasons == []

    def test_domain_admin_membership(self, loaded_loader):
        """Detects Tier 0 via Domain Admins membership (requires DOMAIN\\sam qualifier)."""
        is_tier0, reasons = loaded_loader.check_tier0("DOMAIN\\domain_admin")
        assert is_tier0 is True
        assert "TIER0 Group Membership" in reasons

    def test_enterprise_admin_membership(self, loaded_loader):
        """Detects Tier 0 via Enterprise Admins membership (requires DOMAIN\\sam qualifier)."""
        is_tier0, reasons = loaded_loader.check_tier0("DOMAIN\\enterprise_admin")
        assert is_tier0 is True
        assert "TIER0 Group Membership" in reasons

    def test_bare_name_not_tier0(self, loaded_loader):
        """Bare names (no domain qualifier) never classified as Tier 0.

        Per LookupAccountName() order, bare names resolve to LOCAL accounts before
        domain accounts. Require an explicit DOMAIN\\user or user@domain qualifier.
        """
        is_tier0, reasons = loaded_loader.check_tier0("domain_admin")
        assert is_tier0 is False
        assert reasons == []

    def test_check_tier0_bare_matches(self, loaded_loader):
        """check_tier0_bare() matches a bare sAMAccountName directly (guard bypassed).

        Used by the opt-in --match-bare-runas fallback after the caller has filtered out
        known local accounts. Mirrors check_tier0() scoring via the shared helper.
        """
        is_tier0, reasons = loaded_loader.check_tier0_bare("domain_admin")
        assert is_tier0 is True
        assert "TIER0 Group Membership" in reasons

    def test_check_tier0_bare_no_match(self, loaded_loader):
        """check_tier0_bare() returns (False, []) for a non-privileged or unknown account."""
        assert loaded_loader.check_tier0_bare("regular_user") == (False, [])
        assert loaded_loader.check_tier0_bare("nonexistent") == (False, [])
        assert loaded_loader.check_tier0_bare("") == (False, [])

    def test_bare_administrator_not_tier0(self, loaded_loader):
        """Bare 'Administrator' must not match domain Administrator in BloodHound data."""
        loaded_loader.hv_users["administrator"] = {
            "sid": "S-1-5-21-1234-5678-9012-500",
            "groups": ["S-1-5-21-1234-5678-9012-512"],
            "group_names": ["Domain Admins"],
        }
        is_tier0, reasons = loaded_loader.check_tier0("Administrator")
        assert is_tier0 is False
        assert reasons == []

    def test_domain_qualified_administrator_is_tier0(self, loaded_loader):
        """DOMAIN\\Administrator with Tier 0 group membership IS classified correctly."""
        loaded_loader.hv_users["administrator"] = {
            "sid": "S-1-5-21-1234-5678-9012-500",
            "groups": ["S-1-5-21-1234-5678-9012-512"],
            "group_names": ["Domain Admins"],
        }
        is_tier0, reasons = loaded_loader.check_tier0("DOMAIN\\Administrator")
        assert is_tier0 is True
        assert "TIER0 Group Membership" in reasons

    def test_admin_sd_holder_alone_not_tier0(self, loaded_loader):
        """AdminSDHolder alone is NOT sufficient for Tier 0 - may be historical."""
        is_tier0, reasons = loaded_loader.check_tier0("DOMAIN\\admin_sd_holder")
        assert is_tier0 is False  # AdminSDHolder alone is NOT Tier 0
        assert reasons == []

    def test_admin_sd_holder_with_group_membership(self, loaded_loader):
        """AdminSDHolder + actual Tier 0 group = Tier 0."""
        # Add a user with both AdminSDHolder and Domain Admins membership
        loaded_loader.hv_users["admin_with_groups"] = {
            "sid": "S-1-5-21-1234-5678-9012-1004",
            "groups": ["S-1-5-21-1234-5678-9012-512"],  # Domain Admins
            "group_names": ["Domain Admins"],
            "admincount": "1",  # AdminSDHolder protected
        }
        is_tier0, reasons = loaded_loader.check_tier0("DOMAIN\\admin_with_groups")
        assert is_tier0 is True
        assert "TIER0 Group Membership" in reasons
        assert "AdminSDHolder" in reasons  # Additional context

    def test_regular_user_not_tier0(self, loaded_loader):
        """Regular user is not Tier 0."""
        is_tier0, reasons = loaded_loader.check_tier0("DOMAIN\\regular_user")
        assert is_tier0 is False
        assert reasons == []

    def test_lookup_by_sid(self, loaded_loader):
        """Tier 0 detection works via SID lookup."""
        is_tier0, reasons = loaded_loader.check_tier0("S-1-5-21-1234-5678-9012-500")
        assert is_tier0 is True

    def test_unknown_user(self, loaded_loader):
        """Returns (False, []) for unknown users."""
        is_tier0, reasons = loaded_loader.check_tier0("nonexistent")
        assert is_tier0 is False
        assert reasons == []


class TestAnalyzePasswordAge:
    """Tests for HighValueLoader.analyze_password_age method."""

    @pytest.fixture
    def loaded_loader(self):
        """Create a loader with user data including password dates."""
        loader = HighValueLoader("/test.json")
        # Password changed on Jan 1, 2025
        pwd_date = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        loader.hv_users = {
            "admin": {"sid": "S-1-5-21-1234-5678-9012-500", "pwdlastset": pwd_date},
            "no_pwd_date": {"sid": "S-1-5-21-1234-5678-9012-1001", "pwdlastset": None},
        }
        loader.hv_sids = {
            "S-1-5-21-1234-5678-9012-500": dict(loader.hv_users["admin"], sam="admin"),
            "S-1-5-21-1234-5678-9012-1001": dict(loader.hv_users["no_pwd_date"], sam="no_pwd_date"),
        }
        loader.loaded = True
        return loader

    def test_missing_runas(self, loaded_loader):
        """Returns UNKNOWN for missing runas."""
        status, _ = loaded_loader.analyze_password_age("", "2025-06-15T10:00:00")
        assert status == "UNKNOWN"

    def test_missing_task_date(self, loaded_loader):
        """Returns UNKNOWN for missing task_date."""
        status, _ = loaded_loader.analyze_password_age("admin", "")
        assert status == "UNKNOWN"

    def test_user_not_found(self, loaded_loader):
        """Returns UNKNOWN for user not in BloodHound data."""
        status, explanation = loaded_loader.analyze_password_age("unknown", "2025-06-15T10:00:00")
        assert status == "UNKNOWN"
        assert "not found" in explanation

    def test_no_password_date(self, loaded_loader):
        """Returns UNKNOWN when user has no password date."""
        status, explanation = loaded_loader.analyze_password_age("no_pwd_date", "2025-06-15T10:00:00")
        assert status == "UNKNOWN"
        assert "not available" in explanation

    def test_password_valid(self, loaded_loader):
        """Returns GOOD when task created after password change."""
        # Task created June 15, 2025 (after Jan 1 password change)
        status, _ = loaded_loader.analyze_password_age("admin", "2025-06-15T10:00:00")
        assert status == "GOOD"

    def test_password_stale(self, loaded_loader):
        """Returns BAD when task created before password change."""
        # Task created Dec 1, 2024 (before Jan 1 password change)
        status, _ = loaded_loader.analyze_password_age("admin", "2024-12-01T10:00:00")
        assert status == "BAD"

    def test_lookup_by_sid(self, loaded_loader):
        """Password analysis works via SID lookup."""
        status, _ = loaded_loader.analyze_password_age("S-1-5-21-1234-5678-9012-500", "2025-06-15T10:00:00")
        assert status == "GOOD"


class TestTier0SIDsConstant:
    """Tests for TIER0_SIDS constant."""

    def test_contains_administrators(self):
        """Contains Local Administrators SID."""
        assert "S-1-5-32-544" in TIER0_SIDS

    def test_contains_domain_admins_pattern(self):
        """Contains Domain Admins pattern."""
        assert "S-1-5-21-{domain}-512" in TIER0_SIDS

    def test_contains_enterprise_admins_pattern(self):
        """Contains Enterprise Admins pattern."""
        assert "S-1-5-21-{domain}-519" in TIER0_SIDS

    def test_contains_builtin_administrator(self):
        """Contains built-in Administrator pattern."""
        assert "S-1-5-21-{domain}-500" in TIER0_SIDS

    def test_has_descriptive_names(self):
        """Each SID has a descriptive name."""
        for sid, name in TIER0_SIDS.items():
            assert name, f"SID {sid} has no descriptive name"
