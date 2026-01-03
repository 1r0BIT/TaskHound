"""Tests for taskhound/utils/pwd_resolver.py module.

The refactored PwdLastSetResolver uses SID-based lookups and reuses
existing resolver infrastructure. Tests are updated to match.
"""

from datetime import datetime
from unittest.mock import Mock, patch

from taskhound.utils.pwd_resolver import (
    PwdLastSetResolver,
    PwdLastSetResult,
)


class TestPwdLastSetResult:
    """Tests for PwdLastSetResult dataclass."""

    def test_create_result_with_datetime(self):
        """Test creating result with datetime."""
        dt = datetime(2026, 1, 1, 12, 0, 0)
        result = PwdLastSetResult(pwd_last_set=dt, source="ldap")
        assert result.pwd_last_set == dt
        assert result.source == "ldap"
        assert result.cached is False

    def test_create_result_with_none(self):
        """Test creating result with None."""
        result = PwdLastSetResult(pwd_last_set=None, source="unknown")
        assert result.pwd_last_set is None
        assert result.source == "unknown"

    def test_create_cached_result(self):
        """Test creating cached result."""
        dt = datetime(2026, 1, 1, 12, 0, 0)
        result = PwdLastSetResult(pwd_last_set=dt, source="bloodhound", cached=True)
        assert result.cached is True

    def test_result_with_sid(self):
        """Test creating result with SID tracking."""
        dt = datetime(2026, 1, 1, 12, 0, 0)
        sid = "S-1-5-21-123-456-789-500"
        result = PwdLastSetResult(pwd_last_set=dt, source="ldap", sid=sid)
        assert result.sid == sid


class TestPwdLastSetResolverInit:
    """Tests for PwdLastSetResolver initialization."""

    def test_init_minimal(self):
        """Test minimal initialization."""
        resolver = PwdLastSetResolver()
        assert resolver.hv_loader is None
        assert resolver.bh_connector is None
        # Uses SID-based caching only
        assert resolver._sid_cache == {}
        assert resolver._query_attempted == set()
        assert resolver.stats["cache_hits"] == 0

    def test_init_with_hv_loader(self):
        """Test initialization with HighValueLoader."""
        mock_hv = Mock()
        resolver = PwdLastSetResolver(hv_loader=mock_hv)
        assert resolver.hv_loader is mock_hv

    def test_init_with_ldap_credentials(self):
        """Test initialization with LDAP credentials."""
        resolver = PwdLastSetResolver(
            domain="corp.local",
            dc_ip="192.168.1.1",
            username="admin",
            password="password123",
        )
        assert resolver.domain == "corp.local"
        assert resolver.dc_ip == "192.168.1.1"
        assert resolver.username == "admin"
        assert resolver.password == "password123"

    def test_init_with_flags(self):
        """Test initialization with behavior flags."""
        resolver = PwdLastSetResolver(no_ldap=True, opsec=True)
        assert resolver.no_ldap is True
        assert resolver.opsec is True


class TestPwdLastSetResolverResolve:
    """Tests for resolve method."""

    def test_resolve_cache_hit_by_sid(self):
        """Test resolution from session cache by SID."""
        resolver = PwdLastSetResolver()
        dt = datetime(2026, 1, 1, 12, 0, 0)
        test_sid = "S-1-5-21-123-456-789-500"

        # Pre-populate SID cache
        resolver._sid_cache[test_sid] = PwdLastSetResult(
            pwd_last_set=dt, source="ldap", sid=test_sid
        )

        # Resolve by passing SID directly
        result = resolver.resolve("admin", sid=test_sid)
        assert result.pwd_last_set == dt
        assert result.source == "ldap"
        assert result.cached is True
        assert resolver.stats["cache_hits"] == 1

    def test_resolve_with_sid_string(self):
        """Test resolution when runas is a SID string."""
        resolver = PwdLastSetResolver()
        dt = datetime(2026, 1, 1, 12, 0, 0)
        test_sid = "S-1-5-21-123-456-789-500"

        # Pre-populate SID cache
        resolver._sid_cache[test_sid] = PwdLastSetResult(
            pwd_last_set=dt, source="ldap", sid=test_sid
        )

        # Resolve by SID as runas
        with patch("taskhound.resolver.is_sid", return_value=True):
            result = resolver.resolve(test_sid)
            assert result.pwd_last_set == dt
            assert result.cached is True

    def test_resolve_bloodhound_data_by_sid(self):
        """Test resolution from BloodHound data by SID."""
        mock_hv = Mock()
        mock_hv.loaded = True
        mock_hv.hv_users = {}
        test_sid = "S-1-5-21-123-456-789-1001"
        mock_hv.hv_sids = {
            test_sid: {"pwdlastset": datetime(2026, 1, 1)}
        }

        resolver = PwdLastSetResolver(hv_loader=mock_hv)

        # Resolve directly by SID
        with patch("taskhound.resolver.is_sid", return_value=True):
            result = resolver.resolve(test_sid)

        assert result.pwd_last_set == datetime(2026, 1, 1)
        assert result.source == "bloodhound"
        assert resolver.stats["bloodhound_hits"] == 1

    def test_resolve_bloodhound_api_by_sid(self):
        """Test resolution from BloodHound API by SID."""
        mock_hv = Mock()
        mock_hv.loaded = True
        mock_hv.hv_users = {}
        mock_hv.hv_sids = {}

        mock_bh = Mock()
        mock_bh.get_user_properties.return_value = {
            "pwdlastset": 1704067200  # Unix timestamp
        }

        test_sid = "S-1-5-21-123-456-789-1001"

        with patch("taskhound.resolver.is_sid", return_value=True):
            with patch("taskhound.parsers.highvalue.parse_timestamp") as mock_parse:
                mock_parse.return_value = datetime(2024, 1, 1, 12, 0, 0)

                resolver = PwdLastSetResolver(hv_loader=mock_hv, bh_connector=mock_bh)
                result = resolver.resolve(test_sid)

                assert result.pwd_last_set == datetime(2024, 1, 1, 12, 0, 0)
                assert result.source == "bloodhound_api"
                assert resolver.stats["bloodhound_api_hits"] == 1
                mock_bh.get_user_properties.assert_called_once_with(test_sid)

    def test_resolve_not_found(self):
        """Test resolution when user not found anywhere."""
        resolver = PwdLastSetResolver(no_ldap=True, opsec=True)

        with patch("taskhound.resolver.is_sid", return_value=False):
            result = resolver.resolve("unknownuser")

        assert result.pwd_last_set is None
        assert result.source == "unknown"
        assert resolver.stats["misses"] == 1

    def test_resolve_caches_by_sid(self):
        """Test that results are cached by SID for subsequent lookups."""
        mock_hv = Mock()
        mock_hv.loaded = True
        mock_hv.hv_users = {}
        test_sid = "S-1-5-21-123-456-789-500"
        mock_hv.hv_sids = {test_sid: {"pwdlastset": datetime(2026, 1, 1)}}

        resolver = PwdLastSetResolver(hv_loader=mock_hv)

        with patch("taskhound.resolver.is_sid", return_value=True):
            # First resolve
            result1 = resolver.resolve(test_sid)
            assert result1.source == "bloodhound"

            # Second resolve should hit cache
            result2 = resolver.resolve(test_sid)
            assert result2.cached is True
            assert resolver.stats["cache_hits"] == 1
            assert resolver.stats["bloodhound_hits"] == 1  # Only incremented once


class TestPwdLastSetResolverLdap:
    """Tests for LDAP fallback resolution."""

    def test_resolve_ldap_fallback(self):
        """Test LDAP fallback when BloodHound doesn't have user."""
        mock_hv = Mock()
        mock_hv.loaded = True
        mock_hv.hv_users = {}
        mock_hv.hv_sids = {}

        resolver = PwdLastSetResolver(
            hv_loader=mock_hv,
            domain="corp.local",
            dc_ip="192.168.1.1",
            username="admin",
            password="password",
        )

        test_sid = "S-1-5-21-123-456-789-1001"

        # Patch all resolver imports to prevent network calls
        with patch("taskhound.resolver.is_sid", return_value=False):
            with patch("taskhound.resolver.resolve_name_to_sid_via_ldap", return_value=None):
                with patch("taskhound.resolver.batch_get_user_attributes") as mock_batch:
                    mock_batch.return_value = {
                        "regularuser": {
                            "pwdLastSet": datetime(2026, 1, 1),
                            "sid": test_sid,
                        }
                    }

                    result = resolver.resolve("regularuser")

                    assert result.pwd_last_set == datetime(2026, 1, 1)
                    assert result.source == "ldap"
                    assert result.sid == test_sid
                    assert resolver.stats["ldap_hits"] == 1

    def test_resolve_ldap_disabled(self):
        """Test that LDAP is skipped when no_ldap=True."""
        resolver = PwdLastSetResolver(
            domain="corp.local",
            username="admin",
            password="password",
            no_ldap=True,
        )

        with patch("taskhound.resolver.is_sid", return_value=False):
            result = resolver.resolve("someuser")

        assert result.pwd_last_set is None
        assert result.source == "unknown"

    def test_resolve_ldap_opsec_mode(self):
        """Test that LDAP is skipped in OPSEC mode."""
        resolver = PwdLastSetResolver(
            domain="corp.local",
            username="admin",
            password="password",
            opsec=True,
        )

        with patch("taskhound.resolver.is_sid", return_value=False):
            result = resolver.resolve("someuser")

        assert result.pwd_last_set is None
        assert result.source == "unknown"


class TestPwdLastSetResolverConvenience:
    """Tests for convenience methods."""

    def test_get_pwd_last_set(self):
        """Test get_pwd_last_set convenience method."""
        resolver = PwdLastSetResolver()
        dt = datetime(2026, 1, 1, 12, 0, 0)
        test_sid = "S-1-5-21-123-456-789-500"

        # Use SID-based cache
        resolver._sid_cache[test_sid] = PwdLastSetResult(
            pwd_last_set=dt, source="ldap", sid=test_sid
        )

        result = resolver.get_pwd_last_set("admin", sid=test_sid)
        assert result == dt

    def test_get_pwd_last_set_none(self):
        """Test get_pwd_last_set returns None when not found."""
        resolver = PwdLastSetResolver(no_ldap=True, opsec=True)

        with patch("taskhound.resolver.is_sid", return_value=False):
            result = resolver.get_pwd_last_set("unknownuser")

        assert result is None

    def test_get_stats_summary(self):
        """Test statistics summary generation."""
        resolver = PwdLastSetResolver()
        resolver.stats = {
            "cache_hits": 5,
            "bloodhound_hits": 3,
            "bloodhound_api_hits": 2,
            "ldap_hits": 1,
            "misses": 0,
        }

        summary = resolver.get_stats_summary()
        assert "cache: 5" in summary
        assert "bloodhound: 3" in summary
        assert "bloodhound_api: 2" in summary
        assert "ldap: 1" in summary

    def test_get_stats_summary_empty(self):
        """Test statistics summary when no lookups performed."""
        resolver = PwdLastSetResolver()
        summary = resolver.get_stats_summary()
        assert "No pwdLastSet lookups" in summary


class TestPwdLastSetResolverPrefetch:
    """Tests for batch prefetch functionality."""

    def test_prefetch_from_tasks_uses_bloodhound_data(self):
        """Test prefetching uses existing BloodHound data."""
        mock_hv = Mock()
        mock_hv.loaded = True
        mock_hv.hv_users = {
            "admin": {
                "pwdlastset": datetime(2026, 1, 1),
                "sid": "S-1-5-21-123-456-789-500",
            }
        }

        resolver = PwdLastSetResolver(
            hv_loader=mock_hv,
            domain="corp.local",
            username="admin",
            password="password",
        )

        # Mock task XML parsing
        with patch("taskhound.parsers.task_xml.parse_task_xml") as mock_parse:
            mock_parse.return_value = {"runas": "admin", "logon_type": "password"}

            with patch("taskhound.resolver.is_sid", return_value=False):
                with patch.object(resolver, "_batch_ldap_fetch") as mock_batch:
                    items = [("task1.xml", b"<Task/>")]
                    resolver.prefetch_from_tasks(items)

                    # Admin is in hv_users, no batch fetch needed
                    mock_batch.assert_not_called()

                    # But it should be cached by SID
                    assert "S-1-5-21-123-456-789-500" in resolver._sid_cache

    def test_prefetch_batches_missing_users(self):
        """Test prefetch batches LDAP queries for missing users."""
        mock_hv = Mock()
        mock_hv.loaded = True
        mock_hv.hv_users = {}  # No users in BloodHound

        resolver = PwdLastSetResolver(
            hv_loader=mock_hv,
            domain="corp.local",
            username="admin",
            password="password",
        )

        with patch("taskhound.parsers.task_xml.parse_task_xml") as mock_parse:
            mock_parse.side_effect = [
                {"runas": "user1", "logon_type": "password"},
                {"runas": "user2", "logon_type": "password"},
            ]

            with patch("taskhound.resolver.is_sid", return_value=False):
                with patch.object(resolver, "_batch_ldap_fetch") as mock_batch:
                    items = [("task1.xml", b"<Task/>"), ("task2.xml", b"<Task/>")]
                    resolver.prefetch_from_tasks(items)

                    mock_batch.assert_called_once()
                    call_args = mock_batch.call_args[0][0]
                    assert "user1" in call_args
                    assert "user2" in call_args

    def test_prefetch_skips_sids(self):
        """Test that prefetch skips SID-based runas accounts."""
        resolver = PwdLastSetResolver(
            domain="corp.local",
            username="admin",
            password="password",
        )

        with patch("taskhound.parsers.task_xml.parse_task_xml") as mock_parse:
            mock_parse.return_value = {
                "runas": "S-1-5-21-123-456-789-1001",
                "logon_type": "password",
            }

            with patch("taskhound.resolver.is_sid", return_value=True):
                with patch.object(resolver, "_batch_ldap_fetch") as mock_batch:
                    items = [("task1.xml", b"<Task/>")]
                    resolver.prefetch_from_tasks(items)

                    # Should not batch fetch SIDs
                    mock_batch.assert_not_called()


class TestResolveRunasToSid:
    """Tests for SID resolution from runas strings."""

    def test_resolve_already_sid(self):
        """Test that SIDs are returned unchanged."""
        resolver = PwdLastSetResolver()

        with patch("taskhound.resolver.is_sid", return_value=True):
            result = resolver._resolve_runas_to_sid("S-1-5-21-123-456-789-500")
            assert result == "S-1-5-21-123-456-789-500"

    def test_resolve_from_bloodhound_data(self):
        """Test SID resolution from BloodHound high-value data."""
        mock_hv = Mock()
        mock_hv.loaded = True
        mock_hv.hv_users = {
            "admin": {"sid": "S-1-5-21-123-456-789-500"}
        }

        resolver = PwdLastSetResolver(hv_loader=mock_hv)

        with patch("taskhound.resolver.is_sid", return_value=False):
            result = resolver._resolve_runas_to_sid("CORP\\admin")
            assert result == "S-1-5-21-123-456-789-500"

    def test_resolve_empty_string(self):
        """Test resolution of empty string."""
        resolver = PwdLastSetResolver()
        result = resolver._resolve_runas_to_sid("")
        assert result is None

    def test_resolve_none(self):
        """Test resolution of None."""
        resolver = PwdLastSetResolver()
        result = resolver._resolve_runas_to_sid(None)
        assert result is None
