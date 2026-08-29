"""
Test suite for LAPS models.

Tests cover:
- LAPSCredential dataclass
- LAPSCache class
- LAPSFailure dataclass
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from taskhound.laps.models import (
    LAPSCache,
    LAPSCredential,
    LAPSFailure,
)

# ============================================================================
# Test: LAPSCredential
# ============================================================================


class TestLAPSCredential:
    """Tests for LAPSCredential dataclass"""

    def test_basic_credential_creation(self):
        """Should create credential with required fields"""
        cred = LAPSCredential(
            password="P@ssw0rd123",
            username="Administrator",
            laps_type="legacy",
            computer_name="WS01$"
        )

        assert cred.password == "P@ssw0rd123"
        assert cred.username == "Administrator"
        assert cred.laps_type == "legacy"
        assert cred.computer_name == "WS01$"
        assert cred.encrypted is False

    def test_optional_fields(self):
        """Should accept optional fields"""
        expiration = datetime.now(UTC) + timedelta(hours=24)
        cred = LAPSCredential(
            password="P@ss",
            username="admin",
            laps_type="mslaps",
            computer_name="WS01$",
            dns_hostname="WS01.example.com",
            expiration=expiration,
            encrypted=False
        )

        assert cred.dns_hostname == "WS01.example.com"
        assert cred.expiration == expiration

    def test_is_expired_future(self):
        """Should return False for future expiration"""
        expiration = datetime.now(UTC) + timedelta(hours=24)
        cred = LAPSCredential(
            password="P@ss",
            username="admin",
            laps_type="legacy",
            computer_name="WS01$",
            expiration=expiration
        )

        assert cred.is_expired() is False

    def test_is_expired_past(self):
        """Should return True for past expiration"""
        expiration = datetime.now(UTC) - timedelta(hours=1)
        cred = LAPSCredential(
            password="P@ss",
            username="admin",
            laps_type="legacy",
            computer_name="WS01$",
            expiration=expiration
        )

        assert cred.is_expired() is True

    def test_is_expired_none(self):
        """Should return False when no expiration set"""
        cred = LAPSCredential(
            password="P@ss",
            username="admin",
            laps_type="legacy",
            computer_name="WS01$"
        )

        assert cred.is_expired() is False

    def test_to_cache_dict(self):
        """Should serialize to dictionary"""
        expiration = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        cred = LAPSCredential(
            password="P@ss",
            username="admin",
            laps_type="mslaps",
            computer_name="WS01$",
            dns_hostname="WS01.example.com",
            expiration=expiration
        )

        result = cred.to_cache_dict()

        assert result["password"] == "P@ss"
        assert result["username"] == "admin"
        assert result["laps_type"] == "mslaps"
        assert result["computer_name"] == "WS01$"
        assert result["dns_hostname"] == "WS01.example.com"
        assert "2024-01-15" in result["expiration"]

    def test_from_cache_dict(self):
        """Should deserialize from dictionary"""
        data = {
            "password": "P@ss123",
            "username": "Administrator",
            "laps_type": "legacy",
            "computer_name": "WS01$",
            "dns_hostname": "WS01.example.com",
            "expiration": "2024-01-15T12:00:00+00:00",
            "encrypted": False
        }

        cred = LAPSCredential.from_cache_dict(data)

        assert cred.password == "P@ss123"
        assert cred.username == "Administrator"
        assert cred.laps_type == "legacy"
        assert cred.computer_name == "WS01$"
        assert cred.dns_hostname == "WS01.example.com"

    def test_from_cache_dict_missing_optional(self):
        """Should handle missing optional fields"""
        data = {
            "password": "P@ss",
            "username": "admin",
            "laps_type": "legacy",
            "computer_name": "WS01$"
        }

        cred = LAPSCredential.from_cache_dict(data)

        assert cred.dns_hostname is None
        assert cred.expiration is None
        assert cred.encrypted is False


# ============================================================================
# Test: LAPSCache
# ============================================================================


class TestLAPSCache:
    """Tests for LAPSCache class"""

    def test_empty_cache(self):
        """Should start with empty cache"""
        cache = LAPSCache()

        assert len(cache._cache) == 0
        assert cache.legacy_count == 0
        assert cache.mslaps_count == 0

    @patch('taskhound.laps.models.get_cache')
    def test_add_legacy_credential(self, mock_get_cache):
        """Should add legacy LAPS credential and update count"""
        mock_get_cache.return_value = None
        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss",
            username="Administrator",
            laps_type="legacy",
            computer_name="WS01$"
        )

        cache.add(cred, persist=False)

        assert cache.legacy_count == 1
        assert "WS01" in cache._cache

    @patch('taskhound.laps.models.get_cache')
    def test_add_mslaps_credential(self, mock_get_cache):
        """Should add Windows LAPS credential and update count"""
        mock_get_cache.return_value = None
        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss",
            username="admin",
            laps_type="mslaps",
            computer_name="WS02$"
        )

        cache.add(cred, persist=False)

        assert cache.mslaps_count == 1

    @patch('taskhound.laps.models.get_cache')
    def test_add_encrypted_credential(self, mock_get_cache):
        """Should track encrypted credentials"""
        mock_get_cache.return_value = None
        cache = LAPSCache()
        cred = LAPSCredential(
            password="",
            username="admin",
            laps_type="mslaps",
            computer_name="WS03$",
            encrypted=True
        )

        cache.add(cred, persist=False)

        assert cache.encrypted_count == 1

    def test_get_by_short_name(self):
        """Should retrieve credential by short hostname"""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss",
            username="admin",
            laps_type="legacy",
            computer_name="WS01$"
        )
        cache._cache["WS01"] = cred

        result = cache.get("WS01")

        assert result == cred

    def test_get_case_insensitive(self):
        """Should retrieve credential case-insensitively"""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss",
            username="admin",
            laps_type="legacy",
            computer_name="WS01$"
        )
        cache._cache["WS01"] = cred

        result = cache.get("ws01")

        assert result == cred

    def test_get_nonexistent(self):
        """Should return None for nonexistent key"""
        cache = LAPSCache()

        result = cache.get("NONEXISTENT")

        assert result is None

    @patch('taskhound.laps.models.get_cache')
    def test_get_statistics(self, mock_get_cache):
        """Should return statistics dict"""
        mock_get_cache.return_value = None
        cache = LAPSCache()

        # Add credentials to populate counts
        for i in range(5):
            cred = LAPSCredential(
                password="P@ss",
                username="admin",
                laps_type="legacy",
                computer_name=f"WS{i:02d}$"
            )
            cache.add(cred, persist=False)

        for i in range(3):
            cred = LAPSCredential(
                password="P@ss",
                username="admin",
                laps_type="mslaps",
                computer_name=f"SRV{i:02d}$"
            )
            cache.add(cred, persist=False)

        stats = cache.get_statistics()

        assert stats["legacy"] == 5
        assert stats["mslaps"] == 3

# ============================================================================
# Test: LAPSCache persistence methods
# ============================================================================


class TestLAPSCachePersistence:
    """Tests for LAPSCache persistence methods."""

    @patch('taskhound.laps.models.get_cache')
    def test_persist_credential_when_cache_disabled(self, mock_get_cache):
        """_persist_credential does nothing when cache disabled."""
        mock_get_cache.return_value = None
        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss", username="admin", laps_type="legacy", computer_name="WS01$"
        )
        # Should not raise
        cache._persist_credential("WS01", cred)

    @patch('taskhound.laps.models.get_cache')
    def test_persist_credential_with_expiration(self, mock_get_cache):
        """_persist_credential uses credential expiration for TTL."""
        mock_cache = MagicMock()
        mock_cache.persistent_enabled = True
        mock_get_cache.return_value = mock_cache

        cache = LAPSCache()
        expiration = datetime.now(UTC) + timedelta(hours=12)
        cred = LAPSCredential(
            password="P@ss", username="admin", laps_type="mslaps",
            computer_name="WS01$", expiration=expiration
        )
        cache._persist_credential("WS01", cred)
        mock_cache.set.assert_called_once()

    @patch('taskhound.laps.models.get_cache')
    def test_persist_credential_no_expiration(self, mock_get_cache):
        """_persist_credential uses default TTL when no expiration."""
        mock_cache = MagicMock()
        mock_cache.persistent_enabled = True
        mock_get_cache.return_value = mock_cache

        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss", username="admin", laps_type="legacy",
            computer_name="WS01$"
        )
        cache._persist_credential("WS01", cred)
        mock_cache.set.assert_called_once()
        # Check TTL is 8 hours default
        call_kwargs = mock_cache.set.call_args
        assert call_kwargs[1].get("ttl_hours") == 8 or call_kwargs[0][3] == 8

    @patch('taskhound.laps.models.get_cache')
    def test_persist_credential_exception(self, mock_get_cache):
        """_persist_credential handles exceptions."""
        mock_cache = MagicMock()
        mock_cache.persistent_enabled = True
        mock_cache.set.side_effect = Exception("DB error")
        mock_get_cache.return_value = mock_cache

        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss", username="admin", laps_type="legacy", computer_name="WS01$"
        )
        # Should not raise
        cache._persist_credential("WS01", cred)

    @patch('taskhound.laps.models.get_cache')
    def test_load_from_persistent_cache_disabled(self, mock_get_cache):
        """_load_from_persistent returns None when cache disabled."""
        mock_get_cache.return_value = None
        cache = LAPSCache()
        result = cache._load_from_persistent("WS01")
        assert result is None

    @patch('taskhound.laps.models.get_cache')
    def test_load_from_persistent_not_found(self, mock_get_cache):
        """_load_from_persistent returns None when key not found."""
        mock_cache = MagicMock()
        mock_cache.persistent_enabled = True
        mock_cache.get.return_value = None
        mock_get_cache.return_value = mock_cache

        cache = LAPSCache()
        result = cache._load_from_persistent("WS01")
        assert result is None

    @patch('taskhound.laps.models.get_cache')
    def test_load_from_persistent_expired(self, mock_get_cache):
        """_load_from_persistent deletes and returns None for expired creds."""
        mock_cache = MagicMock()
        mock_cache.persistent_enabled = True
        # Return an expired credential
        past_time = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        mock_cache.get.return_value = {
            "password": "P@ss", "username": "admin", "laps_type": "legacy",
            "computer_name": "WS01$", "expiration": past_time
        }
        mock_get_cache.return_value = mock_cache

        cache = LAPSCache()
        result = cache._load_from_persistent("WS01")
        assert result is None
        mock_cache.delete.assert_called_once()

    @patch('taskhound.laps.models.get_cache')
    def test_load_from_persistent_success(self, mock_get_cache):
        """_load_from_persistent returns credential when found and valid."""
        mock_cache = MagicMock()
        mock_cache.persistent_enabled = True
        future_time = (datetime.now(UTC) + timedelta(hours=12)).isoformat()
        mock_cache.get.return_value = {
            "password": "P@ss123", "username": "admin", "laps_type": "legacy",
            "computer_name": "WS01$", "expiration": future_time
        }
        mock_get_cache.return_value = mock_cache

        cache = LAPSCache()
        result = cache._load_from_persistent("WS01")
        assert result is not None
        assert result.password == "P@ss123"


# ============================================================================
# Test: LAPSCache get method
# ============================================================================


class TestLAPSCacheGet:
    """Tests for LAPSCache.get method."""

    def test_get_from_memory_cache(self):
        """get returns credential from in-memory cache."""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss", username="admin", laps_type="legacy", computer_name="WS01$"
        )
        cache._cache["WS01"] = cred

        result = cache.get("ws01")
        assert result is cred

    def test_get_case_insensitive(self):
        """get is case-insensitive."""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss", username="admin", laps_type="legacy", computer_name="WS01$"
        )
        cache._cache["WS01"] = cred

        assert cache.get("WS01") is cred
        assert cache.get("ws01") is cred

    def test_get_strips_dollar_suffix(self):
        """get strips $ suffix from hostname."""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss", username="admin", laps_type="legacy", computer_name="WS01$"
        )
        cache._cache["WS01"] = cred

        result = cache.get("WS01$")
        assert result is cred

    def test_get_extracts_shortname_from_fqdn(self):
        """get extracts short name from FQDN."""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="P@ss", username="admin", laps_type="legacy", computer_name="WS01$"
        )
        cache._cache["WS01"] = cred

        result = cache.get("ws01.example.com")
        assert result is cred

    def test_get_not_found(self):
        """get returns None when hostname not found."""
        cache = LAPSCache()
        result = cache.get("NONEXISTENT")
        assert result is None


# ============================================================================
# Test: LAPSCache special methods
# ============================================================================


class TestLAPSCacheSpecialMethods:
    """Tests for LAPSCache special methods."""

    def test_len(self):
        """__len__ returns cache size."""
        cache = LAPSCache()
        assert len(cache) == 0

        cache._cache["WS01"] = LAPSCredential(
            password="P", username="a", laps_type="legacy", computer_name="WS01$"
        )
        assert len(cache) == 1

    def test_contains_true(self):
        """__contains__ returns True when hostname found."""
        cache = LAPSCache()
        cache._cache["WS01"] = LAPSCredential(
            password="P", username="a", laps_type="legacy", computer_name="WS01$"
        )
        assert "ws01" in cache

    def test_contains_false(self):
        """__contains__ returns False when hostname not found."""
        cache = LAPSCache()
        assert "NONEXISTENT_HOST_12345" not in cache

    def test_total_usable(self):
        """total_usable returns sum of legacy and mslaps counts."""
        cache = LAPSCache()
        cache.legacy_count = 5
        cache.mslaps_count = 3
        assert cache.total_usable == 8

    def test_get_statistics(self):
        """get_statistics returns correct stats dictionary."""
        cache = LAPSCache()
        cache._cache["WS01"] = LAPSCredential(
            password="P", username="a", laps_type="legacy", computer_name="WS01$"
        )
        cache.legacy_count = 3
        cache.mslaps_count = 2
        cache.encrypted_count = 1
        cache.from_persistent_cache = 1

        stats = cache.get_statistics()
        assert stats["total"] == 1
        assert stats["legacy"] == 3
        assert stats["mslaps"] == 2
        assert stats["encrypted"] == 1
        assert stats["usable"] == 5
        assert stats["from_cache"] == 1


# ============================================================================
# Test: LAPSFailure
# ============================================================================


class TestLAPSFailure:
    """Tests for LAPSFailure dataclass"""

    def test_basic_failure(self):
        """Should create failure with required fields"""
        failure = LAPSFailure(
            hostname="WS01",
            failure_type="not_found",
            message="Host not found in LAPS cache"
        )

        assert failure.hostname == "WS01"
        assert failure.failure_type == "not_found"
        assert failure.message == "Host not found in LAPS cache"

    def test_failure_with_laps_type(self):
        """Should include LAPS type tried"""
        failure = LAPSFailure(
            hostname="WS01",
            failure_type="encrypted",
            message="Password is encrypted",
            laps_type_tried="mslaps"
        )

        assert failure.laps_type_tried == "mslaps"

    def test_failure_types(self):
        """Should accept various failure types"""
        failure_types = ["not_found", "encrypted", "auth_failed", "remote_uac"]

        for ft in failure_types:
            failure = LAPSFailure(
                hostname="WS01",
                failure_type=ft,
                message=f"Failure: {ft}"
            )
            assert failure.failure_type == ft

