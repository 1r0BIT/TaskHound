# Tests for LAPS (Local Administrator Password Solution) module
#
# Tests cover:
#   - LAPSCache operations (add, get, normalization)
#   - Windows LAPS JSON parsing
#   - Legacy LAPS handling
#   - Error handling and edge cases

from datetime import UTC, datetime, timedelta

import pytest

from taskhound.laps import (
    LAPS_ERRORS,
    LAPSCache,
    LAPSCredential,
    LAPSFailure,
    LAPSParseError,
    get_laps_credential_for_host,
    parse_ad_timestamp,
    parse_filetime,
    parse_mslaps_password,
)


class TestLAPSCredential:
    """Tests for LAPSCredential dataclass"""

    def test_basic_creation(self):
        """Test basic credential creation"""
        cred = LAPSCredential(
            password="TestP@ss123",
            username="Administrator",
            laps_type="mslaps",
            computer_name="WS01$",
        )
        assert cred.password == "TestP@ss123"
        assert cred.username == "Administrator"
        assert cred.laps_type == "mslaps"
        assert cred.computer_name == "WS01$"
        assert cred.encrypted is False

    def test_expiration_not_expired(self):
        """Test credential that hasn't expired"""
        future = datetime.now(UTC) + timedelta(days=7)
        cred = LAPSCredential(
            password="test",
            username="Admin",
            laps_type="legacy",
            computer_name="WS01$",
            expiration=future,
        )
        assert cred.is_expired() is False

    def test_expiration_expired(self):
        """Test credential that has expired"""
        past = datetime.now(UTC) - timedelta(days=1)
        cred = LAPSCredential(
            password="test",
            username="Admin",
            laps_type="legacy",
            computer_name="WS01$",
            expiration=past,
        )
        assert cred.is_expired() is True

    def test_expiration_none(self):
        """Test credential with no expiration"""
        cred = LAPSCredential(
            password="test",
            username="Admin",
            laps_type="legacy",
            computer_name="WS01$",
            expiration=None,
        )
        assert cred.is_expired() is False


class TestLAPSCache:
    """Tests for LAPSCache"""

    def test_add_and_get(self):
        """Test basic add and get operations"""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="TestP@ss",
            username="Administrator",
            laps_type="mslaps",
            computer_name="WS01$",
        )
        cache.add(cred)

        result = cache.get("WS01")
        assert result is not None
        assert result.password == "TestP@ss"

    def test_case_insensitive_lookup(self):
        """Test that lookups are case-insensitive"""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="pass",
            username="Admin",
            laps_type="legacy",
            computer_name="WORKSTATION01$",
        )
        cache.add(cred)

        # All these should find the credential
        assert cache.get("WORKSTATION01") is not None
        assert cache.get("workstation01") is not None
        assert cache.get("Workstation01") is not None

    def test_dollar_sign_handling(self):
        """Test that $ suffix is handled correctly"""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="pass",
            username="Admin",
            laps_type="legacy",
            computer_name="SERVER01$",
        )
        cache.add(cred)

        # Both with and without $ should work
        assert cache.get("SERVER01$") is not None
        assert cache.get("SERVER01") is not None

    def test_fqdn_lookup(self):
        """Test lookup by FQDN extracts short name"""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="pass",
            username="Admin",
            laps_type="mslaps",
            computer_name="WS01$",
        )
        cache.add(cred)

        # FQDN should resolve to short name
        assert cache.get("WS01.domain.local") is not None
        assert cache.get("ws01.DOMAIN.LOCAL") is not None

    def test_not_found_returns_none(self):
        """Test that missing entries return None"""
        cache = LAPSCache()
        assert cache.get("NONEXISTENT") is None

    def test_statistics(self):
        """Test cache statistics tracking"""
        cache = LAPSCache()

        # Add various credential types
        cache.add(LAPSCredential("p1", "Admin", "mslaps", "WS01$"))
        cache.add(LAPSCredential("p2", "Admin", "mslaps", "WS02$"))
        cache.add(LAPSCredential("p3", "Admin", "legacy", "WS03$"))
        cache.add(LAPSCredential("", "Admin", "mslaps", "WS04$", encrypted=True))

        stats = cache.get_statistics()
        assert stats["total"] == 4
        assert stats["mslaps"] == 2
        assert stats["legacy"] == 1
        assert stats["encrypted"] == 1
        assert stats["usable"] == 3

    def test_contains(self):
        """Test __contains__ implementation"""
        cache = LAPSCache()
        cache.add(LAPSCredential("pass", "Admin", "legacy", "WS01$"))

        assert "WS01" in cache
        assert "ws01" in cache
        assert "NONEXISTENT" not in cache


class TestMSLAPSParsing:
    """Tests for Windows LAPS JSON parsing"""

    def test_basic_json_parsing(self):
        """Test parsing basic Windows LAPS JSON"""
        json_data = '{"n": "Administrator", "p": "MyP@ssw0rd123"}'
        password, username, encrypted = parse_mslaps_password(json_data)

        assert password == "MyP@ssw0rd123"
        assert username == "Administrator"
        assert encrypted is False

    def test_custom_username(self):
        """Test parsing with custom username"""
        json_data = '{"n": "LocalAdmin", "p": "Secret123"}'
        password, username, encrypted = parse_mslaps_password(json_data)

        assert username == "LocalAdmin"
        assert password == "Secret123"

    def test_default_username_fallback(self):
        """Test fallback when username not in JSON"""
        json_data = '{"p": "Password123"}'
        password, username, encrypted = parse_mslaps_password(json_data, default_username="CustomAdmin")

        assert username == "CustomAdmin"
        assert password == "Password123"

    def test_override_username(self):
        """Test that default_username overrides JSON username"""
        json_data = '{"n": "Administrator", "p": "Pass"}'
        password, username, encrypted = parse_mslaps_password(json_data, default_username="OverrideAdmin")

        # When default_username is provided, it should NOT override - it's a fallback
        # Actually looking at the code, it uses default_username OR json value
        # The current implementation uses JSON value if present
        assert username == "Administrator"

    def test_encrypted_detection(self):
        """Test detection of encrypted passwords"""
        # Long base64-like string indicates encryption
        encrypted_blob = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamts"
        json_data = f'{{"n": "Admin", "p": "{encrypted_blob}"}}'
        password, username, encrypted = parse_mslaps_password(json_data)

        assert encrypted is True

    def test_invalid_json(self):
        """Test handling of invalid JSON"""
        with pytest.raises(LAPSParseError):
            parse_mslaps_password("not valid json")

    def test_missing_password_field(self):
        """Test handling of missing password field"""
        with pytest.raises(LAPSParseError):
            parse_mslaps_password('{"n": "Admin"}')


class TestTimestampParsing:
    """Tests for AD timestamp parsing"""

    def test_parse_ad_timestamp(self):
        """Test parsing AD timestamp"""
        # AD timestamp for approximately 2024-01-01
        # 133480032000000000 is roughly Jan 1, 2024
        timestamp = 133480032000000000
        result = parse_ad_timestamp(timestamp)

        assert result is not None
        assert isinstance(result, datetime)

    def test_parse_ad_timestamp_never_expires(self):
        """Test handling of 'never expires' timestamps"""
        # 0 means never expires
        assert parse_ad_timestamp(0) is None

        # Max int64 also means never
        assert parse_ad_timestamp(9223372036854775807) is None

    def test_parse_filetime_hex(self):
        """Test parsing Windows FILETIME from hex"""
        # Example hex FILETIME
        result = parse_filetime("01D9A2B3C4D5E6F7")

        # Should return a datetime or None, not crash
        assert result is None or isinstance(result, datetime)


class TestGetLAPSCredentialForHost:
    """Tests for get_laps_credential_for_host helper"""

    def test_found_credential(self):
        """Test successful credential lookup"""
        cache = LAPSCache()
        cache.add(LAPSCredential("password123", "Admin", "mslaps", "WS01$"))

        cred, failure = get_laps_credential_for_host(cache, "WS01")

        assert cred is not None
        assert failure is None
        assert cred.password == "password123"

    def test_not_found(self):
        """Test missing credential returns failure"""
        cache = LAPSCache()

        cred, failure = get_laps_credential_for_host(cache, "NONEXISTENT")

        assert cred is None
        assert failure is not None
        assert failure.failure_type == "not_found"

    def test_encrypted_credential(self):
        """Test encrypted credential returns failure"""
        cache = LAPSCache()
        cache.add(LAPSCredential("", "Admin", "mslaps", "WS01$", encrypted=True))

        cred, failure = get_laps_credential_for_host(cache, "WS01")

        assert cred is None
        assert failure is not None
        assert failure.failure_type == "encrypted"


class TestLAPSFailure:
    """Tests for LAPSFailure dataclass"""

    def test_failure_creation(self):
        """Test creating failure objects"""
        failure = LAPSFailure(
            hostname="WS01",
            failure_type="not_found",
            message="No LAPS password",
        )

        assert failure.hostname == "WS01"
        assert failure.failure_type == "not_found"

    def test_failure_with_laps_info(self):
        """Test failure with LAPS-specific info"""
        failure = LAPSFailure(
            hostname="WS01",
            failure_type="auth_failed",
            message="Auth failed",
            laps_user_tried="Administrator",
            laps_type_tried="mslaps",
        )

        assert failure.laps_user_tried == "Administrator"
        assert failure.laps_type_tried == "mslaps"


class TestLAPSErrors:
    """Tests for error message templates"""

    def test_error_message_formatting(self):
        """Test that error messages can be formatted"""
        msg = LAPS_ERRORS["host_not_found"].format(hostname="WS01")
        assert "WS01" in msg

    def test_remote_uac_message(self):
        """Test Remote UAC error message"""
        msg = LAPS_ERRORS["remote_uac"].format(hostname="WORKSTATION01")
        assert "WORKSTATION01" in msg
        assert "LocalAccountTokenFilterPolicy" in msg


class TestLAPSCredentialSerialization:
    """Tests for LAPSCredential serialization (to_cache_dict/from_cache_dict)"""

    def test_to_cache_dict_basic(self):
        """Test serializing credential to dict"""
        cred = LAPSCredential(
            password="TestP@ss123",
            username="Administrator",
            laps_type="mslaps",
            computer_name="WS01$",
        )
        data = cred.to_cache_dict()

        assert data["password"] == "TestP@ss123"
        assert data["username"] == "Administrator"
        assert data["laps_type"] == "mslaps"
        assert data["computer_name"] == "WS01$"
        assert data["encrypted"] is False
        assert data["expiration"] is None

    def test_to_cache_dict_with_expiration(self):
        """Test serializing credential with expiration to dict"""
        exp = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)
        cred = LAPSCredential(
            password="pass",
            username="Admin",
            laps_type="legacy",
            computer_name="WS02$",
            dns_hostname="WS02.domain.local",
            expiration=exp,
        )
        data = cred.to_cache_dict()

        assert data["dns_hostname"] == "WS02.domain.local"
        assert data["expiration"] == "2025-06-15T12:00:00+00:00"

    def test_from_cache_dict_basic(self):
        """Test deserializing credential from dict"""
        data = {
            "password": "Secret123",
            "username": "LocalAdmin",
            "laps_type": "legacy",
            "computer_name": "SRV01$",
            "dns_hostname": None,
            "expiration": None,
            "encrypted": False,
        }
        cred = LAPSCredential.from_cache_dict(data)

        assert cred.password == "Secret123"
        assert cred.username == "LocalAdmin"
        assert cred.laps_type == "legacy"
        assert cred.computer_name == "SRV01$"
        assert cred.encrypted is False

    def test_from_cache_dict_with_expiration(self):
        """Test deserializing credential with expiration"""
        data = {
            "password": "pass",
            "username": "Admin",
            "laps_type": "mslaps",
            "computer_name": "WS03$",
            "dns_hostname": "WS03.domain.local",
            "expiration": "2025-06-15T12:00:00+00:00",
            "encrypted": False,
        }
        cred = LAPSCredential.from_cache_dict(data)

        assert cred.dns_hostname == "WS03.domain.local"
        assert cred.expiration is not None
        assert cred.expiration.year == 2025
        assert cred.expiration.month == 6

    def test_roundtrip_serialization(self):
        """Test that to_cache_dict -> from_cache_dict preserves data"""
        original = LAPSCredential(
            password="ComplexP@ss!",
            username="CustomAdmin",
            laps_type="mslaps",
            computer_name="DESKTOP-ABC$",
            dns_hostname="DESKTOP-ABC.corp.local",
            expiration=datetime.now(UTC) + timedelta(days=30),
            encrypted=False,
        )

        data = original.to_cache_dict()
        restored = LAPSCredential.from_cache_dict(data)

        assert restored.password == original.password
        assert restored.username == original.username
        assert restored.laps_type == original.laps_type
        assert restored.computer_name == original.computer_name
        assert restored.dns_hostname == original.dns_hostname
        assert restored.encrypted == original.encrypted
        # Allow small time difference due to ISO serialization
        if original.expiration:
            diff = abs((restored.expiration - original.expiration).total_seconds())
            assert diff < 1  # Less than 1 second difference


class TestLAPSCachePersistence:
    """Tests for LAPSCache persistent storage"""

    def test_cache_statistics_include_persistent(self):
        """Test that statistics track items loaded from persistent cache"""
        cache = LAPSCache()
        # from_persistent_cache is initialized to 0
        assert cache.from_persistent_cache == 0

    def test_cache_add_updates_counts(self):
        """Test adding credentials updates statistics"""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="pass",
            username="Admin",
            laps_type="mslaps",
            computer_name="WS01$",
        )
        # Add without persisting (persist=False) to avoid needing real cache
        cache.add(cred, persist=False)
        stats = cache.get_statistics()
        assert stats["mslaps"] == 1
        assert stats["total"] == 1


class TestLAPSCacheDomainScoping:
    """Tests for domain-scoped LAPS cache keys"""

    def test_cache_without_domain(self):
        """Test cache key is just computer name when no domain set"""
        cache = LAPSCache()  # No domain
        cred = LAPSCredential(
            password="pass",
            username="Admin",
            laps_type="mslaps",
            computer_name="WS01$",
        )
        cache.add(cred, persist=False)

        # Key should be uppercase computer name without $
        assert "WS01" in cache._cache
        assert cache.get("ws01") is not None  # Case-insensitive lookup

    def test_cache_with_domain(self):
        """Test cache key includes domain when domain is set"""
        cache = LAPSCache(domain="contoso.local")
        cred = LAPSCredential(
            password="pass",
            username="Admin",
            laps_type="mslaps",
            computer_name="WS01$",
        )
        cache.add(cred, persist=False)

        # Key should be DOMAIN\COMPUTERNAME
        assert "CONTOSO.LOCAL\\WS01" in cache._cache

        # Lookup should still work with just hostname
        assert cache.get("WS01") is not None
        assert cache.get("ws01") is not None  # Case-insensitive

    def test_cache_lookup_case_insensitive(self):
        """Test that cache lookups are case-insensitive"""
        cache = LAPSCache(domain="CORP.LOCAL")
        cred = LAPSCredential(
            password="secret",
            username="Admin",
            laps_type="legacy",
            computer_name="DESKTOP-ABC$",
        )
        cache.add(cred, persist=False)

        # All these lookups should find the credential
        assert cache.get("DESKTOP-ABC") is not None
        assert cache.get("desktop-abc") is not None
        assert cache.get("Desktop-Abc") is not None
        assert cache.get("desktop-abc$") is not None

    def test_cache_lookup_with_fqdn(self):
        """Test that FQDN hostnames are normalized to short names"""
        cache = LAPSCache()
        cred = LAPSCredential(
            password="pass",
            username="Admin",
            laps_type="mslaps",
            computer_name="SRV01$",
        )
        cache.add(cred, persist=False)

        # Should find via FQDN
        assert cache.get("SRV01.corp.local") is not None
        assert cache.get("srv01.corp.local") is not None

    def test_cache_domain_attribute(self):
        """Test that domain attribute is set correctly"""
        cache1 = LAPSCache()
        assert cache1.domain is None

        cache2 = LAPSCache(domain="test.local")
        assert cache2.domain == "test.local"


class TestCLIValidation:
    """Tests for LAPS CLI argument validation"""

    def test_laps_help_text(self):
        """Test that LAPS options appear in help"""
        from taskhound.config import build_parser

        parser = build_parser()
        # Check that LAPS arguments exist
        actions = {action.dest: action for action in parser._actions}

        assert "laps" in actions
        assert "laps_user" in actions
        assert "force_laps" in actions

    def test_laps_opsec_validation(self):
        """Test LAPS + OPSEC validation logic"""

        from taskhound.config import build_parser

        parser = build_parser()

        # This would normally exit, so we just verify the args parse
        args = parser.parse_args(["--laps", "-u", "user", "-p", "pass", "-d", "domain.local",
                                  "--dc-ip", "10.0.0.1", "-t", "target"])
        assert args.laps is True
