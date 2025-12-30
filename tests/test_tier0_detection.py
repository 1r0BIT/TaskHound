"""
Tests for Tier-0 detection functionality in sid_resolver.

Tests the pre-flight LDAP query approach for detecting Tier-0 users.
"""
from unittest.mock import MagicMock, patch

from taskhound.resolver import (
    TIER0_ACCOUNT_RIDS,
    TIER0_BUILTIN_SIDS,
    TIER0_GROUP_RIDS,
    Tier0Cache,
    check_tier0_membership,
    fetch_tier0_members,
)


class TestTier0Constants:
    """Tests for Tier-0 group/account constants."""

    def test_tier0_group_rids_has_domain_admins(self):
        """Domain Admins (512) should be in TIER0_GROUP_RIDS."""
        assert 512 in TIER0_GROUP_RIDS
        assert TIER0_GROUP_RIDS[512] == "Domain Admins"

    def test_tier0_group_rids_has_enterprise_admins(self):
        """Enterprise Admins (519) should be in TIER0_GROUP_RIDS."""
        assert 519 in TIER0_GROUP_RIDS
        assert TIER0_GROUP_RIDS[519] == "Enterprise Admins"

    def test_tier0_group_rids_has_schema_admins(self):
        """Schema Admins (518) should be in TIER0_GROUP_RIDS."""
        assert 518 in TIER0_GROUP_RIDS
        assert TIER0_GROUP_RIDS[518] == "Schema Admins"

    def test_tier0_account_rids_has_administrator(self):
        """Administrator (500) should be in TIER0_ACCOUNT_RIDS."""
        assert 500 in TIER0_ACCOUNT_RIDS
        assert "Administrator" in TIER0_ACCOUNT_RIDS[500]

    def test_tier0_account_rids_has_krbtgt(self):
        """krbtgt (502) should be in TIER0_ACCOUNT_RIDS."""
        assert 502 in TIER0_ACCOUNT_RIDS
        assert TIER0_ACCOUNT_RIDS[502] == "krbtgt"

    def test_tier0_builtin_sids_has_administrators(self):
        """Builtin Administrators should be in TIER0_BUILTIN_SIDS."""
        assert "S-1-5-32-544" in TIER0_BUILTIN_SIDS
        assert TIER0_BUILTIN_SIDS["S-1-5-32-544"] == "Administrators"

    def test_tier0_builtin_sids_has_account_operators(self):
        """Account Operators should be in TIER0_BUILTIN_SIDS."""
        assert "S-1-5-32-548" in TIER0_BUILTIN_SIDS

    def test_tier0_builtin_sids_has_server_operators(self):
        """Server Operators should be in TIER0_BUILTIN_SIDS."""
        assert "S-1-5-32-549" in TIER0_BUILTIN_SIDS

    def test_tier0_builtin_sids_has_backup_operators(self):
        """Backup Operators should be in TIER0_BUILTIN_SIDS."""
        assert "S-1-5-32-551" in TIER0_BUILTIN_SIDS


class TestCheckTier0Membership:
    """Tests for check_tier0_membership function (cache lookup)."""

    def test_returns_false_for_empty_username(self):
        """Should return False for empty username."""
        cache: Tier0Cache = {"admin": (True, ["Domain Admins"])}

        is_tier0, groups = check_tier0_membership("", cache)

        assert is_tier0 is False
        assert groups == []

    def test_returns_false_for_none_username(self):
        """Should return False for None username."""
        cache: Tier0Cache = {"admin": (True, ["Domain Admins"])}

        is_tier0, groups = check_tier0_membership(None, cache)

        assert is_tier0 is False
        assert groups == []

    def test_returns_false_for_empty_cache(self):
        """Should return False for empty cache."""
        is_tier0, groups = check_tier0_membership("admin", {})

        assert is_tier0 is False
        assert groups == []

    def test_returns_false_for_none_cache(self):
        """Should return False for None cache."""
        is_tier0, groups = check_tier0_membership("admin", None)

        assert is_tier0 is False
        assert groups == []

    def test_finds_tier0_user_in_cache(self):
        """Should find Tier-0 user in cache."""
        cache: Tier0Cache = {
            "admin": (True, ["Domain Admins", "Schema Admins"]),
            "user1": (True, ["Administrators"]),
        }

        is_tier0, groups = check_tier0_membership("admin", cache)

        assert is_tier0 is True
        assert "Domain Admins" in groups
        assert "Schema Admins" in groups

    def test_handles_domain_prefix(self):
        """Should strip domain prefix from username."""
        cache: Tier0Cache = {"admin": (True, ["Domain Admins"])}

        is_tier0, groups = check_tier0_membership("DOMAIN\\admin", cache)

        assert is_tier0 is True
        assert groups == ["Domain Admins"]

    def test_handles_upn_format(self):
        """Should strip UPN suffix from username."""
        cache: Tier0Cache = {"admin": (True, ["Enterprise Admins"])}

        is_tier0, groups = check_tier0_membership("admin@domain.local", cache)

        assert is_tier0 is True
        assert groups == ["Enterprise Admins"]

    def test_case_insensitive_lookup(self):
        """Should do case-insensitive lookup."""
        cache: Tier0Cache = {"admin": (True, ["Domain Admins"])}

        is_tier0, groups = check_tier0_membership("ADMIN", cache)

        assert is_tier0 is True

    def test_skips_system_accounts(self):
        """Should skip well-known system accounts."""
        cache: Tier0Cache = {
            "system": (True, ["Administrators"]),
            "local service": (True, ["Administrators"]),
            "network service": (True, ["Administrators"]),
        }

        assert check_tier0_membership("SYSTEM", cache) == (False, [])
        assert check_tier0_membership("Local Service", cache) == (False, [])
        assert check_tier0_membership("Network Service", cache) == (False, [])

    def test_returns_false_for_non_tier0_user(self):
        """Should return False for user not in cache."""
        cache: Tier0Cache = {"admin": (True, ["Domain Admins"])}

        is_tier0, groups = check_tier0_membership("regularuser", cache)

        assert is_tier0 is False
        assert groups == []


class TestFetchTier0Members:
    """Tests for fetch_tier0_members function."""

    def test_returns_empty_for_no_domain(self):
        """Should return empty cache if no domain provided."""
        result = fetch_tier0_members(domain="")

        assert result == {}

    def test_returns_empty_for_none_domain(self):
        """Should return empty cache if domain is None."""
        result = fetch_tier0_members(domain=None)

        assert result == {}

    @patch("taskhound.resolver.tier0.get_cache")
    def test_uses_cached_data_if_available(self, mock_get_cache):
        """Should return cached data if available."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = {"cacheduser": (True, ["Domain Admins"])}
        mock_get_cache.return_value = mock_cache

        result = fetch_tier0_members(domain="test.local")

        assert result == {"cacheduser": (True, ["Domain Admins"])}
        mock_cache.get.assert_called_once()

    @patch("taskhound.resolver.tier0.get_cache")
    @patch("taskhound.resolver.tier0.get_ldap_connection")
    def test_returns_empty_on_connection_failure(self, mock_ldap, mock_get_cache):
        """Should return empty cache on connection failure (e.g., DNS or network error)."""
        from taskhound.utils.ldap import LDAPConnectionError

        mock_get_cache.return_value = MagicMock(get=MagicMock(return_value=None))
        mock_ldap.side_effect = LDAPConnectionError("Connection failed")

        result = fetch_tier0_members(domain="test.local", dc_ip=None)

        # Should try to connect
        mock_ldap.assert_called_once()
        # Should return empty on connection failure
        assert result == {}

    @patch("taskhound.resolver.tier0.get_cache")
    @patch("taskhound.resolver.tier0.get_ldap_connection")
    def test_handles_ldap_connection_failure(self, mock_ldap, mock_cache):
        """Should return empty cache on LDAP connection failure."""
        from taskhound.utils.ldap import LDAPConnectionError

        mock_cache.return_value = MagicMock(get=MagicMock(return_value=None))
        mock_ldap.side_effect = LDAPConnectionError("Connection refused")

        result = fetch_tier0_members(
            domain="test.local",
            auth_username="user",
            auth_password="pass",
        )

        assert result == {}

    @patch("taskhound.resolver.tier0.get_cache")
    @patch("taskhound.resolver.tier0.get_ldap_connection")
    def test_queries_domain_controllers_for_domain_sid(self, mock_ldap, mock_cache):
        """Should query domain controllers to find domain SID."""
        mock_cache.return_value = MagicMock(get=MagicMock(return_value=None))

        # Mock LDAP connection that returns empty results
        mock_conn = MagicMock()
        mock_conn.search.return_value = []  # No DCs found
        mock_ldap.return_value = mock_conn

        result = fetch_tier0_members(
            domain="test.local",
            auth_username="user",
            auth_password="pass",
        )

        # Should have tried to search for domain controllers
        mock_conn.search.assert_called()
        # Should return empty since no DC found
        assert result == {}


class TestFetchTier0MembersIntegration:
    """Integration-style tests with more complex mocking."""

    def _create_ldap_entry(self, attrs: dict):
        """Create a mock LDAP SearchResultEntry."""
        from impacket.ldap import ldapasn1 as ldapasn1_impacket

        mock_entry = MagicMock(spec=ldapasn1_impacket.SearchResultEntry)

        # Build mock attributes
        mock_attrs = []
        for name, value in attrs.items():
            mock_attr = MagicMock()
            mock_attr.__getitem__ = MagicMock(side_effect=lambda k, n=name, v=value: n if k == "type" else MagicMock(
                __iter__=MagicMock(return_value=iter([v] if not isinstance(v, list) else v)),
                asOctets=MagicMock(return_value=v if isinstance(v, bytes) else None)
            ))

            # Set up the type attribute
            type(mock_attr).__getitem__ = lambda self, key, n=name, v=value: (
                n if key == "type" else MagicMock(
                    __iter__=lambda self, vals=[v] if not isinstance(v, list) else v: iter(vals)
                )
            )
            mock_attrs.append(mock_attr)

        mock_entry.__getitem__ = MagicMock(side_effect=lambda k: mock_attrs if k == "attributes" else None)
        return mock_entry

    @patch("taskhound.resolver.tier0.get_cache")
    @patch("taskhound.resolver.tier0.get_ldap_connection")
    def test_uses_provided_dc_ip(self, mock_ldap, mock_cache):
        """Should use provided DC IP instead of resolving."""
        mock_cache.return_value = MagicMock(get=MagicMock(return_value=None))
        mock_conn = MagicMock()
        mock_conn.search.return_value = []
        mock_ldap.return_value = mock_conn

        fetch_tier0_members(
            domain="test.local",
            dc_ip="10.0.0.1",
            auth_username="user",
            auth_password="pass",
        )

        # Should use provided IP
        mock_ldap.assert_called_once()
        call_kwargs = mock_ldap.call_args.kwargs
        assert call_kwargs["dc_ip"] == "10.0.0.1"


class TestTier0CacheTypeAlias:
    """Tests for Tier0Cache type alias usage."""

    def test_tier0_cache_structure(self):
        """Tier0Cache should have correct structure."""
        cache: Tier0Cache = {
            "admin": (True, ["Domain Admins", "Enterprise Admins"]),
            "user1": (True, ["Administrators"]),
        }

        # Verify structure
        for username, (is_tier0, groups) in cache.items():
            assert isinstance(username, str)
            assert isinstance(is_tier0, bool)
            assert isinstance(groups, list)
            for group in groups:
                assert isinstance(group, str)

    def test_empty_cache_is_valid(self):
        """Empty dict is valid Tier0Cache."""
        cache: Tier0Cache = {}
        assert cache == {}

    def test_cache_with_multiple_groups(self):
        """User can be member of multiple Tier-0 groups."""
        cache: Tier0Cache = {
            "superadmin": (True, [
                "Domain Admins",
                "Enterprise Admins",
                "Schema Admins",
                "Administrators",
            ])
        }

        is_tier0, groups = cache["superadmin"]
        assert is_tier0 is True
        assert len(groups) == 4
