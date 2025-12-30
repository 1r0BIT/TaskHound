"""
Additional SID resolver tests for coverage improvement.

Tests for BloodHound API resolution, SMB LSARPC resolution, and LDAP resolution paths.
"""
from unittest.mock import MagicMock, patch

from taskhound.resolver import (
    format_runas_with_sid_resolution,
    looks_like_domain_user,
    resolve_sid,
    resolve_sid_from_bloodhound,
    resolve_sid_via_bloodhound_api,
)


class TestResolveViaBloodhoundApi:
    """Tests for resolve_sid_via_bloodhound_api function."""

    def test_returns_none_when_no_connector(self):
        """Should return None when bh_connector is None."""
        result = resolve_sid_via_bloodhound_api("S-1-5-21-xxx", None)

        assert result is None

    def test_queries_bloodhound_with_cypher(self):
        """Should query BloodHound API with Cypher query."""
        mock_connector = MagicMock()
        mock_connector.run_cypher_query.return_value = {
            "data": {
                "data": [{"name": "ADMIN@DOMAIN.LOCAL"}]
            }
        }

        result = resolve_sid_via_bloodhound_api(
            "S-1-5-21-123456789-1001",
            mock_connector
        )

        assert result == "ADMIN@DOMAIN.LOCAL"
        mock_connector.run_cypher_query.assert_called_once()
        # Verify the query contains the SID
        query = mock_connector.run_cypher_query.call_args[0][0]
        assert "S-1-5-21-123456789-1001" in query

    def test_returns_none_on_empty_result(self):
        """Should return None when BloodHound returns no data."""
        mock_connector = MagicMock()
        mock_connector.run_cypher_query.return_value = None

        result = resolve_sid_via_bloodhound_api(
            "S-1-5-21-unknown",
            mock_connector
        )

        assert result is None

    def test_returns_none_on_empty_data_array(self):
        """Should return None when data array is empty."""
        mock_connector = MagicMock()
        mock_connector.run_cypher_query.return_value = {
            "data": {"data": []}
        }

        result = resolve_sid_via_bloodhound_api(
            "S-1-5-21-unknown",
            mock_connector
        )

        assert result is None

    def test_handles_api_exception(self):
        """Should handle exceptions from BloodHound API."""
        mock_connector = MagicMock()
        mock_connector.run_cypher_query.side_effect = Exception("API Error")

        result = resolve_sid_via_bloodhound_api(
            "S-1-5-21-error",
            mock_connector
        )

        assert result is None


class TestResolveFromBloodhoundExtended:
    """Extended tests for resolve_sid_from_bloodhound."""

    def test_returns_samaccountname(self):
        """Should return samaccountname if available."""
        mock_loader = MagicMock()
        mock_loader.loaded = True
        mock_loader.hv_sids = {
            "S-1-5-21-123-1001": {
                "samaccountname": "admin",
                "name": "Administrator Full Name"
            }
        }

        result = resolve_sid_from_bloodhound("S-1-5-21-123-1001", mock_loader)

        assert result == "admin"

    def test_falls_back_to_name(self):
        """Should fall back to name if samaccountname not available."""
        mock_loader = MagicMock()
        mock_loader.loaded = True
        mock_loader.hv_sids = {
            "S-1-5-21-123-1002": {
                "name": "SERVICE_ACCOUNT"
            }
        }

        result = resolve_sid_from_bloodhound("S-1-5-21-123-1002", mock_loader)

        assert result == "SERVICE_ACCOUNT"

    def test_strips_quotes_from_username(self):
        """Should strip quotes from username."""
        mock_loader = MagicMock()
        mock_loader.loaded = True
        mock_loader.hv_sids = {
            "S-1-5-21-123-1003": {
                "samaccountname": '"quoteduser"'
            }
        }

        result = resolve_sid_from_bloodhound("S-1-5-21-123-1003", mock_loader)

        assert result == "quoteduser"


class TestLooksLikeDomainUser:
    """Tests for looks_like_domain_user function."""

    def test_recognizes_domain_backslash_user(self):
        """Should recognize DOMAIN\\user format."""
        assert looks_like_domain_user("DOMAIN\\admin") is True
        assert looks_like_domain_user("corp.local\\jsmith") is True

    def test_recognizes_upn_format(self):
        """Should recognize user@domain format."""
        assert looks_like_domain_user("admin@domain.local") is True
        assert looks_like_domain_user("jsmith@corp.local") is True

    def test_rejects_local_accounts(self):
        """Should reject local-only accounts."""
        assert looks_like_domain_user("Administrator") is False
        assert looks_like_domain_user("localuser") is False

    def test_rejects_nt_authority_system(self):
        """Should reject NT AUTHORITY\\SYSTEM."""
        assert looks_like_domain_user("NT AUTHORITY\\SYSTEM") is False

    def test_rejects_local_system_user(self):
        """Should reject local system account via user check."""
        # DOMAIN\\system is rejected because 'system' is in local_user_names
        assert looks_like_domain_user("DOMAIN\\system") is False

    def test_rejects_empty_string(self):
        """Should reject empty string."""
        assert looks_like_domain_user("") is False

    def test_rejects_none(self):
        """Should reject None."""
        assert looks_like_domain_user(None) is False

    def test_accepts_domain_user_with_backslash(self):
        """Should accept normal domain user."""
        assert looks_like_domain_user("CORP\\jsmith") is True

    def test_rejects_dot_local_domain(self):
        """Should reject local accounts with dot domain."""
        assert looks_like_domain_user(".\\localadmin") is False

    def test_recognizes_domain_sid(self):
        """Should recognize domain SID format."""
        assert looks_like_domain_user("S-1-5-21-123456789-987654321-111111111-1001") is True

    def test_rejects_local_system_sid(self):
        """Should reject well-known local SIDs."""
        assert looks_like_domain_user("S-1-5-18") is False  # SYSTEM
        assert looks_like_domain_user("S-1-5-19") is False  # Local Service
        assert looks_like_domain_user("S-1-5-20") is False  # Network Service


class TestResolveSid:
    """Tests for the main resolve_sid function."""

    @patch("taskhound.resolver.sid_to_name.get_cache")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_from_bloodhound")
    def test_returns_cached_result(self, mock_bh, mock_cache):
        """Should return cached result if available."""
        mock_cache_instance = MagicMock()
        # Cache returns the username for "sids" category
        mock_cache_instance.get.side_effect = lambda cat, key: (
            "DOMAIN\\cacheduser" if cat == "sids" and key == "S-1-5-21-123-456-789-1001" else None
        )
        mock_cache.return_value = mock_cache_instance

        result, resolved = resolve_sid("S-1-5-21-123-456-789-1001")

        # Should format as "username (SID)"
        assert "cacheduser" in result
        assert "S-1-5-21-123-456-789-1001" in result
        mock_bh.assert_not_called()

    @patch("taskhound.resolver.sid_to_name.get_cache")
    def test_skips_after_max_failures(self, mock_cache):
        """Should skip resolution after max failures."""
        mock_cache_instance = MagicMock()
        # First get for sids returns None, second get for failures returns 3
        mock_cache_instance.get.side_effect = lambda cat, key: (
            3 if cat == "sid_failures" else None
        )
        mock_cache.return_value = mock_cache_instance

        result, resolved = resolve_sid("S-1-5-21-123-456-789-1002")

        assert "Unresolvable" in result

    @patch("taskhound.resolver.sid_to_name.get_cache")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_from_bloodhound")
    def test_tries_bloodhound_first(self, mock_bh, mock_cache):
        """Should try BloodHound data first."""
        mock_cache_instance = MagicMock()
        mock_cache_instance.get.return_value = None
        mock_cache.return_value = mock_cache_instance
        mock_bh.return_value = "bhuser"

        mock_loader = MagicMock()
        mock_loader.loaded = True

        result, resolved = resolve_sid("S-1-5-21-123-456-789-1003", hv_loader=mock_loader)

        mock_bh.assert_called_once()
        assert resolved == "bhuser"

    def test_handles_non_sid_input(self):
        """Should handle non-SID input gracefully."""
        result, resolved = resolve_sid("DOMAIN\\user")

        # Should return the input as-is since it's not a SID
        assert result == "DOMAIN\\user"


class TestFormatRunasWithSidResolution:
    """Tests for format_runas_with_sid_resolution function."""

    def test_returns_original_for_non_sid(self):
        """Should return original value for non-SID input."""
        result, resolved = format_runas_with_sid_resolution(
            "DOMAIN\\admin",
            None, None, None, False,
            None, None, None, None, None, False
        )

        assert result == "DOMAIN\\admin"
        assert resolved is None

    @patch("taskhound.resolver.sid_to_name.resolve_sid")
    def test_resolves_sid(self, mock_resolve):
        """Should resolve SID to username."""
        mock_resolve.return_value = ("resolveduser (S-1-5-21-xxx)", "resolveduser")

        result, resolved = format_runas_with_sid_resolution(
            "S-1-5-21-123456789-1001",
            None, None, None, False,
            None, None, None, None, None, False
        )

        mock_resolve.assert_called_once()
        assert resolved == "resolveduser"


class TestResolveSidEdgeCases:
    """Edge cases and error handling tests."""

    def test_handles_malformed_sid(self):
        """Should handle malformed SID gracefully."""
        result, resolved = resolve_sid("S-1-invalid")

        # Should return original since it fails is_sid check
        assert result == "S-1-invalid"

    @patch("taskhound.resolver.sid_to_name.get_cache")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_from_bloodhound")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_via_bloodhound_api")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_via_smb")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_via_ldap")
    def test_increments_failure_on_all_failures(
        self, mock_ldap, mock_smb, mock_api, mock_bh, mock_cache
    ):
        """Should increment failure count when all methods fail."""
        mock_cache_instance = MagicMock()
        mock_cache_instance.get.return_value = None
        # increment() returns the new value (1 on first call)
        mock_cache_instance.increment.return_value = 1
        mock_cache.return_value = mock_cache_instance

        mock_bh.return_value = None
        mock_api.return_value = None
        mock_smb.return_value = None
        mock_ldap.return_value = None

        resolve_sid(
            "S-1-5-21-123-456-789-1004",
            no_ldap=False,
            domain="test.local",
            username="user",
            password="pass"
        )

        # Should have called increment on sid_failures category
        mock_cache_instance.increment.assert_called_once()
        call_args = mock_cache_instance.increment.call_args
        assert call_args[0][0] == "sid_failures"  # category
        assert "S-1-5-21-123-456-789-1004" in call_args[0][1]  # key contains SID

    @patch("taskhound.resolver.sid_to_name.get_cache")
    @patch("taskhound.resolver.sid_to_name.resolve_sid_from_bloodhound")
    def test_caches_successful_resolution(self, mock_bh, mock_cache):
        """Should cache successful resolution."""
        mock_cache_instance = MagicMock()
        mock_cache_instance.get.return_value = None
        mock_cache.return_value = mock_cache_instance

        mock_bh.return_value = "DOMAIN\\found"
        mock_loader = MagicMock()
        mock_loader.loaded = True

        resolve_sid("S-1-5-21-123-456-789-1005", hv_loader=mock_loader)

        # Check that set was called with sids category
        calls = [call for call in mock_cache_instance.set.call_args_list
                 if call[0][0] == "sids"]
        assert len(calls) >= 1
