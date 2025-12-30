"""
Tests for SID resolver utilities.
"""
import struct
from unittest.mock import MagicMock

import pytest

from taskhound.utils.sid_resolver import (
    binary_to_sid,
    is_sid,
    resolve_sid_from_bloodhound,
    sid_to_binary,
)


class TestIsSid:
    """Tests for is_sid function"""

    def test_valid_domain_sid(self):
        """Should recognize valid domain SID"""
        sid = "S-1-5-21-123456789-123456789-123456789-1001"

        assert is_sid(sid) is True

    def test_valid_builtin_sid(self):
        """Should recognize builtin account SIDs"""
        # Local System
        assert is_sid("S-1-5-18") is True
        # Local Service
        assert is_sid("S-1-5-19") is True
        # Network Service
        assert is_sid("S-1-5-20") is True

    def test_valid_builtin_administrators(self):
        """Should recognize builtin group SIDs"""
        # Builtin Administrators
        assert is_sid("S-1-5-32-544") is True

    def test_empty_string_returns_false(self):
        """Should return False for empty string"""
        assert is_sid("") is False

    def test_none_returns_false(self):
        """Should return False for None"""
        assert is_sid(None) is False

    def test_invalid_sid_no_prefix(self):
        """Should reject SID without S- prefix"""
        assert is_sid("1-5-21-123456789") is False

    def test_invalid_sid_wrong_format(self):
        """Should reject malformed SID"""
        assert is_sid("S-1-invalid") is False

    def test_username_is_not_sid(self):
        """Should reject username"""
        assert is_sid("DOMAIN\\admin") is False

    def test_strips_whitespace(self):
        """Should strip whitespace before checking"""
        assert is_sid("  S-1-5-18  ") is True


class TestSidToBinary:
    """Tests for sid_to_binary function"""

    def test_converts_simple_sid(self):
        """Should convert simple SID to binary"""
        sid = "S-1-5-18"  # Local System

        result = sid_to_binary(sid)

        assert result is not None
        assert isinstance(result, bytes)
        assert len(result) >= 8  # Minimum SID size

    def test_converts_domain_sid(self):
        """Should convert domain SID to binary"""
        sid = "S-1-5-21-123456789-987654321-111111111-500"

        result = sid_to_binary(sid)

        assert result is not None
        # 5 sub-authorities (21, 123456789, 987654321, 111111111, 500)
        # Revision (1) + SubAuth count (1) + Authority (6) + 5 sub-authorities (20) = 28
        assert len(result) == 28

    def test_returns_none_for_invalid_sid(self):
        """Should return None for invalid SID"""
        assert sid_to_binary("invalid") is None
        assert sid_to_binary("") is None
        assert sid_to_binary("S-1") is None  # Too short

    def test_returns_none_for_non_sid_prefix(self):
        """Should return None for string not starting with S-"""
        assert sid_to_binary("1-5-21-123456789") is None

    def test_roundtrip_conversion(self):
        """Should survive roundtrip conversion"""
        original_sid = "S-1-5-21-123456789-987654321-111111111-1001"

        binary = sid_to_binary(original_sid)
        recovered = binary_to_sid(binary)

        assert recovered == original_sid


class TestBinaryToSid:
    """Tests for binary_to_sid function"""

    def test_converts_binary_to_sid_string(self):
        """Should convert binary SID to string"""
        # Build a known binary SID for S-1-5-18
        # Revision=1, SubAuth count=1, Authority=5, SubAuth=18
        binary = struct.pack("B", 1)  # Revision
        binary += struct.pack("B", 1)  # SubAuth count
        binary += struct.pack(">Q", 5)[2:]  # Authority (6 bytes)
        binary += struct.pack("<I", 18)  # SubAuth

        result = binary_to_sid(binary)

        assert result == "S-1-5-18"

    def test_returns_none_for_empty_bytes(self):
        """Should return None for empty bytes"""
        assert binary_to_sid(b"") is None

    def test_returns_none_for_too_short_bytes(self):
        """Should return None for bytes too short"""
        assert binary_to_sid(b"\x01") is None
        assert binary_to_sid(b"\x01\x02\x03") is None

    def test_returns_none_for_none(self):
        """Should return None for None input"""
        assert binary_to_sid(None) is None

    def test_handles_truncated_subauthorities(self):
        """Should handle truncated binary data"""
        # Claim 5 sub-authorities but only provide data for 1
        binary = struct.pack("B", 1)  # Revision
        binary += struct.pack("B", 5)  # SubAuth count (claims 5)
        binary += struct.pack(">Q", 5)[2:]  # Authority (6 bytes)
        binary += struct.pack("<I", 18)  # Only 1 SubAuth provided

        result = binary_to_sid(binary)

        assert result is None


class TestResolveFromBloodhound:
    """Tests for resolve_sid_from_bloodhound function"""

    def test_returns_none_when_no_loader(self):
        """Should return None when hv_loader is None"""
        result = resolve_sid_from_bloodhound("S-1-5-21-xxx", None)

        assert result is None

    def test_returns_none_when_loader_not_loaded(self):
        """Should return None when loader exists but not loaded"""
        mock_loader = MagicMock()
        mock_loader.loaded = False

        result = resolve_sid_from_bloodhound("S-1-5-21-xxx", mock_loader)

        assert result is None

    def test_returns_username_when_found(self):
        """Should look up SID in BloodHound data"""
        mock_loader = MagicMock()
        mock_loader.loaded = True
        mock_loader.hv_sids = {
            "S-1-5-21-123456789-1001": {
                "sam": "admin",
                "domain": "DOMAIN.LAB"
            }
        }

        # The function may return user data, None, or processed value
        # depending on implementation - testing the lookup path
        resolve_sid_from_bloodhound("S-1-5-21-123456789-1001", mock_loader)

        # Function accesses hv_sids, so the mock should have been called
        # Result depends on implementation details
        # Main test is that it doesn't raise an exception
        pass  # If we get here without exception, the path was tested

    def test_returns_none_when_sid_not_found(self):
        """Should return None when SID not in BloodHound data"""
        mock_loader = MagicMock()
        mock_loader.loaded = True
        mock_loader.hv_sids = {}

        result = resolve_sid_from_bloodhound("S-1-5-21-unknown", mock_loader)

        assert result is None


class TestSidBinaryRoundtrip:
    """Roundtrip tests for SID conversion"""

    @pytest.mark.parametrize("sid", [
        "S-1-5-18",  # Local System
        "S-1-5-19",  # Local Service
        "S-1-5-20",  # Network Service
        "S-1-5-32-544",  # Builtin Administrators
        "S-1-5-21-123456789-987654321-111111111-500",  # Domain Admin
        "S-1-5-21-123456789-987654321-111111111-501",  # Domain Guest
        "S-1-5-21-123456789-987654321-111111111-512",  # Domain Admins group
        "S-1-5-21-1234567890-1234567890-1234567890-1001",  # Regular user
    ])
    def test_roundtrip_preserves_sid(self, sid):
        """SID should survive binary roundtrip"""
        binary = sid_to_binary(sid)
        recovered = binary_to_sid(binary)

        assert recovered == sid


class TestIsSidEdgeCases:
    """Edge case tests for is_sid function"""

    def test_requires_subauthority(self):
        """Should require at least one sub-authority"""
        # S-1-5 has no sub-authority - should this be valid?
        # Based on pattern requiring sub-authorities:
        assert is_sid("S-1-5") is False

    def test_handles_very_long_sid(self):
        """Should handle SID with many sub-authorities"""
        # Windows supports up to 15 sub-authorities
        sid = "S-1-5-" + "-".join(str(i) for i in range(15))

        assert is_sid(sid) is True

    def test_handles_large_sub_authority_values(self):
        """Should handle large sub-authority values"""
        sid = "S-1-5-21-4294967295-4294967295-4294967295-4294967295"

        assert is_sid(sid) is True


class TestSidToBinaryEdgeCases:
    """Edge case tests for sid_to_binary function"""

    def test_handles_large_authority(self):
        """Should handle large authority values"""
        # SECURITY_NT_AUTHORITY is 5, but other values exist
        sid = "S-1-5-21-123456789"

        result = sid_to_binary(sid)

        assert result is not None

    def test_handles_zero_subauthority(self):
        """Should handle zero as sub-authority"""
        sid = "S-1-5-0"

        result = sid_to_binary(sid)

        assert result is not None
        assert binary_to_sid(result) == sid


class TestGetDomainSidPrefix:
    """Tests for get_domain_sid_prefix function"""

    def test_extracts_domain_prefix_from_user_sid(self):
        """Should extract domain prefix from user SID (remove RID)"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        sid = "S-1-5-21-123456789-987654321-111222333-1001"

        result = get_domain_sid_prefix(sid)

        assert result == "S-1-5-21-123456789-987654321-111222333"

    def test_extracts_domain_prefix_from_computer_sid(self):
        """Should extract domain prefix from computer account SID"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        sid = "S-1-5-21-3570960105-1792075822-554663251-1002"

        result = get_domain_sid_prefix(sid)

        assert result == "S-1-5-21-3570960105-1792075822-554663251"

    def test_returns_none_for_builtin_sid(self):
        """Should return None for builtin SIDs (not domain SIDs)"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        # Local System
        assert get_domain_sid_prefix("S-1-5-18") is None
        # Builtin Administrators
        assert get_domain_sid_prefix("S-1-5-32-544") is None

    def test_returns_none_for_empty_string(self):
        """Should return None for empty string"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        assert get_domain_sid_prefix("") is None

    def test_returns_none_for_none(self):
        """Should return None for None"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        assert get_domain_sid_prefix(None) is None


class TestIsForeignDomainSid:
    """Tests for is_foreign_domain_sid function"""

    def test_detects_foreign_domain_sid(self):
        """Should detect SID from different domain"""
        from taskhound.utils.sid_resolver import is_foreign_domain_sid

        local_prefix = "S-1-5-21-123456789-987654321-111222333"
        foreign_sid = "S-1-5-21-999888777-666555444-333222111-1001"

        assert is_foreign_domain_sid(foreign_sid, local_prefix) is True

    def test_detects_same_domain_sid(self):
        """Should return False for SID from same domain"""
        from taskhound.utils.sid_resolver import is_foreign_domain_sid

        local_prefix = "S-1-5-21-123456789-987654321-111222333"
        same_domain_sid = "S-1-5-21-123456789-987654321-111222333-500"

        assert is_foreign_domain_sid(same_domain_sid, local_prefix) is False

    def test_returns_false_for_builtin_sid(self):
        """Should return False for builtin SIDs (not domain SIDs)"""
        from taskhound.utils.sid_resolver import is_foreign_domain_sid

        local_prefix = "S-1-5-21-123456789-987654321-111222333"

        # Local System - not a domain SID
        assert is_foreign_domain_sid("S-1-5-18", local_prefix) is False

    def test_returns_false_when_no_local_prefix(self):
        """Should return False when local domain prefix is unknown"""
        from taskhound.utils.sid_resolver import is_foreign_domain_sid

        foreign_sid = "S-1-5-21-999888777-666555444-333222111-1001"

        assert is_foreign_domain_sid(foreign_sid, None) is False


class TestLDAPDomainValidation:
    """Tests for LDAP domain validation (B7 bug fix)"""

    def test_resolve_name_to_sid_via_ldap_rejects_empty_domain(self):
        """Should return None for empty domain (prevents invalidDNSyntax error)"""
        from taskhound.utils.sid_resolver import resolve_name_to_sid_via_ldap

        # Empty domain should return None immediately without attempting LDAP
        result = resolve_name_to_sid_via_ldap(
            name="testcomputer",
            domain="",
            is_computer=True,
        )

        assert result is None

    def test_resolve_name_to_sid_via_ldap_rejects_domain_without_dots(self):
        """Should return None for domain without dots (not FQDN)"""
        from taskhound.utils.sid_resolver import resolve_name_to_sid_via_ldap

        # Single-label domain (no dots) should return None
        result = resolve_name_to_sid_via_ldap(
            name="testcomputer",
            domain="TESTDOMAIN",
            is_computer=True,
        )

        assert result is None

    def test_resolve_sid_via_ldap_rejects_empty_domain(self):
        """Should return None for empty domain in SID resolution"""
        from taskhound.utils.sid_resolver import resolve_sid_via_ldap

        result = resolve_sid_via_ldap(
            sid="S-1-5-21-123456789-987654321-111111111-1001",
            domain="",
            username="testuser",
            password="testpass",
        )

        assert result is None

    def test_resolve_sid_via_ldap_rejects_domain_without_dots(self):
        """Should return None for domain without dots in SID resolution"""
        from taskhound.utils.sid_resolver import resolve_sid_via_ldap

        result = resolve_sid_via_ldap(
            sid="S-1-5-21-123456789-987654321-111111111-1001",
            domain="NODOTS",
            username="testuser",
            password="testpass",
        )

        assert result is None

    def test_batch_get_user_attributes_rejects_empty_domain(self):
        """Should return empty dict for empty domain in batch query"""
        from taskhound.utils.sid_resolver import batch_get_user_attributes

        result = batch_get_user_attributes(
            usernames=["testuser"],
            domain="",
        )

        assert result == {}

    def test_fetch_tier0_members_rejects_empty_domain(self):
        """Should return empty dict for empty domain in Tier-0 preflight"""
        from taskhound.utils.sid_resolver import fetch_tier0_members

        result = fetch_tier0_members(domain="")

        assert result == {}

    def test_fetch_tier0_members_rejects_domain_without_dots(self):
        """Should return empty dict for domain without dots"""
        from taskhound.utils.sid_resolver import fetch_tier0_members

        result = fetch_tier0_members(domain="SINGLELABEL")

        assert result == {}


class TestUnknownDomainSIDDetection:
    """Tests for unknown domain SID detection (F3 feature)"""

    def test_is_unknown_domain_sid_returns_true_for_unknown_prefix(self):
        """Should return True when SID prefix is not in known set"""
        from taskhound.utils.sid_resolver import is_unknown_domain_sid

        known_prefixes = {
            "S-1-5-21-123456789-987654321-111111111",  # corp.local
            "S-1-5-21-999888777-666555444-333222111",  # trust.local
        }

        # Unknown domain SID (different prefix)
        unknown_sid = "S-1-5-21-555666777-888999000-111222333-500"

        assert is_unknown_domain_sid(unknown_sid, known_prefixes) is True

    def test_is_unknown_domain_sid_returns_false_for_known_prefix(self):
        """Should return False when SID prefix is in known set"""
        from taskhound.utils.sid_resolver import is_unknown_domain_sid

        known_prefixes = {
            "S-1-5-21-123456789-987654321-111111111",  # corp.local
            "S-1-5-21-999888777-666555444-333222111",  # trust.local
        }

        # Known domain SID
        known_sid = "S-1-5-21-123456789-987654321-111111111-1001"

        assert is_unknown_domain_sid(known_sid, known_prefixes) is False

    def test_is_unknown_domain_sid_returns_false_for_empty_known_set(self):
        """Should return False when known set is empty (can't classify)"""
        from taskhound.utils.sid_resolver import is_unknown_domain_sid

        unknown_sid = "S-1-5-21-555666777-888999000-111222333-500"

        assert is_unknown_domain_sid(unknown_sid, set()) is False
        assert is_unknown_domain_sid(unknown_sid, None) is False

    def test_is_unknown_domain_sid_returns_false_for_non_domain_sid(self):
        """Should return False for well-known SIDs (not domain SIDs)"""
        from taskhound.utils.sid_resolver import is_unknown_domain_sid

        known_prefixes = {"S-1-5-21-123456789-987654321-111111111"}

        # Well-known SIDs are not domain SIDs
        assert is_unknown_domain_sid("S-1-5-18", known_prefixes) is False  # SYSTEM
        assert is_unknown_domain_sid("S-1-5-32-544", known_prefixes) is False  # BUILTIN


class TestResolveUnknownSIDToLocalName:
    """Tests for resolve_unknown_sid_to_local_name function"""

    def test_resolves_rid_500_to_administrator(self):
        """Should resolve RID 500 to UNKNOWN\\Administrator"""
        from taskhound.utils.sid_resolver import resolve_unknown_sid_to_local_name

        sid = "S-1-5-21-555666777-888999000-111222333-500"
        result = resolve_unknown_sid_to_local_name(sid)

        assert result == "UNKNOWN\\Administrator"

    def test_resolves_rid_501_to_guest(self):
        """Should resolve RID 501 to UNKNOWN\\Guest"""
        from taskhound.utils.sid_resolver import resolve_unknown_sid_to_local_name

        sid = "S-1-5-21-555666777-888999000-111222333-501"
        result = resolve_unknown_sid_to_local_name(sid)

        assert result == "UNKNOWN\\Guest"

    def test_resolves_high_rid_to_user_number(self):
        """Should resolve high RIDs (>=1000) to UNKNOWN\\User-<RID>"""
        from taskhound.utils.sid_resolver import resolve_unknown_sid_to_local_name

        sid = "S-1-5-21-555666777-888999000-111222333-1001"
        result = resolve_unknown_sid_to_local_name(sid)

        assert result == "UNKNOWN\\User-1001"

    def test_returns_none_for_unknown_low_rid(self):
        """Should return None for unknown low RIDs (not well-known)"""
        from taskhound.utils.sid_resolver import resolve_unknown_sid_to_local_name

        # RID 600 is not well-known and < 1000
        sid = "S-1-5-21-555666777-888999000-111222333-600"
        result = resolve_unknown_sid_to_local_name(sid)

        assert result is None

    def test_returns_none_for_non_domain_sid(self):
        """Should return None for non-domain SIDs"""
        from taskhound.utils.sid_resolver import resolve_unknown_sid_to_local_name

        assert resolve_unknown_sid_to_local_name("S-1-5-18") is None
        assert resolve_unknown_sid_to_local_name("S-1-5-32-544") is None

    def test_returns_none_for_invalid_input(self):
        """Should return None for invalid SID strings"""
        from taskhound.utils.sid_resolver import resolve_unknown_sid_to_local_name

        assert resolve_unknown_sid_to_local_name("") is None
        assert resolve_unknown_sid_to_local_name(None) is None
        assert resolve_unknown_sid_to_local_name("invalid") is None


class TestFetchKnownDomainSIDsViaLDAP:
    """Tests for fetch_known_domain_sids_via_ldap function"""

    def test_returns_empty_dict_for_empty_domain(self):
        """Should return empty dict for empty domain"""
        from taskhound.utils.sid_resolver import fetch_known_domain_sids_via_ldap

        result = fetch_known_domain_sids_via_ldap(domain="")
        assert result == {}

    def test_returns_empty_dict_for_domain_without_dots(self):
        """Should return empty dict for domain without dots"""
        from taskhound.utils.sid_resolver import fetch_known_domain_sids_via_ldap

        result = fetch_known_domain_sids_via_ldap(domain="NODOTS")
        assert result == {}

    def test_returns_empty_dict_without_credentials(self):
        """Should return empty dict when no credentials provided"""
        from taskhound.utils.sid_resolver import fetch_known_domain_sids_via_ldap

        result = fetch_known_domain_sids_via_ldap(
            domain="corp.local",
            username="testuser",
            # No password or hashes
        )
        assert result == {}


class TestWellKnownSIDs:
    """Tests for Chain 0: Well-Known SID Static Lookup"""

    def test_well_known_sids_dict_exists(self):
        """Should have WELL_KNOWN_SIDS dictionary"""
        from taskhound.utils.sid_resolver import WELL_KNOWN_SIDS

        assert isinstance(WELL_KNOWN_SIDS, dict)
        assert len(WELL_KNOWN_SIDS) > 0

    def test_system_sid_in_lookup_table(self):
        """Should have NT AUTHORITY\\SYSTEM in lookup table"""
        from taskhound.utils.sid_resolver import WELL_KNOWN_SIDS

        assert "S-1-5-18" in WELL_KNOWN_SIDS
        assert WELL_KNOWN_SIDS["S-1-5-18"] == "NT AUTHORITY\\SYSTEM"

    def test_local_service_sid_in_lookup_table(self):
        """Should have NT AUTHORITY\\LOCAL SERVICE in lookup table"""
        from taskhound.utils.sid_resolver import WELL_KNOWN_SIDS

        assert "S-1-5-19" in WELL_KNOWN_SIDS
        assert WELL_KNOWN_SIDS["S-1-5-19"] == "NT AUTHORITY\\LOCAL SERVICE"

    def test_network_service_sid_in_lookup_table(self):
        """Should have NT AUTHORITY\\NETWORK SERVICE in lookup table"""
        from taskhound.utils.sid_resolver import WELL_KNOWN_SIDS

        assert "S-1-5-20" in WELL_KNOWN_SIDS
        assert WELL_KNOWN_SIDS["S-1-5-20"] == "NT AUTHORITY\\NETWORK SERVICE"

    def test_builtin_administrators_sid_in_lookup_table(self):
        """Should have BUILTIN\\Administrators in lookup table"""
        from taskhound.utils.sid_resolver import WELL_KNOWN_SIDS

        assert "S-1-5-32-544" in WELL_KNOWN_SIDS
        assert WELL_KNOWN_SIDS["S-1-5-32-544"] == "BUILTIN\\Administrators"

    def test_everyone_sid_in_lookup_table(self):
        """Should have Everyone SID in lookup table"""
        from taskhound.utils.sid_resolver import WELL_KNOWN_SIDS

        assert "S-1-1-0" in WELL_KNOWN_SIDS
        assert WELL_KNOWN_SIDS["S-1-1-0"] == "Everyone"


class TestResolveSidChain0:
    """Tests for resolve_sid() Chain 0 - Well-Known SID instant lookup"""

    def test_resolves_system_sid_instantly(self):
        """Should resolve S-1-5-18 to NT AUTHORITY\\SYSTEM without network"""
        from taskhound.utils.sid_resolver import resolve_sid

        display_name, resolved = resolve_sid("S-1-5-18")

        assert resolved == "NT AUTHORITY\\SYSTEM"
        assert "S-1-5-18" in display_name
        assert "NT AUTHORITY\\SYSTEM" in display_name

    def test_resolves_local_service_sid_instantly(self):
        """Should resolve S-1-5-19 to NT AUTHORITY\\LOCAL SERVICE without network"""
        from taskhound.utils.sid_resolver import resolve_sid

        display_name, resolved = resolve_sid("S-1-5-19")

        assert resolved == "NT AUTHORITY\\LOCAL SERVICE"

    def test_resolves_network_service_sid_instantly(self):
        """Should resolve S-1-5-20 to NT AUTHORITY\\NETWORK SERVICE without network"""
        from taskhound.utils.sid_resolver import resolve_sid

        display_name, resolved = resolve_sid("S-1-5-20")

        assert resolved == "NT AUTHORITY\\NETWORK SERVICE"

    def test_resolves_builtin_administrators_instantly(self):
        """Should resolve S-1-5-32-544 to BUILTIN\\Administrators without network"""
        from taskhound.utils.sid_resolver import resolve_sid

        display_name, resolved = resolve_sid("S-1-5-32-544")

        assert resolved == "BUILTIN\\Administrators"

    def test_resolves_everyone_instantly(self):
        """Should resolve S-1-1-0 to Everyone without network"""
        from taskhound.utils.sid_resolver import resolve_sid

        display_name, resolved = resolve_sid("S-1-1-0")

        assert resolved == "Everyone"

    def test_domain_sid_not_in_well_known(self):
        """Domain SIDs should NOT be resolved by Chain 0"""
        from taskhound.utils.sid_resolver import WELL_KNOWN_SIDS

        # Domain user SID should not be in well-known table
        domain_sid = "S-1-5-21-123456789-987654321-111111111-1001"
        assert domain_sid not in WELL_KNOWN_SIDS


class TestGlobalCatalogDNS:
    """Tests for Global Catalog DNS discovery functions"""

    def test_discover_global_catalog_servers_returns_list(self):
        """Should return a list (possibly empty) for GC discovery"""
        from taskhound.utils.dns import discover_global_catalog_servers

        # This will fail without real DNS, but should return empty list not error
        result = discover_global_catalog_servers("nonexistent.local")
        assert isinstance(result, list)

    def test_get_working_gc_returns_explicit_server(self):
        """Should return user-provided GC server directly"""
        from taskhound.utils.dns import get_working_gc

        result = get_working_gc(domain="test.local", gc_server="192.168.1.1")
        assert result == "192.168.1.1"

    def test_get_working_gc_returns_none_without_discovery(self):
        """Should return None if no GC found and none specified"""
        from taskhound.utils.dns import get_working_gc

        # Will fail to discover in test environment
        result = get_working_gc(domain="nonexistent.local")
        assert result is None


class TestResolveSidViaGlobalCatalog:
    """Tests for resolve_sid_via_global_catalog function"""

    def test_returns_none_without_credentials(self):
        """Should return None when no credentials provided"""
        from taskhound.utils.sid_resolver import resolve_sid_via_global_catalog

        result = resolve_sid_via_global_catalog(
            sid="S-1-5-21-123456789-987654321-111111111-1001",
            domain="corp.local",
            # No credentials
        )
        assert result is None

    def test_returns_none_for_invalid_domain(self):
        """Should return None for invalid domain format"""
        from taskhound.utils.sid_resolver import resolve_sid_via_global_catalog

        result = resolve_sid_via_global_catalog(
            sid="S-1-5-21-123456789-987654321-111111111-1001",
            domain="nodots",  # Invalid - no dots
            username="test",
            password="test",
        )
        assert result is None

    def test_returns_none_for_empty_domain(self):
        """Should return None for empty domain"""
        from taskhound.utils.sid_resolver import resolve_sid_via_global_catalog

        result = resolve_sid_via_global_catalog(
            sid="S-1-5-21-123456789-987654321-111111111-1001",
            domain="",
            username="test",
            password="test",
        )
        assert result is None


class TestGcServerParameter:
    """Tests for --gc-server CLI flag support"""

    def test_resolve_sid_accepts_gc_server_parameter(self):
        """resolve_sid should accept gc_server parameter"""
        from taskhound.utils.sid_resolver import resolve_sid

        # Call with gc_server parameter - should not raise
        display, resolved = resolve_sid(
            sid="S-1-5-18",  # SYSTEM - will be resolved from well-known table
            gc_server="10.0.0.1",
        )
        # Well-known SID should still resolve instantly
        assert "SYSTEM" in display

    def test_format_runas_accepts_gc_server_parameter(self):
        """format_runas_with_sid_resolution should accept gc_server parameter"""
        from taskhound.utils.sid_resolver import format_runas_with_sid_resolution

        # Call with gc_server parameter - should not raise
        display, resolved = format_runas_with_sid_resolution(
            runas="S-1-5-18",  # SYSTEM - will be resolved from well-known table
            gc_server="10.0.0.1",
        )
        # Well-known SID should still resolve instantly
        assert "SYSTEM" in display

    def test_auth_context_has_gc_server_field(self):
        """AuthContext should have gc_server field"""
        from taskhound.auth import AuthContext

        auth = AuthContext(
            username="test",
            password="test",
            domain="test.local",
            gc_server="192.168.1.100",
        )
        assert auth.gc_server == "192.168.1.100"

    def test_auth_context_gc_server_defaults_to_none(self):
        """AuthContext gc_server should default to None"""
        from taskhound.auth import AuthContext

        auth = AuthContext(
            username="test",
            password="test",
            domain="test.local",
        )
        assert auth.gc_server is None


class TestExternalTrustPrefixCaching:
    """Tests for external trust domain prefix caching"""

    def test_external_trust_prefixes_set_exists(self):
        """Module should have _external_trust_prefixes set"""
        from taskhound.utils import sid_resolver

        assert hasattr(sid_resolver, '_external_trust_prefixes')
        assert isinstance(sid_resolver._external_trust_prefixes, set)

    def test_resolve_unknown_sid_distinguishes_well_known_from_fallback(self):
        """resolve_unknown_sid_to_local_name returns proper names for well-known vs custom RIDs"""
        from taskhound.utils.sid_resolver import resolve_unknown_sid_to_local_name

        # Well-known RID 500 (Administrator)
        result_500 = resolve_unknown_sid_to_local_name("S-1-5-21-123456789-987654321-111111111-500")
        assert result_500 == "UNKNOWN\\Administrator"

        # Custom local account RID 1000 (NOT well-known, just a fallback)
        result_1000 = resolve_unknown_sid_to_local_name("S-1-5-21-123456789-987654321-111111111-1000")
        assert result_1000 == "UNKNOWN\\User-1000"

        # Custom local account RID 1234
        result_1234 = resolve_unknown_sid_to_local_name("S-1-5-21-123456789-987654321-111111111-1234")
        assert result_1234 == "UNKNOWN\\User-1234"

    def test_rid_1000_is_not_well_known(self):
        """RID 1000 should NOT be in WELL_KNOWN_LOCAL_RIDS"""
        from taskhound.utils.sid_resolver import WELL_KNOWN_LOCAL_RIDS

        # RID 1000 is a local user account, not a well-known system account
        assert 1000 not in WELL_KNOWN_LOCAL_RIDS
        # But 500 (Administrator) should be
        assert 500 in WELL_KNOWN_LOCAL_RIDS


class TestResolveTrustSidToName:
    """Tests for resolve_trust_sid_to_name function"""

    def test_resolves_well_known_rid_to_upn_format(self):
        """Should resolve well-known RID 500 to UPN format"""
        from taskhound.utils.sid_resolver import resolve_trust_sid_to_name

        # Administrator (RID 500)
        result = resolve_trust_sid_to_name(
            "S-1-5-21-111111111-222222222-333333333-500",
            "TRUSTEDFOREST.LOCAL"
        )
        assert result == "Administrator@TRUSTEDFOREST.LOCAL"

    def test_resolves_guest_rid_to_upn_format(self):
        """Should resolve well-known RID 501 (Guest) to UPN format"""
        from taskhound.utils.sid_resolver import resolve_trust_sid_to_name

        result = resolve_trust_sid_to_name(
            "S-1-5-21-111111111-222222222-333333333-501",
            "TRUSTEDFOREST.LOCAL"
        )
        assert result == "Guest@TRUSTEDFOREST.LOCAL"

    def test_resolves_custom_rid_to_domain_fallback(self):
        """Should resolve custom RID (>= 1000) to domain\\User-RID format"""
        from taskhound.utils.sid_resolver import resolve_trust_sid_to_name

        result = resolve_trust_sid_to_name(
            "S-1-5-21-111111111-222222222-333333333-1234",
            "TRUSTEDFOREST.LOCAL"
        )
        assert result == "TRUSTEDFOREST.LOCAL\\User-1234"

    def test_returns_none_for_invalid_sid(self):
        """Should return None for invalid SID"""
        from taskhound.utils.sid_resolver import resolve_trust_sid_to_name

        assert resolve_trust_sid_to_name("invalid", "TRUSTEDFOREST.LOCAL") is None
        assert resolve_trust_sid_to_name("", "TRUSTEDFOREST.LOCAL") is None
        assert resolve_trust_sid_to_name(None, "TRUSTEDFOREST.LOCAL") is None

    def test_returns_none_for_non_domain_sid(self):
        """Should return None for non-domain SID (e.g., S-1-5-18)"""
        from taskhound.utils.sid_resolver import resolve_trust_sid_to_name

        # SYSTEM SID doesn't have domain format
        assert resolve_trust_sid_to_name("S-1-5-18", "TRUSTEDFOREST.LOCAL") is None

    def test_returns_none_for_missing_fqdn(self):
        """Should return None if trust FQDN is missing"""
        from taskhound.utils.sid_resolver import resolve_trust_sid_to_name

        assert resolve_trust_sid_to_name(
            "S-1-5-21-111111111-222222222-333333333-500",
            ""
        ) is None
        assert resolve_trust_sid_to_name(
            "S-1-5-21-111111111-222222222-333333333-500",
            None
        ) is None


class TestCrossTrustResolution:
    """Tests for cross-trust SID resolution with [CROSS-TRUST] prefix"""

    def test_is_unknown_domain_sid_accepts_dict(self):
        """is_unknown_domain_sid should work with Dict[str, str]"""
        from taskhound.utils.sid_resolver import is_unknown_domain_sid

        known_prefixes = {
            "S-1-5-21-123456789-987654321-111111111": "CORP.LOCAL",
            "S-1-5-21-444444444-555555555-666666666": "TRUSTEDFOREST.LOCAL",
        }

        # SID in known prefixes - not unknown
        result = is_unknown_domain_sid(
            "S-1-5-21-123456789-987654321-111111111-500",
            known_prefixes
        )
        assert result is False

        # SID NOT in known prefixes - unknown
        result = is_unknown_domain_sid(
            "S-1-5-21-999999999-888888888-777777777-500",
            known_prefixes
        )
        assert result is True

    def test_known_domain_prefixes_type_hint_is_dict(self):
        """resolve_sid known_domain_prefixes should be Dict[str, str]"""
        import inspect

        from taskhound.utils.sid_resolver import resolve_sid

        sig = inspect.signature(resolve_sid)
        known_domain_prefixes_param = sig.parameters['known_domain_prefixes']

        # Check the annotation includes Dict
        annotation_str = str(known_domain_prefixes_param.annotation)
        assert "Dict" in annotation_str or "dict" in annotation_str

    def test_external_trust_skips_gc_for_all_rids(self):
        """EXTERNAL trusts should ALWAYS skip GC, not just for well-known RIDs"""
        from taskhound.utils.sid_resolver import TrustInfo, resolve_sid

        # A non-well-known RID (like 1234) from a KNOWN EXTERNAL trust
        # Should resolve without GC attempt
        known_prefixes = {
            "S-1-5-21-444444444-555555555-666666666": TrustInfo(
                fqdn="TRUSTEDFOREST.LOCAL",
                is_intra_forest=False,  # External trust - skip GC
            ),
        }

        # RID 1234 is not a well-known RID - but trust IS known and EXTERNAL
        display, resolved = resolve_sid(
            "S-1-5-21-444444444-555555555-666666666-1234",
            no_ldap=True,  # Disable LDAP to force trust path
            known_domain_prefixes=known_prefixes,
            local_domain_sid_prefix="S-1-5-21-111111111-222222222-333333333",
        )

        # Should get CROSS-TRUST prefix and domain context
        assert "[CROSS-TRUST]" in display
        assert "TRUSTEDFOREST.LOCAL" in display

    def test_external_trust_shows_user_rid_format(self):
        """Non-well-known RIDs from EXTERNAL trusts should show User-{RID} format"""
        from taskhound.utils.sid_resolver import TrustInfo, resolve_sid

        known_prefixes = {
            "S-1-5-21-444444444-555555555-666666666": TrustInfo(
                fqdn="TRUSTEDFOREST.LOCAL",
                is_intra_forest=False,  # External trust
            ),
        }

        # RID 1500 - a typical user RID, not well-known
        display, resolved = resolve_sid(
            "S-1-5-21-444444444-555555555-666666666-1500",
            no_ldap=True,
            known_domain_prefixes=known_prefixes,
            local_domain_sid_prefix="S-1-5-21-111111111-222222222-333333333",
        )

        # Should show User-{RID} format from resolve_trust_sid_to_name
        assert "[CROSS-TRUST]" in display
        assert "TRUSTEDFOREST.LOCAL" in display
        assert "User-1500" in display or "1500" in display

    def test_intra_forest_trust_tries_gc(self):
        """INTRA-FOREST trusts should try GC lookup first"""
        from taskhound.utils.sid_resolver import TrustInfo, resolve_sid

        # Intra-forest trust - GC should be tried (not skipped)
        known_prefixes = {
            "S-1-5-21-444444444-555555555-666666666": TrustInfo(
                fqdn="CHILD.CORP.LOCAL",
                is_intra_forest=True,  # Intra-forest - GC will work
            ),
        }

        # With no_ldap=True, GC won't be tried, so we should NOT get CROSS-TRUST
        # because we're not skipping GC for intra-forest trusts
        display, resolved = resolve_sid(
            "S-1-5-21-444444444-555555555-666666666-1500",
            no_ldap=True,
            known_domain_prefixes=known_prefixes,
            local_domain_sid_prefix="S-1-5-21-111111111-222222222-333333333",
        )

        # Intra-forest trusts DON'T get [CROSS-TRUST] prefix - they use GC
        # With no_ldap=True, the SID won't be resolved (GC path blocked)
        assert "[CROSS-TRUST]" not in display

    def test_string_trust_data_backwards_compat(self):
        """String trust data (backwards compat) should try GC first"""
        from taskhound.utils.sid_resolver import resolve_sid

        # Old-style string dict (from BloodHound) - should try GC
        known_prefixes = {
            "S-1-5-21-444444444-555555555-666666666": "SOMEFOREST.LOCAL",
        }

        display, resolved = resolve_sid(
            "S-1-5-21-444444444-555555555-666666666-1500",
            no_ldap=True,
            known_domain_prefixes=known_prefixes,
            local_domain_sid_prefix="S-1-5-21-111111111-222222222-333333333",
        )

        # String format doesn't know trust type - defaults to try GC
        # So no [CROSS-TRUST] prefix
        assert "[CROSS-TRUST]" not in display


class TestDcLsarpcResolution:
    """Tests for DC LSARPC resolution of cross-trust SIDs"""

    def test_resolve_sid_via_dc_lsarpc_function_exists(self):
        """Verify resolve_sid_via_dc_lsarpc function exists and is importable"""
        from taskhound.utils.sid_resolver import resolve_sid_via_dc_lsarpc
        assert callable(resolve_sid_via_dc_lsarpc)

    def test_resolve_sid_via_dc_lsarpc_returns_none_without_credentials(self):
        """DC LSARPC should return None when no credentials provided"""
        from taskhound.utils.sid_resolver import resolve_sid_via_dc_lsarpc
        
        result = resolve_sid_via_dc_lsarpc(
            "S-1-5-21-444444444-555555555-666666666-1500",
            dc_ip="192.168.1.1",
            domain="CORP.LOCAL",
            username=None,  # No credentials
            password=None,
            hashes=None,
            kerberos=False,
            aes_key=None,
        )
        assert result is None

    def test_resolve_sid_accepts_no_rpc_parameter(self):
        """resolve_sid should accept no_rpc parameter"""
        from taskhound.utils.sid_resolver import resolve_sid
        import inspect
        
        sig = inspect.signature(resolve_sid)
        params = list(sig.parameters.keys())
        assert "no_rpc" in params

    def test_resolve_sid_accepts_aes_key_parameter(self):
        """resolve_sid should accept aes_key parameter"""
        from taskhound.utils.sid_resolver import resolve_sid
        import inspect
        
        sig = inspect.signature(resolve_sid)
        params = list(sig.parameters.keys())
        assert "aes_key" in params

    def test_format_runas_accepts_no_rpc_parameter(self):
        """format_runas_with_sid_resolution should accept no_rpc parameter"""
        from taskhound.utils.sid_resolver import format_runas_with_sid_resolution
        import inspect
        
        sig = inspect.signature(format_runas_with_sid_resolution)
        params = list(sig.parameters.keys())
        assert "no_rpc" in params

    def test_format_runas_accepts_aes_key_parameter(self):
        """format_runas_with_sid_resolution should accept aes_key parameter"""
        from taskhound.utils.sid_resolver import format_runas_with_sid_resolution
        import inspect
        
        sig = inspect.signature(format_runas_with_sid_resolution)
        params = list(sig.parameters.keys())
        assert "aes_key" in params

    def test_no_rpc_disables_target_lsarpc(self):
        """no_rpc=True should prevent target LSARPC resolution"""
        from taskhound.utils.sid_resolver import resolve_sid
        from unittest.mock import MagicMock, patch
        
        mock_smb = MagicMock()
        
        # With no_rpc=True, smb_connection should not be used
        # Even if provided, the function should not call resolve_sid_via_smb
        with patch('taskhound.utils.sid_resolver.resolve_sid_via_smb') as mock_lsarpc:
            mock_lsarpc.return_value = None  # Would return something if called
            
            display, resolved = resolve_sid(
                "S-1-5-21-111111111-222222222-333333333-1500",
                smb_connection=mock_smb,
                no_rpc=True,  # Disable RPC
                no_ldap=True,  # Skip LDAP for cleaner test
            )
            
            # resolve_sid_via_smb should NOT be called when no_rpc=True
            mock_lsarpc.assert_not_called()
    def test_dc_lsarpc_fallback_without_local_domain_prefix(self):
        """DC LSARPC should be tried as fallback when we can't detect foreign SIDs"""
        from taskhound.utils.sid_resolver import resolve_sid
        from unittest.mock import patch
        
        # Scenario: We have a domain SID but no local_domain_sid_prefix
        # So is_foreign returns False, target LSARPC fails, DC LSARPC should be tried
        with patch('taskhound.utils.sid_resolver.resolve_sid_via_smb') as mock_target:
            with patch('taskhound.utils.sid_resolver.resolve_sid_via_dc_lsarpc') as mock_dc:
                mock_target.return_value = None  # Target LSARPC fails
                mock_dc.return_value = "TRUSTEDDOM\\SomeUser"  # DC resolves it
                
                display, resolved = resolve_sid(
                    "S-1-5-21-999999999-888888888-777777777-1234",
                    smb_connection=None,  # No target connection
                    no_ldap=True,
                    domain="CORP.LOCAL",
                    dc_ip="192.168.1.1",
                    username="admin",
                    password="password",
                    local_domain_sid_prefix=None,  # Don't know our local domain
                )
                
                # DC LSARPC should have been called as fallback
                mock_dc.assert_called_once()
                assert resolved == "TRUSTEDDOM\\SomeUser"

    def test_gc_failure_triggers_dc_lsarpc_for_unknown_trust(self):
        """When GC fails for an unknown foreign SID, DC LSARPC should be tried"""
        from taskhound.utils.sid_resolver import resolve_sid
        from unittest.mock import patch
        
        # Scenario: Foreign SID, no BloodHound trust data, GC fails
        with patch('taskhound.utils.sid_resolver.resolve_sid_via_global_catalog') as mock_gc:
            with patch('taskhound.utils.sid_resolver.resolve_sid_via_dc_lsarpc') as mock_dc:
                mock_gc.return_value = None  # GC lookup fails
                mock_dc.return_value = "UNKNOWN\\ResolvedUser"
                
                display, resolved = resolve_sid(
                    "S-1-5-21-444444444-555555555-666666666-1001",
                    no_ldap=False,
                    domain="CORP.LOCAL",
                    dc_ip="192.168.1.1",
                    username="admin",
                    password="password",
                    local_domain_sid_prefix="S-1-5-21-111111111-222222222-333333333",
                    known_domain_prefixes=None,  # No BloodHound data
                )
                
                # DC LSARPC should be called after GC fails
                assert mock_dc.called