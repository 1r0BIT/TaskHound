"""
Test suite for additional helper utilities.

Tests cover:
- is_ipv4 function
- parse_ntlm_hashes function
- normalize_targets function (including CIDR expansion)
- expand_cidr function
- is_cidr function
- sanitize_json_string function
"""

import pytest

from taskhound.utils.helpers import (
    expand_cidr,
    is_cidr,
    is_ipv4,
    normalize_targets,
    parse_ntlm_hashes,
    sanitize_json_string,
)

# ============================================================================
# Test: is_ipv4
# ============================================================================


class TestIsIpv4:
    """Tests for is_ipv4 function"""

    def test_valid_ipv4(self):
        """Should return True for valid IPv4 addresses"""
        assert is_ipv4("192.168.1.1") is True
        assert is_ipv4("10.0.0.1") is True
        assert is_ipv4("172.16.0.1") is True

    def test_edge_case_ips(self):
        """Should handle edge case IPs"""
        assert is_ipv4("0.0.0.0") is True
        assert is_ipv4("255.255.255.255") is True

    def test_invalid_octets(self):
        """Should return False for invalid octet values"""
        assert is_ipv4("256.1.1.1") is False
        assert is_ipv4("1.1.1.256") is False
        assert is_ipv4("-1.1.1.1") is False

    def test_wrong_format(self):
        """Should return False for wrong format"""
        assert is_ipv4("192.168.1") is False  # Missing octet
        assert is_ipv4("192.168.1.1.1") is False  # Extra octet
        assert is_ipv4("192.168.1.") is False  # Trailing dot

    def test_non_numeric(self):
        """Should return False for non-numeric values"""
        assert is_ipv4("hostname.domain.local") is False
        assert is_ipv4("192.168.a.1") is False

    def test_with_whitespace(self):
        """Should handle leading/trailing whitespace"""
        assert is_ipv4("  192.168.1.1  ") is True


# ============================================================================
# Test: parse_ntlm_hashes
# ============================================================================


class TestParseNtlmHashes:
    """Tests for parse_ntlm_hashes function"""

    def test_none_input(self):
        """Should return empty strings for None"""
        lm, nt = parse_ntlm_hashes(None)
        assert lm == ""
        assert nt == ""

    def test_empty_string(self):
        """Should return empty strings for empty string"""
        lm, nt = parse_ntlm_hashes("")
        assert lm == ""
        assert nt == ""

    def test_lm_nt_format(self):
        """Should parse LM:NT format"""
        lm, nt = parse_ntlm_hashes("aad3b435b51404ee:31d6cfe0d16ae931")
        assert lm == "aad3b435b51404ee"
        assert nt == "31d6cfe0d16ae931"

    def test_nt_only_format(self):
        """Should handle NT hash only (no colon)"""
        lm, nt = parse_ntlm_hashes("31d6cfe0d16ae931b73c59d7e0c089c0")
        assert lm == ""
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_empty_lm_with_colon(self):
        """Should handle empty LM with colon prefix"""
        lm, nt = parse_ntlm_hashes(":31d6cfe0d16ae931b73c59d7e0c089c0")
        assert lm == ""
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"


# ============================================================================
# Test: normalize_targets
# ============================================================================


class TestNormalizeTargets:
    """Tests for normalize_targets function"""

    def test_keeps_ips(self):
        """Should keep IP addresses unchanged"""
        targets = ["192.168.1.1", "10.0.0.1"]

        result = normalize_targets(targets, "example.com")

        assert result == ["192.168.1.1", "10.0.0.1"]

    def test_appends_domain_to_short_hostnames(self):
        """Should append domain to short hostnames"""
        targets = ["DC01", "WS01"]

        result = normalize_targets(targets, "example.com")

        assert result == ["DC01.example.com", "WS01.example.com"]

    def test_keeps_fqdns(self):
        """Should keep FQDNs unchanged"""
        targets = ["DC01.corp.local", "WS01.example.com"]

        result = normalize_targets(targets, "example.com")

        assert result == ["DC01.corp.local", "WS01.example.com"]

    def test_ignores_empty_lines(self):
        """Should ignore empty lines"""
        targets = ["DC01", "", "  ", "WS01"]

        result = normalize_targets(targets, "example.com")

        assert result == ["DC01.example.com", "WS01.example.com"]

    def test_strips_whitespace(self):
        """Should strip whitespace from targets"""
        targets = ["  DC01  ", "  192.168.1.1  "]

        result = normalize_targets(targets, "example.com")

        assert result == ["DC01.example.com", "192.168.1.1"]

    def test_mixed_targets(self):
        """Should handle mixed IPs, short names, and FQDNs"""
        targets = ["192.168.1.1", "DC01", "WS01.corp.local"]

        result = normalize_targets(targets, "example.com")

        assert result == ["192.168.1.1", "DC01.example.com", "WS01.corp.local"]

    def test_empty_list(self):
        """Should return empty list for empty input"""
        result = normalize_targets([], "example.com")

        assert result == []

    def test_cidr_expansion(self):
        """Should expand CIDR notation to individual IPs"""
        targets = ["192.168.1.0/30"]

        result = normalize_targets(targets, "example.com")

        # /30 has 4 IPs, but .hosts() excludes network (.0) and broadcast (.3)
        assert result == ["192.168.1.1", "192.168.1.2"]

    def test_cidr_with_mixed_targets(self):
        """Should handle CIDR mixed with other target types"""
        targets = ["10.0.0.0/30", "DC01", "192.168.1.100"]

        result = normalize_targets(targets, "example.com")

        assert result == ["10.0.0.1", "10.0.0.2", "DC01.example.com", "192.168.1.100"]

    def test_cidr_single_host(self):
        """Should handle /32 single host CIDR"""
        targets = ["192.168.1.50/32"]

        result = normalize_targets(targets, "example.com")

        assert result == ["192.168.1.50"]


# ============================================================================
# Test: expand_cidr
# ============================================================================


class TestExpandCidr:
    """Tests for expand_cidr function"""

    def test_slash_24(self):
        """Should expand /24 to 254 hosts"""
        result = expand_cidr("192.168.1.0/24")

        assert len(result) == 254
        assert result[0] == "192.168.1.1"
        assert result[-1] == "192.168.1.254"

    def test_slash_30(self):
        """Should expand /30 to 2 hosts"""
        result = expand_cidr("10.0.0.0/30")

        assert result == ["10.0.0.1", "10.0.0.2"]

    def test_slash_31(self):
        """Should expand /31 point-to-point"""
        result = expand_cidr("10.0.0.0/31")

        assert result == ["10.0.0.0", "10.0.0.1"]

    def test_slash_32(self):
        """Should expand /32 single host"""
        result = expand_cidr("192.168.1.100/32")

        assert result == ["192.168.1.100"]

    def test_invalid_cidr_raises(self):
        """Should raise ValueError for invalid CIDR"""
        with pytest.raises(ValueError):
            expand_cidr("not-a-cidr")

    def test_invalid_prefix_raises(self):
        """Should raise ValueError for invalid prefix"""
        with pytest.raises(ValueError):
            expand_cidr("192.168.1.0/33")


# ============================================================================
# Test: is_cidr
# ============================================================================


class TestIsCidr:
    """Tests for is_cidr function"""

    def test_valid_cidr(self):
        """Should return True for valid CIDR notation"""
        assert is_cidr("192.168.1.0/24") is True
        assert is_cidr("10.0.0.0/8") is True
        assert is_cidr("172.16.0.0/16") is True

    def test_single_host_cidr(self):
        """Should return True for /32 single host"""
        assert is_cidr("192.168.1.1/32") is True

    def test_plain_ip_not_cidr(self):
        """Should return False for plain IP address"""
        assert is_cidr("192.168.1.1") is False

    def test_hostname_not_cidr(self):
        """Should return False for hostname"""
        assert is_cidr("DC01.example.com") is False
        assert is_cidr("DC01") is False

    def test_invalid_cidr(self):
        """Should return False for invalid CIDR notation"""
        assert is_cidr("192.168.1.0/33") is False
        assert is_cidr("not/valid") is False


# ============================================================================
# Test: sanitize_json_string
# ============================================================================


class TestSanitizeJsonString:
    """Tests for sanitize_json_string function"""

    def test_already_valid_json(self):
        """Should not modify already valid JSON"""
        json_str = '{"name": "test", "value": "data"}'

        result = sanitize_json_string(json_str)

        # Should be able to parse
        import json
        parsed = json.loads(result)
        assert parsed["name"] == "test"

    def test_escapes_unescaped_backslash(self):
        """Should escape unescaped backslashes in DN-style values"""
        # Common in AD Distinguished Names: CN=LASTNAME\, FIRSTNAME
        json_str = r'{"dn": "CN=Smith\, John,OU=Users"}'

        result = sanitize_json_string(json_str)

        # Should be parseable now
        import json
        parsed = json.loads(result)
        assert "Smith" in parsed["dn"]

    def test_preserves_escaped_quotes(self):
        """Should preserve already escaped quotes"""
        json_str = r'{"name": "test \"quoted\""}'

        result = sanitize_json_string(json_str)

        import json
        parsed = json.loads(result)
        assert '"' in parsed["name"]

    def test_preserves_escaped_newlines(self):
        """Should preserve escaped newlines"""
        json_str = '{"text": "line1\\nline2"}'

        result = sanitize_json_string(json_str)

        import json
        parsed = json.loads(result)
        assert "\n" in parsed["text"]

    def test_preserves_unicode_escapes(self):
        """Should preserve unicode escape sequences"""
        json_str = r'{"text": "test\u0041"}'  # \u0041 = 'A'

        result = sanitize_json_string(json_str)

        import json
        parsed = json.loads(result)
        assert "A" in parsed["text"]


# ============================================================================
# ============================================================================


