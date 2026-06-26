"""
Tests for BloodHound OpenGraph upload module.
"""


from taskhound.output.bloodhound import (
    extract_host_from_connector,
    normalize_bloodhound_connector,
)


class TestNormalizeBloodHoundConnector:
    """Tests for normalize_bloodhound_connector function"""

    def test_adds_scheme_and_port_to_hostname(self):
        """Should add http scheme and default port to bare hostname"""
        result = normalize_bloodhound_connector("localhost")

        assert result == "http://localhost:8080"

    def test_adds_scheme_and_port_to_ip(self):
        """Should add http scheme and default port to bare IP"""
        result = normalize_bloodhound_connector("192.168.1.1")

        assert result == "http://192.168.1.1:8080"

    def test_adds_port_to_http_url(self):
        """Should add default port to http URL without port"""
        result = normalize_bloodhound_connector("http://localhost")

        assert result == "http://localhost:8080"

    def test_adds_port_443_to_https_url(self):
        """Should add port 443 to https URL without port"""
        result = normalize_bloodhound_connector("https://bh.domain.com")

        assert result == "https://bh.domain.com:443"

    def test_preserves_existing_port(self):
        """Should preserve existing port"""
        result = normalize_bloodhound_connector("http://localhost:9000")

        assert result == "http://localhost:9000"

    def test_legacy_mode_uses_bolt_scheme(self):
        """Should use bolt scheme for legacy mode"""
        result = normalize_bloodhound_connector("localhost", is_legacy=True)

        assert result == "bolt://localhost:7687"

    def test_legacy_mode_preserves_bolt_port(self):
        """Should preserve custom port in legacy mode"""
        result = normalize_bloodhound_connector("bolt://neo4j.domain.com:7474", is_legacy=True)

        assert result == "bolt://neo4j.domain.com:7474"

    def test_handles_fqdn(self):
        """Should handle fully qualified domain name"""
        result = normalize_bloodhound_connector("bloodhound.corp.example.com")

        assert result == "http://bloodhound.corp.example.com:8080"


class TestExtractHostFromConnector:
    """Tests for extract_host_from_connector function"""

    def test_extracts_from_http_url(self):
        """Should extract hostname from http URL"""
        result = extract_host_from_connector("http://bloodhound.domain.lab:8080")

        assert result == "bloodhound.domain.lab"

    def test_extracts_from_https_url(self):
        """Should extract hostname from https URL"""
        result = extract_host_from_connector("https://bh.example.com:443")

        assert result == "bh.example.com"

    def test_extracts_from_bolt_url(self):
        """Should extract hostname from bolt URL"""
        result = extract_host_from_connector("bolt://neo4j.domain.lab:7687")

        assert result == "neo4j.domain.lab"

    def test_extracts_localhost(self):
        """Should extract localhost"""
        result = extract_host_from_connector("http://localhost:8080")

        assert result == "localhost"

    def test_extracts_ip_address(self):
        """Should extract IP address"""
        result = extract_host_from_connector("http://192.168.1.100:8080")

        assert result == "192.168.1.100"

    def test_handles_url_without_scheme(self):
        """Should handle URL without scheme"""
        result = extract_host_from_connector("192.168.1.1:8080")

        assert result == "192.168.1.1"

    def test_handles_bare_hostname(self):
        """Should handle bare hostname"""
        result = extract_host_from_connector("bloodhound")

        assert result == "bloodhound"


class TestUploadIntegration:
    """Tests for upload-related functions"""

    def test_has_requests_flag(self):
        """Should have HAS_REQUESTS flag defined"""
        from taskhound.output.bloodhound import HAS_REQUESTS

        # In test environment, requests should be installed
        assert HAS_REQUESTS is True

    def test_timeout_constant_defined(self):
        """Should have TIMEOUT constant defined"""
        from taskhound.output.bloodhound import TIMEOUT

        assert isinstance(TIMEOUT, int)
        assert TIMEOUT > 0


class TestNormalizeConnectorEdgeCases:
    """Edge case tests for normalize_bloodhound_connector"""

    def test_handles_ipv6_localhost(self):
        """Should handle IPv6 localhost notation"""
        # Note: urlparse handles IPv6 differently
        result = normalize_bloodhound_connector("http://[::1]")

        assert "::1" in result

    def test_handles_empty_string(self):
        """Should handle empty string input"""
        # Will try to parse empty string
        result = normalize_bloodhound_connector("")

        # Should return something with scheme and port
        assert "://" in result

    def test_handles_url_with_path(self):
        """Should handle URL with path component"""
        result = normalize_bloodhound_connector("http://localhost/api")

        assert "localhost" in result
        assert ":8080" in result


class TestExtractHostEdgeCases:
    """Edge case tests for extract_host_from_connector"""

    def test_handles_url_with_path(self):
        """Should extract host from URL with path"""
        result = extract_host_from_connector("http://bloodhound.domain.lab:8080/api/v2")

        assert result == "bloodhound.domain.lab"

    def test_handles_url_with_credentials(self):
        """Should handle URL with embedded credentials"""
        result = extract_host_from_connector("http://user:pass@bloodhound:8080")

        assert result == "bloodhound"

    def test_handles_single_word(self):
        """Should handle single word input"""
        result = extract_host_from_connector("bloodhound")

        assert result == "bloodhound"
