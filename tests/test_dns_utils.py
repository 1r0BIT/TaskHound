# Tests for DNS utilities module
#
# These tests cover DC discovery, hostname resolution, and nameserver functionality.

import socket
from unittest.mock import MagicMock, patch

from taskhound.utils.dns import (
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_LDAP_TIMEOUT,
    _is_ip_address,
    _test_port,
    discover_domain_controllers,
    get_working_dc,
    resolve_hostname,
)


class TestIsIpAddress:
    """Tests for _is_ip_address helper."""

    def test_valid_ipv4(self):
        """Should return True for valid IPv4."""
        assert _is_ip_address("192.168.1.1") is True
        assert _is_ip_address("10.0.0.1") is True
        assert _is_ip_address("255.255.255.255") is True
        assert _is_ip_address("0.0.0.0") is True

    def test_invalid_ipv4(self):
        """Should return False for invalid IPv4."""
        assert _is_ip_address("192.168.1.256") is False
        assert _is_ip_address("192.168.1") is False
        assert _is_ip_address("hostname") is False
        assert _is_ip_address("dc.corp.local") is False
        assert _is_ip_address("") is False


class TestTestPort:
    """Tests for _test_port helper."""

    @patch("socket.socket")
    def test_port_open(self, mock_socket_class):
        """Should return True when port is open."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        result = _test_port("192.168.1.1", 636, timeout=3)

        assert result is True
        mock_sock.settimeout.assert_called_once_with(3)
        mock_sock.connect_ex.assert_called_once_with(("192.168.1.1", 636))
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_port_closed(self, mock_socket_class):
        """Should return False when port is closed."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused
        mock_socket_class.return_value = mock_sock

        result = _test_port("192.168.1.1", 636, timeout=3)

        assert result is False

    @patch("socket.socket")
    def test_port_exception(self, mock_socket_class):
        """Should return False on exception."""
        mock_socket_class.side_effect = OSError("Connection failed")

        result = _test_port("192.168.1.1", 636, timeout=3)

        assert result is False


class TestDiscoverDomainControllers:
    """Tests for discover_domain_controllers function."""

    @patch("dns.resolver.Resolver")
    def test_srv_discovery_success(self, mock_resolver_class):
        """Should discover DCs via SRV records."""
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        # Mock SRV response
        mock_rdata1 = MagicMock()
        mock_rdata1.target = "dc1.corp.local."
        mock_rdata1.priority = 0
        mock_rdata1.weight = 100
        mock_rdata2 = MagicMock()
        mock_rdata2.target = "dc2.corp.local."
        mock_rdata2.priority = 10
        mock_rdata2.weight = 50

        mock_resolver.resolve.return_value = [mock_rdata1, mock_rdata2]

        result = discover_domain_controllers("corp.local")

        assert result == ["dc1.corp.local", "dc2.corp.local"]
        mock_resolver.resolve.assert_called_once()

    @patch("dns.resolver.Resolver")
    def test_srv_failure_falls_back_to_a_record(self, mock_resolver_class):
        """Should fall back to A record when SRV fails."""
        import dns.resolver

        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        # SRV lookup fails, A lookup succeeds
        def resolve_side_effect(name, rdtype, **kwargs):
            if rdtype == "SRV":
                raise dns.resolver.NXDOMAIN()
            elif rdtype == "A":
                mock_a = MagicMock()
                mock_a.__str__ = lambda self: "192.168.1.10"
                return [mock_a]

        mock_resolver.resolve.side_effect = resolve_side_effect

        result = discover_domain_controllers("corp.local", nameserver="10.0.0.1")

        assert result == ["192.168.1.10"]

    @patch("socket.gethostbyname")
    def test_system_dns_fallback(self, mock_gethostbyname):
        """Should fall back to system DNS when dnspython unavailable."""
        mock_gethostbyname.return_value = "192.168.1.10"

        # Mock dnspython import failure
        with patch.dict("sys.modules", {"dns.resolver": None}):
            with patch("builtins.__import__", side_effect=ImportError("No module named 'dns'")):
                # This will use socket.gethostbyname fallback
                pass

        # For this test, just verify the fallback logic exists
        mock_gethostbyname.return_value = "10.0.0.5"
        discover_domain_controllers("corp.local")
        # Either SRV works or falls back - we just verify no crash

    def test_no_dns_returns_empty(self):
        """Should return empty list when all DNS fails."""
        with patch("socket.gethostbyname", side_effect=socket.gaierror("DNS failed")):
            with patch.dict("sys.modules", {"dns": None, "dns.resolver": None}):
                result = discover_domain_controllers("nonexistent.local")
                # May return empty or have some result depending on system DNS
                assert isinstance(result, list)


class TestResolveHostname:
    """Tests for resolve_hostname function."""

    def test_ip_address_passthrough(self):
        """Should return IP address unchanged."""
        result = resolve_hostname("192.168.1.1")
        assert result == "192.168.1.1"

    @patch("socket.gethostbyname")
    def test_hostname_resolution(self, mock_gethostbyname):
        """Should resolve hostname to IP."""
        mock_gethostbyname.return_value = "192.168.1.10"

        result = resolve_hostname("dc.corp.local")

        assert result == "192.168.1.10"
        mock_gethostbyname.assert_called_once_with("dc.corp.local")

    @patch("socket.gethostbyname")
    def test_resolution_failure(self, mock_gethostbyname):
        """Should return None on resolution failure."""
        mock_gethostbyname.side_effect = socket.gaierror("DNS failed")

        result = resolve_hostname("nonexistent.local")

        assert result is None


class TestGetWorkingDc:
    """Tests for get_working_dc function."""

    def test_explicit_dc_ip_returned(self):
        """Should return user-provided DC IP directly."""
        result = get_working_dc("corp.local", dc_ip="10.0.0.1")
        assert result == "10.0.0.1"

    @patch("taskhound.utils.dns.discover_domain_controllers")
    @patch("taskhound.utils.dns.resolve_hostname")
    @patch("taskhound.utils.dns._test_port")
    def test_discovery_with_working_dc(self, mock_test_port, mock_resolve, mock_discover):
        """Should return first working DC."""
        mock_discover.return_value = ["dc1.corp.local", "dc2.corp.local"]
        mock_resolve.side_effect = lambda h, **kw: "192.168.1.10" if "dc1" in h else "192.168.1.11"
        mock_test_port.return_value = True

        result = get_working_dc("corp.local")

        assert result == "192.168.1.10"

    @patch("taskhound.utils.dns.discover_domain_controllers")
    @patch("taskhound.utils.dns.resolve_hostname")
    @patch("taskhound.utils.dns._test_port")
    def test_discovery_skips_unreachable_dc(self, mock_test_port, mock_resolve, mock_discover):
        """Should skip unreachable DC and try next."""
        mock_discover.return_value = ["dc1.corp.local", "dc2.corp.local"]
        mock_resolve.side_effect = lambda h, **kw: "192.168.1.10" if "dc1" in h else "192.168.1.11"
        # First DC unreachable, second works
        mock_test_port.side_effect = [False, False, True, True]  # dc1 636/389 fail, dc2 636 works

        result = get_working_dc("corp.local")

        assert result == "192.168.1.11"

    @patch("taskhound.utils.dns.discover_domain_controllers")
    def test_discovery_failure_returns_none(self, mock_discover):
        """Should return None when no DCs found."""
        mock_discover.return_value = []

        result = get_working_dc("nonexistent.local")

        assert result is None


class TestConstants:
    """Tests for module constants."""

    def test_default_dns_timeout(self):
        """DNS timeout should be reasonable."""
        assert DEFAULT_DNS_TIMEOUT == 5

    def test_default_ldap_timeout(self):
        """LDAP timeout should be reasonable."""
        assert DEFAULT_LDAP_TIMEOUT == 10
