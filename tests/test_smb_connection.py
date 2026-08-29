"""
Test suite for SMB connection functions.

Tests cover:
- _parse_hashes function
- smb_connect function
- smb_negotiate function
- smb_login function
"""

from unittest.mock import MagicMock, patch

from taskhound.smb.connection import (
    _parse_hashes,
    smb_connect,
    smb_login,
    smb_negotiate,
)

# ============================================================================
# Test: _parse_hashes
# ============================================================================


class TestParseHashes:
    """Tests for _parse_hashes function"""

    def test_none_input(self):
        """Should return empty password and hashes for None"""
        pwd, lm, nt = _parse_hashes(None)
        assert pwd is None
        assert lm == ""
        assert nt == ""

    def test_empty_string_input(self):
        """Should return empty values for empty string"""
        pwd, lm, nt = _parse_hashes("")
        assert pwd is None
        assert lm == ""
        assert nt == ""

    def test_lm_nt_hash_format(self):
        """Should parse LM:NT format correctly"""
        pwd, lm, nt = _parse_hashes(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert pwd is None
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_nt_hash_only_32_hex(self):
        """Should recognize 32-char hex as NT hash"""
        pwd, lm, nt = _parse_hashes("31d6cfe0d16ae931b73c59d7e0c089c0")
        assert pwd is None
        assert lm == ""
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_cleartext_password(self):
        """Should treat non-hash strings as cleartext password"""
        pwd, lm, nt = _parse_hashes("MySecretP@ssw0rd!")
        assert pwd == "MySecretP@ssw0rd!"
        assert lm == ""
        assert nt == ""

    def test_empty_lm_with_nt_hash(self):
        """Should handle empty LM with NT hash"""
        pwd, lm, nt = _parse_hashes(":31d6cfe0d16ae931b73c59d7e0c089c0")
        assert pwd is None
        assert lm == ""
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_password_with_colon(self):
        """Should handle passwords containing colon after first split"""
        pwd, lm, nt = _parse_hashes("abc:def:ghi")
        # Splits on first colon only
        assert pwd is None
        assert lm == "abc"
        assert nt == "def:ghi"

    def test_short_hex_as_password(self):
        """Should treat short hex strings as passwords"""
        pwd, lm, nt = _parse_hashes("abcdef12345")  # Not 32 chars
        assert pwd == "abcdef12345"
        assert lm == ""
        assert nt == ""

    def test_whitespace_trimmed(self):
        """Should trim whitespace from hashes"""
        pwd, lm, nt = _parse_hashes(" aad3b435b51404eeaad3b435b51404ee : 31d6cfe0d16ae931b73c59d7e0c089c0 ")
        assert pwd is None
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"


# ============================================================================
# Test: smb_connect
# ============================================================================


class TestSmbConnect:
    """Tests for smb_connect function"""

    @patch('taskhound.smb.connection.SMBConnection')
    def test_basic_password_auth(self, mock_smb_class):
        """Should connect with basic password authentication"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        result = smb_connect(
            target="192.168.1.1",
            domain="EXAMPLE",
            username="admin",
            password="password123"
        )

        assert result == mock_smb
        mock_smb.login.assert_called_once_with("admin", "password123", "EXAMPLE")

    @patch('taskhound.smb.connection.SMBConnection')
    def test_ntlm_hash_auth(self, mock_smb_class):
        """Should connect with NTLM hash authentication"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        result = smb_connect(
            target="192.168.1.1",
            domain="EXAMPLE",
            username="admin",
            password="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )

        assert result == mock_smb
        mock_smb.login.assert_called_once_with(
            "admin", "", "EXAMPLE",
            lmhash="aad3b435b51404eeaad3b435b51404ee",
            nthash="31d6cfe0d16ae931b73c59d7e0c089c0"
        )

    @patch('taskhound.smb.connection.SMBConnection')
    def test_kerberos_auth(self, mock_smb_class):
        """Should connect with Kerberos authentication"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        result = smb_connect(
            target="192.168.1.1",
            domain="EXAMPLE",
            username="admin",
            password="password123",
            kerberos=True,
            dc_ip="192.168.1.10"
        )

        assert result == mock_smb
        mock_smb.kerberosLogin.assert_called_once()
        call_kwargs = mock_smb.kerberosLogin.call_args[1]
        assert call_kwargs["user"] == "admin"
        assert call_kwargs["password"] == "password123"
        assert call_kwargs["domain"] == "EXAMPLE"
        assert call_kwargs["kdcHost"] == "192.168.1.10"

    @patch('taskhound.smb.connection.SMBConnection')
    def test_custom_timeout(self, mock_smb_class):
        """Should use custom timeout"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        smb_connect(
            target="192.168.1.1",
            domain="EXAMPLE",
            username="admin",
            password="pass",
            timeout=120
        )

        call_kwargs = mock_smb_class.call_args[1]
        assert call_kwargs["timeout"] == 120


# ============================================================================
# Test: smb_negotiate
# ============================================================================


class TestSmbNegotiate:
    """Tests for smb_negotiate function"""

    @patch('taskhound.smb.connection.SMBConnection')
    def test_creates_connection_without_auth(self, mock_smb_class):
        """Should create connection without authenticating"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        result = smb_negotiate("192.168.1.1", timeout=30)

        assert result == mock_smb
        mock_smb_class.assert_called_once_with(
            remoteName="192.168.1.1",
            remoteHost="192.168.1.1",
            sess_port=445,
            timeout=30
        )
        # Should NOT call login or kerberosLogin
        mock_smb.login.assert_not_called()
        mock_smb.kerberosLogin.assert_not_called()


# ============================================================================
# Test: smb_login
# ============================================================================


class TestSmbLogin:
    """Tests for smb_login function"""

    def test_password_auth(self):
        """Should authenticate with password"""
        mock_smb = MagicMock()

        smb_login(mock_smb, domain="EXAMPLE", username="admin", password="pass123")

        mock_smb.login.assert_called_once_with("admin", "pass123", "EXAMPLE")

    def test_hash_auth(self):
        """Should authenticate with hashes"""
        mock_smb = MagicMock()

        smb_login(
            mock_smb,
            domain="EXAMPLE",
            username="admin",
            password="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )

        mock_smb.login.assert_called_once_with(
            "admin", "", "EXAMPLE",
            lmhash="aad3b435b51404eeaad3b435b51404ee",
            nthash="31d6cfe0d16ae931b73c59d7e0c089c0"
        )

    def test_kerberos_auth(self):
        """Should authenticate with Kerberos"""
        mock_smb = MagicMock()

        smb_login(
            mock_smb,
            domain="EXAMPLE",
            username="admin",
            password="pass123",
            kerberos=True,
            dc_ip="192.168.1.10"
        )

        mock_smb.kerberosLogin.assert_called_once()
        call_kwargs = mock_smb.kerberosLogin.call_args[1]
        assert call_kwargs["user"] == "admin"
        assert call_kwargs["kdcHost"] == "192.168.1.10"


# ============================================================================
# ============================================================================


