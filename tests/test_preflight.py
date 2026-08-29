"""Tests for pre-flight credential validation (taskhound.utils.network.preflight_credential_check)."""

from unittest.mock import MagicMock, patch

import pytest

from taskhound.utils.network import preflight_credential_check


class TestPreflightSkipConditions:
    """Tests for conditions that skip the preflight check entirely."""

    @patch("taskhound.smb.connection.smb_connect")
    def test_preflight_skipped_for_local_auth(self, mock_smb):
        """Local auth (domain='.') should return without calling smb_connect."""
        preflight_credential_check(
            domain=".",
            username="admin",
            password="pass",
            hashes=None,
            kerberos=False,
            dc_ip="10.0.0.1",
            timeout=5,
        )
        mock_smb.assert_not_called()

    @patch("taskhound.smb.connection.smb_connect")
    def test_preflight_skipped_for_none_domain(self, mock_smb):
        """domain=None should return silently without calling smb_connect."""
        preflight_credential_check(
            domain=None,
            username="admin",
            password="pass",
            hashes=None,
            kerberos=False,
            dc_ip="10.0.0.1",
            timeout=5,
        )
        mock_smb.assert_not_called()


class TestPreflightSMBChecks:
    """Tests for SMB credential validation behavior."""

    @patch("taskhound.smb.connection.smb_connect")
    def test_preflight_exits_on_auth_failure(self, mock_smb):
        """Auth failure (STATUS_LOGON_FAILURE) should call sys.exit(1)."""
        mock_smb.side_effect = Exception("STATUS_LOGON_FAILURE")

        with pytest.raises(SystemExit) as exc_info:
            preflight_credential_check(
                domain="corp.local",
                username="baduser",
                password="wrongpass",
                hashes=None,
                kerberos=False,
                dc_ip="10.0.0.1",
                timeout=5,
            )
        assert exc_info.value.code == 1

    @patch("taskhound.smb.connection.smb_connect")
    def test_preflight_warns_on_network_error(self, mock_smb):
        """Network errors (Connection refused) should NOT exit, just warn."""
        mock_smb.side_effect = Exception("Connection refused")

        # Should NOT raise SystemExit
        preflight_credential_check(
            domain="corp.local",
            username="user",
            password="pass",
            hashes=None,
            kerberos=False,
            dc_ip="10.0.0.1",
            timeout=5,
        )

    @patch("taskhound.smb.connection.smb_connect")
    def test_preflight_passes_on_success(self, mock_smb):
        """Successful SMB connection should not exit."""
        mock_conn = MagicMock()
        mock_smb.return_value = mock_conn

        # Should NOT raise SystemExit
        preflight_credential_check(
            domain="corp.local",
            username="validuser",
            password="validpass",
            hashes=None,
            kerberos=False,
            dc_ip="10.0.0.1",
            timeout=5,
        )
        mock_conn.close.assert_called_once()


class TestPreflightLDAPChecks:
    """Tests for dedicated LDAP credential validation."""

    @patch("taskhound.smb.connection.smb_connect")
    def test_preflight_ldap_exits_on_bad_creds(self, mock_smb):
        """LDAP auth failure (invalidCredentials data 52e) should exit."""
        mock_conn = MagicMock()
        mock_smb.return_value = mock_conn

        with patch("taskhound.auth.context.effective_ldap_creds") as mock_eff, \
             patch("impacket.ldap.ldap.LDAPConnection") as mock_ldap_cls:
            # Return effective LDAP creds
            mock_eff.return_value = ("corp.local", "baduser", "badpass", None)
            # LDAP connection raises auth failure
            mock_ldap_conn = MagicMock()
            mock_ldap_cls.return_value = mock_ldap_conn
            mock_ldap_conn.login.side_effect = Exception("invalidCredentials data 52e")

            with pytest.raises(SystemExit) as exc_info:
                preflight_credential_check(
                    domain="corp.local",
                    username="mainuser",
                    password="mainpass",
                    hashes=None,
                    kerberos=False,
                    dc_ip="10.0.0.1",
                    timeout=5,
                    ldap_user="baduser",
                    ldap_password="badpass",
                )
            assert exc_info.value.code == 1

    @patch("taskhound.smb.connection.smb_connect")
    def test_preflight_skips_ldap_when_no_ldap(self, mock_smb):
        """no_ldap=True should skip LDAP check even with ldap_user set."""
        mock_conn = MagicMock()
        mock_smb.return_value = mock_conn

        with patch("impacket.ldap.ldap.LDAPConnection") as mock_ldap_cls:
            preflight_credential_check(
                domain="corp.local",
                username="user",
                password="pass",
                hashes=None,
                kerberos=False,
                dc_ip="10.0.0.1",
                timeout=5,
                ldap_user="someone",
                no_ldap=True,
            )
            # LDAP connection should never be created when no_ldap=True
            mock_ldap_cls.assert_not_called()

    @patch("taskhound.smb.connection.smb_connect")
    def test_preflight_skips_ldap_when_same_creds(self, mock_smb):
        """No ldap_* params means same creds as main -- only SMB check runs."""
        mock_conn = MagicMock()
        mock_smb.return_value = mock_conn

        with patch("impacket.ldap.ldap.LDAPConnection") as mock_ldap_cls:
            preflight_credential_check(
                domain="corp.local",
                username="user",
                password="pass",
                hashes=None,
                kerberos=False,
                dc_ip="10.0.0.1",
                timeout=5,
            )
            # No dedicated LDAP creds, so LDAP connection should NOT be created
            mock_ldap_cls.assert_not_called()
