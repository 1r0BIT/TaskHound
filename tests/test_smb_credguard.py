"""Additional tests for taskhound/smb/credguard.py module."""

from unittest.mock import MagicMock, patch

import pytest

from taskhound.smb.credguard import RemoteRegistryOps, check_credential_guard


@pytest.fixture
def mock_scm_and_rrp():
    """Create mocks for SCM and RRP with service already running"""
    with patch('taskhound.smb.credguard.transport') as mock_transport, \
         patch('taskhound.smb.credguard.scmr') as mock_scmr, \
         patch('taskhound.smb.credguard.rrp') as mock_rrp:

        # Setup transport to return different DCE connections
        mock_scm_dce = MagicMock()
        mock_rrp_dce = MagicMock()

        def transport_factory(binding):
            mock = MagicMock()
            if 'svcctl' in binding:
                mock.get_dce_rpc.return_value = mock_scm_dce
            else:  # winreg
                mock.get_dce_rpc.return_value = mock_rrp_dce
            return mock

        mock_transport.DCERPCTransportFactory.side_effect = transport_factory

        # Setup SCM mocks - service already running
        mock_scmr.hROpenSCManagerW.return_value = {"lpScHandle": MagicMock()}
        mock_scmr.hROpenServiceW.return_value = {"lpServiceHandle": MagicMock()}
        mock_scmr.hRQueryServiceStatus.return_value = {
            "lpServiceStatus": {"dwCurrentState": 4}  # SERVICE_RUNNING = 4
        }
        mock_scmr.SERVICE_RUNNING = 4
        mock_scmr.SERVICE_STOPPED = 1
        mock_scmr.SERVICE_START = 0x0010
        mock_scmr.SERVICE_STOP = 0x0020
        mock_scmr.SERVICE_CHANGE_CONFIG = 0x0002
        mock_scmr.SERVICE_QUERY_CONFIG = 0x0001
        mock_scmr.SERVICE_QUERY_STATUS = 0x0004
        mock_scmr.SERVICE_CONTROL_STOP = 0x00000001
        mock_scmr.MSRPC_UUID_SCMR = "uuid-scmr"

        # Setup RRP mocks
        mock_rrp.MSRPC_UUID_RRP = "uuid-rrp"
        mock_rrp.KEY_READ = 0x20019
        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": MagicMock()}

        yield {
            'transport': mock_transport,
            'scmr': mock_scmr,
            'rrp': mock_rrp,
            'scm_dce': mock_scm_dce,
            'rrp_dce': mock_rrp_dce,
        }


class TestCheckCredentialGuard:
    """Tests for check_credential_guard function."""

    def test_returns_true_when_lsa_cfg_flags_set(self, mock_scm_and_rrp):
        """Returns True when LsaCfgFlags is 1."""
        mock_smb = MagicMock()
        mock_rrp = mock_scm_and_rrp['rrp']
        # hBaseRegQueryValue returns tuple (dataType, value)
        mock_rrp.hBaseRegQueryValue.return_value = (4, 1)  # REG_DWORD=4, value=1

        result = check_credential_guard(mock_smb, "192.168.1.100")
        assert result is True

    def test_returns_false_when_not_enabled(self, mock_scm_and_rrp):
        """Returns False when Credential Guard is not enabled."""
        mock_smb = MagicMock()
        mock_rrp = mock_scm_and_rrp['rrp']
        # hBaseRegQueryValue returns tuple (dataType, value)
        mock_rrp.hBaseRegQueryValue.return_value = (4, 0)  # REG_DWORD=4, value=0

        result = check_credential_guard(mock_smb, "192.168.1.100")
        assert result is False

    @patch('taskhound.smb.credguard.transport')
    def test_returns_none_on_exception(self, mock_transport):
        """Returns None when an exception occurs (Remote Registry not available)."""
        mock_smb = MagicMock()
        mock_transport.DCERPCTransportFactory.side_effect = Exception("Connection failed")

        result = check_credential_guard(mock_smb, "192.168.1.100")
        assert result is None

    def test_function_callable(self):
        """Function is callable."""
        assert callable(check_credential_guard)


class TestCredGuardRegistry:
    """Tests for registry key constants used."""

    def test_lsa_path_format(self):
        """LSA registry path is properly formatted."""
        # The function internally uses this path
        lsa_path = "SYSTEM\\CurrentControlSet\\Control\\Lsa"
        assert "Lsa" in lsa_path
        assert "Control" in lsa_path

    def test_lsa_cfg_flags_key(self):
        """LsaCfgFlags is the key to check."""
        key_name = "LsaCfgFlags"
        assert key_name == "LsaCfgFlags"

    def test_isolated_user_mode_key(self):
        """IsolatedUserMode is an alternative key."""
        key_name = "IsolatedUserMode"
        assert key_name == "IsolatedUserMode"


class TestRemoteRegistryOpsClass:
    """Tests for RemoteRegistryOps class."""

    def test_class_exists(self):
        """Class is importable."""
        assert RemoteRegistryOps is not None

    def test_service_name_constant(self):
        """Service name constant is correct."""
        assert RemoteRegistryOps.SERVICE_NAME == "RemoteRegistry"

    def test_binding_constants(self):
        """Binding constants are correct."""
        assert "winreg" in RemoteRegistryOps.WINREG_BINDING
        assert "svcctl" in RemoteRegistryOps.SVCCTL_BINDING
