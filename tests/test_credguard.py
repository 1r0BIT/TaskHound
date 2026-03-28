"""
Test suite for Credential Guard detection functionality.

Tests cover:
- check_credential_guard function
- Registry key checking (LsaCfgFlags, IsolatedUserMode)
- Error handling for SMB/registry operations
- RemoteRegistry service management
"""

from unittest.mock import MagicMock, patch

import pytest

from taskhound.smb.credguard import RemoteRegistryOps, check_credential_guard

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_smb_connection():
    """Create a mock SMB connection"""
    mock = MagicMock()
    return mock


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


# ============================================================================
# Unit Tests: check_credential_guard
# ============================================================================


class TestCheckCredentialGuard:
    """Tests for check_credential_guard function"""

    def test_credential_guard_enabled_via_lsacfgflags(self, mock_smb_connection, mock_scm_and_rrp):
        """Should return True when LsaCfgFlags is 1"""
        mock_rrp = mock_scm_and_rrp['rrp']
        # LsaCfgFlags = 1 (enabled) - hBaseRegQueryValue returns tuple (dataType, value)
        mock_rrp.hBaseRegQueryValue.return_value = (4, 1)  # REG_DWORD=4, value=1

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is True

    def test_credential_guard_enabled_via_isolatedusermode(self, mock_smb_connection, mock_scm_and_rrp):
        """Should return True when IsolatedUserMode is 1"""
        mock_rrp = mock_scm_and_rrp['rrp']
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        # LsaCfgFlags throws exception (not found), IsolatedUserMode = 1
        # hBaseRegQueryValue returns tuple (dataType, value)
        mock_rrp.hBaseRegQueryValue.side_effect = [
            DCERPCException(),  # LsaCfgFlags not found
            (4, 1)  # IsolatedUserMode = 1 (REG_DWORD=4)
        ]

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is True

    def test_credential_guard_disabled(self, mock_smb_connection, mock_scm_and_rrp):
        """Should return False when both keys are 0"""
        mock_rrp = mock_scm_and_rrp['rrp']

        # Both keys return 0 - hBaseRegQueryValue returns tuple (dataType, value)
        mock_rrp.hBaseRegQueryValue.side_effect = [
            (4, 0),  # LsaCfgFlags = 0 (REG_DWORD=4)
            (4, 0)   # IsolatedUserMode = 0 (REG_DWORD=4)
        ]

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is False

    def test_credential_guard_keys_not_found(self, mock_smb_connection, mock_scm_and_rrp):
        """Should return False when registry keys don't exist"""
        mock_rrp = mock_scm_and_rrp['rrp']
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        # Both keys throw exception
        mock_rrp.hBaseRegQueryValue.side_effect = DCERPCException()

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is False

    @patch('taskhound.smb.credguard.transport')
    def test_connection_error_returns_none(self, mock_transport, mock_smb_connection):
        """Should return None on connection error (Remote Registry not available)"""
        # Make transport factory throw an exception
        mock_transport.DCERPCTransportFactory.side_effect = Exception("Connection failed")

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is None

    def test_registry_open_error_returns_none(self, mock_smb_connection, mock_scm_and_rrp):
        """Should return None when cannot open registry (Remote Registry not available)"""
        mock_rrp = mock_scm_and_rrp['rrp']
        # Opening local machine fails
        mock_rrp.hOpenLocalMachine.side_effect = Exception("Access denied")

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is None

    def test_lsa_key_open_error_returns_none(self, mock_smb_connection, mock_scm_and_rrp):
        """Should return None when cannot open LSA key"""
        mock_rrp = mock_scm_and_rrp['rrp']
        # Opening LSA key fails
        mock_rrp.hBaseRegOpenKey.side_effect = Exception("Key not found")

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is None

    def test_lsacfgflags_enabled_without_lock(self, mock_smb_connection, mock_scm_and_rrp):
        """Should return True when LsaCfgFlags is 2 (enabled without UEFI lock)"""
        mock_rrp = mock_scm_and_rrp['rrp']

        # LsaCfgFlags = 2 (enabled without lock) - hBaseRegQueryValue returns tuple (dataType, value)
        mock_rrp.hBaseRegQueryValue.return_value = (4, 2)  # REG_DWORD=4, value=2

        result = check_credential_guard(mock_smb_connection, "DC01")

        # Value 2 means Credential Guard enabled without UEFI lock
        assert result is True

    def test_lsacfgflags_other_values(self, mock_smb_connection, mock_scm_and_rrp):
        """Should return False for LsaCfgFlags values other than 1 or 2"""
        mock_rrp = mock_scm_and_rrp['rrp']

        # LsaCfgFlags = 99 (unexpected value) - hBaseRegQueryValue returns tuple (dataType, value)
        mock_rrp.hBaseRegQueryValue.side_effect = [
            (4, 99),  # LsaCfgFlags = 99 (REG_DWORD=4)
            (4, 0)    # IsolatedUserMode = 0 (REG_DWORD=4)
        ]

        result = check_credential_guard(mock_smb_connection, "DC01")

        # Should return False since value is not 1 or 2
        assert result is False


# ============================================================================
# Unit Tests: RemoteRegistryOps service management
# ============================================================================


class TestRemoteRegistryOps:
    """Tests for RemoteRegistryOps class"""

    def test_starts_stopped_service(self, mock_smb_connection, mock_scm_and_rrp):
        """Should start RemoteRegistry service if stopped"""
        mock_scmr = mock_scm_and_rrp['scmr']

        # Service is stopped
        mock_scmr.hRQueryServiceStatus.return_value = {
            "lpServiceStatus": {"dwCurrentState": 1}  # SERVICE_STOPPED
        }
        mock_scmr.hRQueryServiceConfigW.return_value = {
            "lpServiceConfig": {"dwStartType": 0x3}  # Not disabled
        }

        ops = RemoteRegistryOps(mock_smb_connection, "DC01")
        ops.enable_registry()

        # Should have started service
        mock_scmr.hRStartServiceW.assert_called_once()
        # Should be marked for stop on finish
        assert ops._should_stop is True

    def test_enables_disabled_service(self, mock_smb_connection, mock_scm_and_rrp):
        """Should enable RemoteRegistry service if disabled"""
        mock_scmr = mock_scm_and_rrp['scmr']

        # Service is stopped and disabled
        mock_scmr.hRQueryServiceStatus.return_value = {
            "lpServiceStatus": {"dwCurrentState": 1}  # SERVICE_STOPPED
        }
        mock_scmr.hRQueryServiceConfigW.return_value = {
            "lpServiceConfig": {"dwStartType": 0x4}  # SERVICE_DISABLED
        }

        ops = RemoteRegistryOps(mock_smb_connection, "DC01")
        ops.enable_registry()

        # Should have enabled then started service
        assert mock_scmr.hRChangeServiceConfigW.call_count >= 1
        mock_scmr.hRStartServiceW.assert_called_once()
        # Should be marked for disable on finish
        assert ops._disabled is True

    def test_does_not_stop_already_running(self, mock_smb_connection, mock_scm_and_rrp):
        """Should not stop service if it was already running"""
        mock_scmr = mock_scm_and_rrp['scmr']

        # Service already running
        mock_scmr.hRQueryServiceStatus.return_value = {
            "lpServiceStatus": {"dwCurrentState": 4}  # SERVICE_RUNNING
        }

        ops = RemoteRegistryOps(mock_smb_connection, "DC01")
        ops.enable_registry()

        # Should not start or stop
        mock_scmr.hRStartServiceW.assert_not_called()
        assert ops._should_stop is False

        ops.finish()
        mock_scmr.hRControlService.assert_not_called()

    def test_restores_service_state(self, mock_smb_connection, mock_scm_and_rrp):
        """Should restore service to original state on finish"""
        mock_scmr = mock_scm_and_rrp['scmr']

        # Service stopped and disabled
        mock_scmr.hRQueryServiceStatus.return_value = {
            "lpServiceStatus": {"dwCurrentState": 1}
        }
        mock_scmr.hRQueryServiceConfigW.return_value = {
            "lpServiceConfig": {"dwStartType": 0x4}
        }

        ops = RemoteRegistryOps(mock_smb_connection, "DC01")
        ops.enable_registry()
        ops.finish()

        # Should have stopped and disabled service
        mock_scmr.hRControlService.assert_called_once()
        # Change config called twice: once to enable, once to disable
        assert mock_scmr.hRChangeServiceConfigW.call_count == 2
