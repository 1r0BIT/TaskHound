# Tests for SVCCTL RPC service enumeration module.

from unittest.mock import MagicMock, patch

from taskhound.smb.svcctl import _close_dce_pipe, enumerate_services


class TestCloseDcePipe:
    def test_closes_file_handle(self):
        dce = MagicMock()
        smb_conn = MagicMock()
        tp = MagicMock()
        tp.get_smb_connection.return_value = smb_conn
        tp._SMBTransport__tid = 42
        tp._SMBTransport__handle = 99
        dce.get_rpc_transport.return_value = tp

        _close_dce_pipe(dce)

        smb_conn.closeFile.assert_called_once_with(42, 99)

    def test_no_crash_on_missing_attrs(self):
        dce = MagicMock()
        tp = MagicMock(spec=[])  # no attributes
        tp.get_smb_connection = MagicMock(return_value=None)
        dce.get_rpc_transport.return_value = tp

        # Should not raise
        _close_dce_pipe(dce)

    def test_suppresses_exceptions(self):
        dce = MagicMock()
        smb_conn = MagicMock()
        smb_conn.closeFile.side_effect = Exception("pipe error")
        tp = MagicMock()
        tp.get_smb_connection.return_value = smb_conn
        tp._SMBTransport__tid = 1
        tp._SMBTransport__handle = 2
        dce.get_rpc_transport.return_value = tp

        # Should not raise
        _close_dce_pipe(dce)


class TestEnumerateServices:
    @patch("taskhound.smb.svcctl.transport")
    @patch("taskhound.smb.svcctl.scmr")
    def test_basic_enumeration(self, mock_scmr, mock_transport):
        """Test that enumerate_services calls the right SVCCTL functions."""
        smb = MagicMock()

        # Mock transport setup
        mock_rpc = MagicMock()
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value = mock_rpc
        mock_rpc.get_dce_rpc.return_value = mock_dce

        # Mock SCM open
        mock_scmr.hROpenSCManagerW.return_value = {"lpScHandle": b"sc_handle"}

        # Mock service enumeration - return one service
        mock_scmr.SERVICE_WIN32_OWN_PROCESS = 0x10
        mock_scmr.SERVICE_WIN32_SHARE_PROCESS = 0x20
        mock_scmr.SERVICE_STATE_ALL = 0x03
        mock_scmr.SC_MANAGER_ENUMERATE_SERVICE = 0x0004
        mock_scmr.SERVICE_QUERY_CONFIG = 0x0001
        mock_scmr.MSRPC_UUID_SCMR = "uuid"

        mock_scmr.hREnumServicesStatusW.return_value = [
            {
                "lpServiceName": "MSSQLSERVER\x00",
                "lpDisplayName": "SQL Server\x00",
                "ServiceStatus": {
                    "dwCurrentState": 0x04,  # Running
                    "dwServiceType": 0x10,  # Win32OwnProcess
                },
            }
        ]

        # Mock service config query
        mock_scmr.hROpenServiceW.return_value = {"lpServiceHandle": b"svc_handle"}
        mock_scmr.hRQueryServiceConfigW.return_value = {
            "lpServiceConfig": {
                "lpServiceStartName": "CORP\\sqladmin\x00",
                "lpBinaryPathName": "C:\\SQL\\sqlservr.exe\x00",
                "dwStartType": 0x02,
            }
        }

        services = enumerate_services(smb, "db01")

        assert len(services) == 1
        assert services[0]["name"] == "MSSQLSERVER"
        assert services[0]["display_name"] == "SQL Server"
        assert services[0]["account"] == "CORP\\sqladmin"
        assert services[0]["binary_path"] == "C:\\SQL\\sqlservr.exe"
        assert services[0]["start_type"] == 0x02
        assert services[0]["state"] == 0x04

    @patch("taskhound.smb.svcctl.transport")
    @patch("taskhound.smb.svcctl.scmr")
    def test_returns_empty_on_rpc_error(self, mock_scmr, mock_transport):
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        smb = MagicMock()
        mock_rpc = MagicMock()
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value = mock_rpc
        mock_rpc.get_dce_rpc.return_value = mock_dce
        mock_scmr.MSRPC_UUID_SCMR = "uuid"
        mock_scmr.SC_MANAGER_ENUMERATE_SERVICE = 0x0004
        mock_scmr.SERVICE_WIN32_OWN_PROCESS = 0x10
        mock_scmr.SERVICE_WIN32_SHARE_PROCESS = 0x20
        mock_scmr.SERVICE_STATE_ALL = 0x03

        mock_scmr.hROpenSCManagerW.side_effect = DCERPCException(error_code=0x00000005)

        services = enumerate_services(smb, "host1")
        assert services == []

    @patch("taskhound.smb.svcctl.transport")
    @patch("taskhound.smb.svcctl.scmr")
    def test_cleans_up_handles(self, mock_scmr, mock_transport):
        """Verify SCM handle is closed in finally block."""
        smb = MagicMock()
        mock_rpc = MagicMock()
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value = mock_rpc
        mock_rpc.get_dce_rpc.return_value = mock_dce
        mock_scmr.MSRPC_UUID_SCMR = "uuid"
        mock_scmr.SC_MANAGER_ENUMERATE_SERVICE = 0x0004
        mock_scmr.SERVICE_WIN32_OWN_PROCESS = 0x10
        mock_scmr.SERVICE_WIN32_SHARE_PROCESS = 0x20
        mock_scmr.SERVICE_STATE_ALL = 0x03

        mock_scmr.hROpenSCManagerW.return_value = {"lpScHandle": b"handle"}
        mock_scmr.hREnumServicesStatusW.return_value = []

        enumerate_services(smb, "host1")

        mock_scmr.hRCloseServiceHandle.assert_called_once_with(mock_dce, b"handle")
