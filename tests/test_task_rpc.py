"""Tests for taskhound/smb/task_rpc.py module."""

from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from taskhound.smb.task_rpc import (
    ACCOUNT_BLOCKED_CODES,
    PASSWORD_INVALID_CODES,
    PASSWORD_VALID_CODES,
    TASK_RUNNABLE_CODES,
    TASK_SCHEDULER_CODES,
    CredentialConfidence,
    CredentialContext,
    CredentialStatus,
    TaskRunInfo,
    TaskSchedulerRPC,
    calculate_confidence,
    enrich_with_confidence,
    get_return_code_description,
)


class TestCredentialStatus:
    """Tests for CredentialStatus enum."""

    def test_valid_status(self):
        """Test VALID status value."""
        assert CredentialStatus.VALID.value == "valid"

    def test_valid_restricted_status(self):
        """Test VALID_RESTRICTED status value."""
        assert CredentialStatus.VALID_RESTRICTED.value == "valid_restricted"

    def test_invalid_status(self):
        """Test INVALID status value."""
        assert CredentialStatus.INVALID.value == "invalid"

    def test_blocked_status(self):
        """Test BLOCKED status value."""
        assert CredentialStatus.BLOCKED.value == "blocked"

    def test_unknown_status(self):
        """Test UNKNOWN status value."""
        assert CredentialStatus.UNKNOWN.value == "unknown"

    def test_all_statuses_exist(self):
        """Test all expected statuses exist."""
        expected = {"VALID", "VALID_RESTRICTED", "INVALID", "BLOCKED", "UNKNOWN"}
        actual = {s.name for s in CredentialStatus}
        assert actual == expected


class TestTaskRunInfo:
    """Tests for TaskRunInfo dataclass."""

    def test_create_task_run_info(self):
        """Test creating TaskRunInfo dataclass."""
        info = TaskRunInfo(
            task_path="\\TestTask",
            last_run=datetime(2024, 1, 1, 12, 0, 0),
            return_code=0,
            credential_status=CredentialStatus.VALID,
            status_detail="Task completed successfully",
            password_valid=True,
            task_hijackable=True,
        )
        assert info.task_path == "\\TestTask"
        assert info.last_run == datetime(2024, 1, 1, 12, 0, 0)
        assert info.return_code == 0
        assert info.credential_status == CredentialStatus.VALID
        assert info.status_detail == "Task completed successfully"
        assert info.password_valid is True
        assert info.task_hijackable is True

    def test_task_run_info_with_none_last_run(self):
        """Test TaskRunInfo with None last_run."""
        info = TaskRunInfo(
            task_path="\\TestTask",
            last_run=None,
            return_code=0x00041303,
            credential_status=CredentialStatus.UNKNOWN,
            status_detail="Task has never run",
            password_valid=False,
            task_hijackable=False,
        )
        assert info.last_run is None
        assert info.credential_status == CredentialStatus.UNKNOWN

    def test_task_run_info_blocked(self):
        """Test TaskRunInfo with blocked account."""
        info = TaskRunInfo(
            task_path="\\BlockedTask",
            last_run=datetime(2024, 1, 1),
            return_code=0x80070533,  # ERROR_ACCOUNT_DISABLED
            credential_status=CredentialStatus.BLOCKED,
            status_detail="Account disabled",
            password_valid=False,
            task_hijackable=False,
        )
        assert info.credential_status == CredentialStatus.BLOCKED
        assert info.password_valid is False


class TestReturnCodeSets:
    """Tests for return code sets."""

    def test_password_valid_codes_contains_success(self):
        """Test SUCCESS code is in PASSWORD_VALID_CODES."""
        assert 0x00000000 in PASSWORD_VALID_CODES

    def test_password_valid_codes_contains_file_not_found(self):
        """Test FILE_NOT_FOUND code is in PASSWORD_VALID_CODES."""
        assert 0x00000002 in PASSWORD_VALID_CODES

    def test_account_restricted_codes_contains_logon_type_not_granted(self):
        """Test ERROR_LOGON_TYPE_NOT_GRANTED is in ACCOUNT_RESTRICTED_CODES (documentation only)."""
        from taskhound.smb.task_rpc import ACCOUNT_RESTRICTED_CODES
        assert 0x80070569 in ACCOUNT_RESTRICTED_CODES

    def test_task_runnable_codes_subset_of_valid(self):
        """Test TASK_RUNNABLE_CODES is subset of PASSWORD_VALID_CODES."""
        assert TASK_RUNNABLE_CODES.issubset(PASSWORD_VALID_CODES)

    def test_task_runnable_codes_contains_success(self):
        """Test SUCCESS code is in TASK_RUNNABLE_CODES."""
        assert 0x00000000 in TASK_RUNNABLE_CODES

    def test_password_invalid_codes_contains_logon_failure(self):
        """Test ERROR_LOGON_FAILURE is in PASSWORD_INVALID_CODES."""
        assert 0x8007052E in PASSWORD_INVALID_CODES

    def test_password_invalid_codes_contains_no_such_user(self):
        """Test ERROR_NO_SUCH_USER is in PASSWORD_INVALID_CODES."""
        assert 0x80070525 in PASSWORD_INVALID_CODES

    def test_account_blocked_codes_contains_disabled(self):
        """Test ERROR_ACCOUNT_DISABLED is in ACCOUNT_BLOCKED_CODES."""
        assert 0x80070533 in ACCOUNT_BLOCKED_CODES  # Win32 0x0533 = 1331

    def test_account_blocked_codes_contains_locked_out(self):
        """Test ERROR_ACCOUNT_LOCKED_OUT is in ACCOUNT_BLOCKED_CODES."""
        assert 0x80070775 in ACCOUNT_BLOCKED_CODES

    def test_no_overlap_invalid_valid(self):
        """Test no overlap between invalid and valid codes."""
        overlap = PASSWORD_INVALID_CODES & PASSWORD_VALID_CODES
        assert len(overlap) == 0

    def test_no_overlap_blocked_valid(self):
        """Test no overlap between blocked and valid codes."""
        overlap = ACCOUNT_BLOCKED_CODES & PASSWORD_VALID_CODES
        assert len(overlap) == 0


class TestGetReturnCodeDescription:
    """Tests for get_return_code_description function."""

    def test_success_code(self):
        """Test description for SUCCESS code."""
        desc = get_return_code_description(0x00000000)
        # impacket returns STATUS_SUCCESS for 0x0
        assert "SUCCESS" in desc.upper()

    def test_file_not_found_code(self):
        """Test description for ERROR_FILE_NOT_FOUND code."""
        # Use HRESULT form which maps through impacket's system_errors
        desc = get_return_code_description(0x80070002)
        assert "FILE_NOT_FOUND" in desc.upper() or "NOT_FOUND" in desc.upper()

    def test_logon_failure_code(self):
        """Test description for ERROR_LOGON_FAILURE code."""
        desc = get_return_code_description(0x8007052E)
        # impacket returns the Win32 error name
        assert "LOGON" in desc.upper()

    def test_account_disabled_code(self):
        """Test description for ERROR_ACCOUNT_DISABLED code."""
        # ERROR_ACCOUNT_DISABLED is Win32 0x0533 (1331), HRESULT 0x80070533
        desc = get_return_code_description(0x80070533)
        assert "DISABLED" in desc.upper() or "ACCOUNT" in desc.upper()

    def test_unknown_code(self):
        """Test description for unknown code."""
        desc = get_return_code_description(0x12345678)
        assert "Unknown" in desc
        assert "12345678" in desc.upper()

    def test_all_documented_codes_have_descriptions(self):
        """Test all Task Scheduler codes have descriptions."""
        for code in TASK_SCHEDULER_CODES:
            desc = get_return_code_description(code)
            assert desc != ""

    def test_task_scheduler_code_returns_our_description(self):
        """Test Task Scheduler-specific codes use our descriptions."""
        # SCHED_S_TASK_HAS_NOT_RUN
        desc = get_return_code_description(0x00041303)
        assert desc == "Task not yet run"

    def test_ntstatus_uses_impacket(self):
        """Test NTSTATUS codes are resolved via impacket."""
        # STATUS_LOGON_FAILURE
        desc = get_return_code_description(0xC000006D)
        assert "LOGON" in desc.upper()

    def test_hresult_win32_extraction(self):
        """Test HRESULT codes with Win32 errors extract correctly."""
        # 0x80070533 = HRESULT wrapper of ERROR_ACCOUNT_DISABLED (Win32 0x0533)
        desc = get_return_code_description(0x80070533)
        assert "Unknown" not in desc
        assert "DISABLED" in desc.upper()


class TestTaskSchedulerRPCInit:
    """Tests for TaskSchedulerRPC initialization."""

    def test_init_with_password(self):
        """Test initialization with password."""
        rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="password123",
        )
        assert rpc.target == "192.168.1.100"
        assert rpc.domain == "DOMAIN"
        assert rpc.username == "admin"
        assert rpc.password == "password123"
        assert rpc.lm_hash == ""
        assert rpc.nt_hash == ""
        assert rpc._dce is None

    def test_init_with_hashes(self):
        """Test initialization with NTLM hashes."""
        rpc = TaskSchedulerRPC(
            target="dc01.domain.local",
            domain="DOMAIN",
            username="admin",
            password="",
            lm_hash="aad3b435b51404ee",
            nt_hash="8846f7eaee8fb117",
        )
        assert rpc.lm_hash == "aad3b435b51404ee"
        assert rpc.nt_hash == "8846f7eaee8fb117"

    def test_init_ip_target(self):
        """Test initialization with IP address target."""
        rpc = TaskSchedulerRPC(
            target="10.0.0.1",
            domain="CORP",
            username="user",
            password="pass",
        )
        assert rpc.target == "10.0.0.1"

    def test_init_hostname_target(self):
        """Test initialization with hostname target."""
        rpc = TaskSchedulerRPC(
            target="server.corp.local",
            domain="CORP",
            username="user",
            password="pass",
        )
        assert rpc.target == "server.corp.local"


class TestTaskSchedulerRPCDisconnect:
    """Tests for TaskSchedulerRPC disconnect."""

    def test_disconnect_without_connection(self):
        """Test disconnect when not connected."""
        rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )
        # Should not raise
        rpc.disconnect()
        assert rpc._dce is None

    def test_disconnect_with_connection(self):
        """Test disconnect with active connection."""
        rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )
        rpc._dce = Mock()
        rpc.disconnect()
        assert rpc._dce is None


class TestTaskSchedulerRPCContextManager:
    """Tests for TaskSchedulerRPC context manager."""

    @patch.object(TaskSchedulerRPC, 'connect')
    @patch.object(TaskSchedulerRPC, 'disconnect')
    def test_context_manager_enter_exit(self, mock_disconnect, mock_connect):
        """Test context manager enters and exits correctly."""
        mock_connect.return_value = True

        rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )

        with rpc as client:
            assert client is rpc
            mock_connect.assert_called_once()

        mock_disconnect.assert_called_once()

    @patch.object(TaskSchedulerRPC, 'connect')
    @patch.object(TaskSchedulerRPC, 'disconnect')
    def test_context_manager_exit_on_exception(self, mock_disconnect, mock_connect):
        """Test context manager exits on exception."""
        mock_connect.return_value = True

        rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )

        with pytest.raises(ValueError), rpc:
            raise ValueError("Test error")

        mock_disconnect.assert_called_once()

    @patch.object(TaskSchedulerRPC, 'connect')
    def test_enter_returns_self(self, mock_connect):
        """Test __enter__ method returns self."""
        mock_connect.return_value = True
        rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )

        # Call __enter__ directly - this exercises lines 207-210
        result = rpc.__enter__()
        assert result is rpc
        mock_connect.assert_called_once()

    def test_exit_returns_false(self):
        """Test __exit__ returns False (doesn't suppress exceptions)."""
        rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )

        # Call __exit__ directly - this exercises lines 212-215
        result = rpc.__exit__(None, None, None)
        assert result is False

    def test_exit_with_exception_returns_false(self):
        """Test __exit__ returns False even with exception."""
        rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )

        # Call __exit__ with exception info - ensures False is returned not None
        result = rpc.__exit__(ValueError, ValueError("test"), None)
        assert result is False


class TestTaskSchedulerRPCInterpretReturnCode:
    """Tests for TaskSchedulerRPC._interpret_return_code method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )

    def test_interpret_success_code(self):
        """Test interpreting SUCCESS code."""
        last_run = datetime(2024, 1, 1)
        status, valid, hijackable, detail = self.rpc._interpret_return_code(
            0x00000000, last_run
        )
        assert status == CredentialStatus.VALID
        assert valid is True
        assert hijackable is True

    def test_interpret_file_not_found(self):
        """Test interpreting FILE_NOT_FOUND code."""
        last_run = datetime(2024, 1, 1)
        status, valid, hijackable, detail = self.rpc._interpret_return_code(
            0x00000002, last_run
        )
        assert status == CredentialStatus.VALID
        assert valid is True
        assert hijackable is True

    def test_interpret_logon_type_not_granted(self):
        """Test interpreting ERROR_LOGON_TYPE_NOT_GRANTED code.

        NOTE: This code should never appear via RPC in practice (Windows doesn't
        record batch logon failures), but we handle it for robustness.
        """
        last_run = datetime(2024, 1, 1)
        status, valid, hijackable, detail = self.rpc._interpret_return_code(
            0x80070569, last_run
        )
        assert status == CredentialStatus.VALID_RESTRICTED
        assert valid is True
        assert hijackable is False
        assert "unexpected via RPC" in detail

    def test_interpret_logon_failure(self):
        """Test interpreting ERROR_LOGON_FAILURE code.

        NOTE: This code should never appear via RPC in practice (Windows doesn't
        record auth failures), but we handle it for robustness.
        """
        last_run = datetime(2024, 1, 1)
        status, valid, hijackable, detail = self.rpc._interpret_return_code(
            0x8007052E, last_run
        )
        assert status == CredentialStatus.INVALID
        assert valid is False
        assert hijackable is False
        assert "unexpected via RPC" in detail

    def test_interpret_account_disabled(self):
        """Test interpreting ERROR_ACCOUNT_DISABLED code.

        NOTE: This code should never appear via RPC in practice (Windows doesn't
        record account status failures), but we handle it for robustness.
        """
        last_run = datetime(2024, 1, 1)
        status, valid, hijackable, detail = self.rpc._interpret_return_code(
            0x80070533, last_run  # ERROR_ACCOUNT_DISABLED (Win32 0x0533)
        )
        assert status == CredentialStatus.BLOCKED
        assert valid is False
        assert hijackable is False
        assert "unexpected via RPC" in detail

    def test_interpret_unknown_code(self):
        """Test interpreting unknown code."""
        last_run = datetime(2024, 1, 1)
        status, valid, hijackable, detail = self.rpc._interpret_return_code(
            0x99999999, last_run
        )
        # Unknown code with task run - assumed valid
        assert status == CredentialStatus.VALID
        assert valid is True

    def test_interpret_none_last_run(self):
        """Test interpreting with None last_run."""
        status, valid, hijackable, detail = self.rpc._interpret_return_code(
            0x00000000, None
        )
        assert status == CredentialStatus.UNKNOWN
        assert valid is False
        assert hijackable is False
        assert "never executed" in detail.lower()


class TestTaskSchedulerRPCGetTaskRunInfo:
    """Tests for TaskSchedulerRPC.get_task_run_info method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )

    def test_get_task_run_info_not_connected(self):
        """Test get_task_run_info when not connected."""
        result = self.rpc.get_task_run_info("\\TestTask")
        assert result is None

    @patch('taskhound.smb.task_rpc.tsch')
    def test_get_task_run_info_success(self, mock_tsch):
        """Test get_task_run_info with successful response."""
        self.rpc._dce = Mock()

        mock_tsch.hSchRpcGetLastRunInfo.return_value = {
            'pLastRuntime': {
                'wYear': 2024,
                'wMonth': 1,
                'wDay': 15,
                'wHour': 10,
                'wMinute': 30,
                'wSecond': 0,
            },
            'pLastReturnCode': 0x00000000,
        }

        result = self.rpc.get_task_run_info("\\TestTask")

        assert result is not None
        assert result.task_path == "\\TestTask"
        assert result.last_run == datetime(2024, 1, 15, 10, 30, 0)
        assert result.return_code == 0
        assert result.password_valid is True

    @patch('taskhound.smb.task_rpc.tsch')
    def test_get_task_run_info_never_run(self, mock_tsch):
        """Test get_task_run_info when task never ran."""
        self.rpc._dce = Mock()

        mock_tsch.hSchRpcGetLastRunInfo.return_value = {
            'pLastRuntime': {
                'wYear': 0,
                'wMonth': 0,
                'wDay': 0,
                'wHour': 0,
                'wMinute': 0,
                'wSecond': 0,
            },
            'pLastReturnCode': 0,
        }

        result = self.rpc.get_task_run_info("\\TestTask")

        assert result is not None
        assert result.last_run is None
        assert result.credential_status == CredentialStatus.UNKNOWN

    @patch('taskhound.smb.task_rpc.tsch')
    def test_get_task_run_info_exception_not_run(self, mock_tsch):
        """Test get_task_run_info with SCHED_S_TASK_HAS_NOT_RUN exception."""
        self.rpc._dce = Mock()

        mock_tsch.hSchRpcGetLastRunInfo.side_effect = Exception(
            "SCHED_S_TASK_HAS_NOT_RUN"
        )

        result = self.rpc.get_task_run_info("\\TestTask")

        assert result is not None
        assert result.last_run is None
        assert result.return_code == 0x00041303
        assert result.credential_status == CredentialStatus.UNKNOWN

    @patch('taskhound.smb.task_rpc.tsch')
    def test_get_task_run_info_exception_other(self, mock_tsch):
        """Test get_task_run_info with other exception."""
        self.rpc._dce = Mock()

        mock_tsch.hSchRpcGetLastRunInfo.side_effect = Exception("Connection failed")

        result = self.rpc.get_task_run_info("\\TestTask")

        assert result is None


class TestTaskSchedulerRPCValidateSpecificTasks:
    """Tests for TaskSchedulerRPC.validate_specific_tasks method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )
        self.rpc._dce = Mock()

    @patch.object(TaskSchedulerRPC, 'get_task_run_info')
    def test_validate_smb_path_conversion(self, mock_get_info):
        """Test SMB path to RPC path conversion."""
        mock_get_info.return_value = TaskRunInfo(
            task_path="\\TestTask",
            last_run=datetime(2024, 1, 1),
            return_code=0,
            credential_status=CredentialStatus.VALID,
            status_detail="OK",
            password_valid=True,
            task_hijackable=True,
        )

        self.rpc.validate_specific_tasks([
            "Windows\\System32\\Tasks\\TestTask"
        ])

        # Should have called with converted RPC path
        mock_get_info.assert_called_once_with("\\TestTask")

    @patch.object(TaskSchedulerRPC, 'get_task_run_info')
    def test_validate_smb_path_forward_slash(self, mock_get_info):
        """Test SMB path with forward slashes."""
        mock_get_info.return_value = TaskRunInfo(
            task_path="\\TestTask",
            last_run=datetime(2024, 1, 1),
            return_code=0,
            credential_status=CredentialStatus.VALID,
            status_detail="OK",
            password_valid=True,
            task_hijackable=True,
        )

        self.rpc.validate_specific_tasks([
            "Windows/System32/Tasks/TestTask"
        ])

        mock_get_info.assert_called_once_with("\\TestTask")

    @patch.object(TaskSchedulerRPC, 'get_task_run_info')
    def test_validate_rpc_path_already_formatted(self, mock_get_info):
        """Test path already in RPC format."""
        mock_get_info.return_value = TaskRunInfo(
            task_path="\\TestTask",
            last_run=datetime(2024, 1, 1),
            return_code=0,
            credential_status=CredentialStatus.VALID,
            status_detail="OK",
            password_valid=True,
            task_hijackable=True,
        )

        self.rpc.validate_specific_tasks(["\\TestTask"])

        mock_get_info.assert_called_once_with("\\TestTask")

    @patch.object(TaskSchedulerRPC, 'get_task_run_info')
    def test_validate_multiple_tasks(self, mock_get_info):
        """Test validating multiple tasks."""
        mock_get_info.return_value = TaskRunInfo(
            task_path="\\Task1",
            last_run=datetime(2024, 1, 1),
            return_code=0,
            credential_status=CredentialStatus.VALID,
            status_detail="OK",
            password_valid=True,
            task_hijackable=True,
        )

        self.rpc.validate_specific_tasks([
            "Windows\\System32\\Tasks\\Task1",
            "Windows\\System32\\Tasks\\Task2",
        ])

        assert mock_get_info.call_count == 2

    @patch.object(TaskSchedulerRPC, 'get_task_run_info')
    def test_validate_task_returns_none(self, mock_get_info):
        """Test when get_task_run_info returns None."""
        mock_get_info.return_value = None

        results = self.rpc.validate_specific_tasks([
            "Windows\\System32\\Tasks\\NonExistentTask"
        ])

        # Should not add to results
        assert len(results) == 0

    @patch.object(TaskSchedulerRPC, 'get_task_run_info')
    def test_validate_preserves_original_path(self, mock_get_info):
        """Test that results contain original SMB paths only (not duplicated with RPC path)."""
        mock_info = TaskRunInfo(
            task_path="\\TestTask",
            last_run=datetime(2024, 1, 1),
            return_code=0,
            credential_status=CredentialStatus.VALID,
            status_detail="OK",
            password_valid=True,
            task_hijackable=True,
        )
        mock_get_info.return_value = mock_info

        original_path = "Windows\\System32\\Tasks\\TestTask"
        results = self.rpc.validate_specific_tasks([original_path])

        # Should have only the original SMB path (no duplication with RPC path)
        assert original_path in results
        assert len(results) == 1  # Only one entry, not duplicated


class TestTaskSchedulerRPCConnect:
    """Tests for TaskSchedulerRPC.connect method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.rpc = TaskSchedulerRPC(
            target="192.168.1.100",
            domain="DOMAIN",
            username="admin",
            password="pass",
        )

    @patch('taskhound.smb.task_rpc.transport')
    @patch('taskhound.smb.task_rpc.tsch')
    def test_connect_success(self, mock_tsch, mock_transport):
        """Test successful connection."""
        mock_dce = Mock()
        mock_rpc_transport = Mock()
        mock_rpc_transport.get_dce_rpc.return_value = mock_dce
        mock_transport.DCERPCTransportFactory.return_value = mock_rpc_transport

        result = self.rpc.connect()

        assert result is True
        assert self.rpc._dce is mock_dce
        mock_dce.connect.assert_called_once()
        mock_dce.bind.assert_called_once()

    @patch('taskhound.smb.task_rpc.transport')
    def test_connect_failure(self, mock_transport):
        """Test connection failure."""
        mock_transport.DCERPCTransportFactory.side_effect = Exception("Connection refused")

        result = self.rpc.connect()

        assert result is False
        assert self.rpc._dce is None


class TestCredentialConfidence:
    """Tests for CredentialConfidence enum."""

    def test_definitely_stale_status(self):
        """Test DEFINITELY_STALE status value."""
        assert CredentialConfidence.DEFINITELY_STALE.value == "definitely_stale"

    def test_high_confidence_valid_status(self):
        """Test HIGH_CONFIDENCE_VALID status value."""
        assert CredentialConfidence.HIGH_CONFIDENCE_VALID.value == "high_confidence"

    def test_confirmed_valid_status(self):
        """Test CONFIRMED_VALID status value."""
        assert CredentialConfidence.CONFIRMED_VALID.value == "confirmed_valid"

    def test_likely_valid_status(self):
        """Test LIKELY_VALID status value."""
        assert CredentialConfidence.LIKELY_VALID.value == "likely_valid"

    def test_possibly_stale_status(self):
        """Test POSSIBLY_STALE status value."""
        assert CredentialConfidence.POSSIBLY_STALE.value == "possibly_stale"

    def test_unknown_status(self):
        """Test UNKNOWN status value."""
        assert CredentialConfidence.UNKNOWN.value == "unknown"

    def test_all_confidence_levels_exist(self):
        """Test all expected confidence levels exist."""
        expected = {
            "DEFINITELY_STALE",
            "HIGH_CONFIDENCE_VALID",
            "CONFIRMED_VALID",
            "LIKELY_VALID",
            "POSSIBLY_STALE",
            "UNKNOWN",
        }
        actual = {c.name for c in CredentialConfidence}
        assert actual == expected


class TestCredentialContext:
    """Tests for CredentialContext dataclass."""

    def test_create_empty_context(self):
        """Test creating CredentialContext with defaults."""
        context = CredentialContext()
        assert context.pwd_last_set is None
        assert context.task_creation_date is None
        assert context.trigger_interval_days is None
        assert context.current_time is not None  # Should default to now

    def test_create_full_context(self):
        """Test creating CredentialContext with all fields."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        context = CredentialContext(
            pwd_last_set=datetime(2025, 12, 1),
            task_creation_date=datetime(2025, 11, 1),
            trigger_interval_days=1,
            current_time=now,
        )
        assert context.pwd_last_set == datetime(2025, 12, 1)
        assert context.task_creation_date == datetime(2025, 11, 1)
        assert context.trigger_interval_days == 1
        assert context.current_time == now


class TestCalculateConfidence:
    """Tests for calculate_confidence function."""

    def _make_run_info(self, last_run, status=CredentialStatus.VALID):
        """Helper to create TaskRunInfo objects."""
        return TaskRunInfo(
            task_path="\\TestTask",
            last_run=last_run,
            return_code=0x0,
            credential_status=status,
            status_detail="SUCCESS",
            password_valid=True,
            task_hijackable=True,
        )

    def test_unknown_when_never_ran(self):
        """Test UNKNOWN confidence when task has never run."""
        run_info = self._make_run_info(None)
        run_info.credential_status = CredentialStatus.UNKNOWN

        confidence, reason = calculate_confidence(run_info, None)

        assert confidence == CredentialConfidence.UNKNOWN
        assert "never run" in reason.lower()

    def test_unknown_when_blocked(self):
        """Test UNKNOWN confidence when account is blocked."""
        run_info = self._make_run_info(datetime(2026, 1, 1))
        run_info.credential_status = CredentialStatus.BLOCKED

        confidence, reason = calculate_confidence(run_info, None)

        assert confidence == CredentialConfidence.UNKNOWN
        assert "blocked" in reason.lower()

    def test_definitely_stale_when_invalid_status(self):
        """Test DEFINITELY_STALE when status is INVALID."""
        run_info = self._make_run_info(datetime(2026, 1, 1))
        run_info.credential_status = CredentialStatus.INVALID

        confidence, reason = calculate_confidence(run_info, None)

        assert confidence == CredentialConfidence.DEFINITELY_STALE
        assert "invalid" in reason.lower()

    def test_likely_valid_without_context(self):
        """Test LIKELY_VALID when no context is provided."""
        run_info = self._make_run_info(datetime(2026, 1, 1))

        confidence, reason = calculate_confidence(run_info, None)

        assert confidence == CredentialConfidence.LIKELY_VALID
        assert "no ad context" in reason.lower()

    def test_definitely_stale_pwd_changed_after_last_run(self):
        """Test DEFINITELY_STALE when password changed after last run."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2026, 1, 1, 12, 0))  # Ran Jan 1
        context = CredentialContext(
            pwd_last_set=datetime(2026, 1, 2, 15, 0),  # Password changed Jan 2
            current_time=now,
        )

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.DEFINITELY_STALE
        assert "changed" in reason.lower()
        assert "2026-01-01" in reason

    def test_high_confidence_pwd_unchanged_but_no_trigger(self):
        """Test HIGH_CONFIDENCE_VALID when password unchanged but trigger timing unknown."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2026, 1, 2, 12, 0))
        context = CredentialContext(
            pwd_last_set=datetime(2025, 6, 15),  # Password set long ago
            task_creation_date=datetime(2025, 12, 1),  # Task created after pwd
            # No trigger_interval_days - can't verify execution timing
            current_time=now,
        )

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.HIGH_CONFIDENCE_VALID
        assert "unchanged" in reason.lower()
        assert "trigger timing unknown" in reason.lower()

    def test_confirmed_valid_pwd_unchanged_and_ran_within_schedule(self):
        """Test CONFIRMED_VALID when password unchanged AND task ran within schedule."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2026, 1, 3, 8, 0))  # Ran today
        context = CredentialContext(
            pwd_last_set=datetime(2025, 6, 15),  # Password set long ago
            task_creation_date=datetime(2025, 11, 1),  # Task created after pwd change
            trigger_interval_days=1,  # Daily task
            current_time=now,
        )

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.CONFIRMED_VALID
        assert "unchanged since task creation" in reason.lower()
        assert "within schedule" in reason.lower()

    def test_likely_valid_pwd_changed_but_task_still_runs(self):
        """Test LIKELY_VALID when password changed but task still runs within schedule."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2026, 1, 3, 8, 0))  # Ran today
        context = CredentialContext(
            pwd_last_set=datetime(2026, 1, 1, 10, 0),  # Password changed Jan 1
            task_creation_date=datetime(2025, 11, 1),  # Task created before pwd change
            trigger_interval_days=1,  # Daily task
            current_time=now,
        )

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.LIKELY_VALID
        assert "changed after task creation" in reason.lower()
        assert "within schedule" in reason.lower()

    def test_likely_valid_within_schedule(self):
        """Test LIKELY_VALID when task ran within expected schedule."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2026, 1, 2, 12, 0))  # Ran yesterday
        context = CredentialContext(
            trigger_interval_days=1,  # Daily task
            current_time=now,
        )

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.LIKELY_VALID
        assert "1d ago" in reason

    def test_possibly_stale_outside_schedule(self):
        """Test POSSIBLY_STALE when task hasn't run within expected schedule."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2025, 12, 20, 12, 0))  # Ran 14 days ago
        context = CredentialContext(
            trigger_interval_days=1,  # Daily task - should have run 14 times!
            current_time=now,
        )

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.POSSIBLY_STALE
        assert "missed" in reason.lower()

    def test_possibly_stale_pwd_unchanged_but_missed_schedule(self):
        """Test POSSIBLY_STALE when password unchanged but task missed its schedule."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2025, 12, 20, 12, 0))  # Ran 14 days ago
        context = CredentialContext(
            pwd_last_set=datetime(2025, 6, 15),  # Password unchanged
            task_creation_date=datetime(2025, 11, 1),  # Task created after pwd
            trigger_interval_days=1,  # Daily task - should have run 14 times!
            current_time=now,
        )

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.POSSIBLY_STALE
        assert "password unchanged" in reason.lower()
        assert "missed" in reason.lower()

    def test_high_confidence_valid_pwd_unchanged_since_run(self):
        """Test HIGH_CONFIDENCE_VALID when password unchanged since last run (no schedule)."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2026, 1, 2, 12, 0))
        context = CredentialContext(
            pwd_last_set=datetime(2026, 1, 1, 10, 0),  # Password set before last run
            current_time=now,
        )

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.HIGH_CONFIDENCE_VALID
        assert "unchanged since last successful run" in reason.lower()

    def test_fallback_recent_run(self):
        """Test LIKELY_VALID fallback for recent run with limited context."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2026, 1, 1, 12, 0))  # 2 days ago
        context = CredentialContext(current_time=now)  # Empty context

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.LIKELY_VALID
        assert "2d ago" in reason

    def test_fallback_old_run(self):
        """Test POSSIBLY_STALE fallback for old run with limited context."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = self._make_run_info(datetime(2025, 11, 1, 12, 0))  # 63 days ago
        context = CredentialContext(current_time=now)  # Empty context

        confidence, reason = calculate_confidence(run_info, context)

        assert confidence == CredentialConfidence.POSSIBLY_STALE
        assert "63d ago" in reason


class TestEnrichWithConfidence:
    """Tests for enrich_with_confidence function."""

    def test_enriches_run_info_in_place(self):
        """Test that enrich_with_confidence modifies the object in place."""
        run_info = TaskRunInfo(
            task_path="\\TestTask",
            last_run=datetime(2026, 1, 1),
            return_code=0x0,
            credential_status=CredentialStatus.VALID,
            status_detail="SUCCESS",
            password_valid=True,
            task_hijackable=True,
        )

        # Initially should be UNKNOWN with empty reason
        assert run_info.confidence == CredentialConfidence.UNKNOWN
        assert run_info.confidence_reason == ""

        result = enrich_with_confidence(run_info)

        # Should be enriched
        assert result is run_info  # Same object
        assert run_info.confidence == CredentialConfidence.LIKELY_VALID
        assert run_info.confidence_reason != ""

    def test_enriches_with_context(self):
        """Test enrich_with_confidence with additional context."""
        now = datetime(2026, 1, 3, 12, 0, 0)
        run_info = TaskRunInfo(
            task_path="\\TestTask",
            last_run=datetime(2026, 1, 1),
            return_code=0x0,
            credential_status=CredentialStatus.VALID,
            status_detail="SUCCESS",
            password_valid=True,
            task_hijackable=True,
        )
        context = CredentialContext(
            pwd_last_set=datetime(2026, 1, 2),  # Password changed AFTER last run
            current_time=now,
        )

        result = enrich_with_confidence(run_info, context)

        assert result.confidence == CredentialConfidence.DEFINITELY_STALE
        assert "changed" in result.confidence_reason.lower()
