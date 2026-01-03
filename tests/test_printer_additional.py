"""
Additional tests to boost coverage for printer module.
"""
from unittest.mock import patch

from taskhound.output.printer import (
    _check_gmsa_account,
    format_block,
    format_trigger_info,
)


class TestFormatTriggerInfoAdditional:
    """Additional trigger info tests for coverage."""

    def test_calendar_with_singular_day_duration(self):
        """Test calendar with 1 day duration shows 'day' not 'days'."""
        meta = {
            "trigger_type": "Calendar",
            "duration": "P1D",
        }
        result = format_trigger_info(meta)
        assert "for 1 day" in result
        assert "days" not in result

    def test_time_trigger_with_unparseable_date(self):
        """Test time trigger falls back to raw date on parse error."""
        meta = {
            "trigger_type": "Time",
            "start_boundary": "not-a-date",
        }
        result = format_trigger_info(meta)
        assert "at not-a-date" in result

    def test_trigger_type_only_returns_just_type(self):
        """Test trigger with no details returns just the type."""
        meta = {"trigger_type": "Logon"}
        result = format_trigger_info(meta)
        assert result == "Logon"


class TestCheckGMSAAccount:
    """Tests for _check_gmsa_account function."""

    def test_returns_none_for_empty_runas(self):
        """Should return None for empty runas."""
        assert _check_gmsa_account("") is None
        assert _check_gmsa_account(None) is None

    def test_returns_none_for_regular_account(self):
        """Should return None for regular user account."""
        assert _check_gmsa_account("DOMAIN\\admin") is None
        assert _check_gmsa_account("user@domain.local") is None

    def test_returns_hint_for_gmsa_account(self):
        """Should return hint for gMSA account ending with $."""
        result = _check_gmsa_account("DOMAIN\\gMSASvc$")
        assert result is not None
        assert "LSA secrets" in result
        assert "DPAPI" in result

    def test_skips_system_account(self):
        """Should skip NT AUTHORITY\\SYSTEM even though it ends with ."""
        # Note: SYSTEM doesn't end with $, but testing the skip logic
        assert _check_gmsa_account("NT AUTHORITY\\SYSTEM") is None

    def test_skips_local_service(self):
        """Should skip local service accounts."""
        assert _check_gmsa_account("NT AUTHORITY\\Local Service") is None
        assert _check_gmsa_account("NT AUTHORITY\\Network Service") is None

    def test_uses_resolved_username(self):
        """Should use resolved username if provided."""
        result = _check_gmsa_account("S-1-5-21-xxx", resolved_username="gMSASvc$")
        assert result is not None
        assert "LSA secrets" in result


class TestFormatBlockEnabled:
    """Tests for enabled field formatting."""

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_enabled_true_capitalized(self, mock_resolve):
        """Should capitalize True for enabled field."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\Test",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            enabled="true",
        )

        text = "\n".join(lines)
        assert "Enabled            : True" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_enabled_false_capitalized(self, mock_resolve):
        """Should capitalize False for enabled field."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\Test",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            enabled="false",
        )

        text = "\n".join(lines)
        assert "Enabled            : False" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_enabled_other_value_unchanged(self, mock_resolve):
        """Should keep other enabled values unchanged."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\Test",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            enabled="Disabled",
        )

        text = "\n".join(lines)
        assert "Enabled            : Disabled" in text


class TestFormatBlockCredValidationDetails:
    """Additional credential validation tests."""

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_shows_last_run_time(self, mock_resolve):
        """Should show last run time in cred validation."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Test",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            cred_validation={
                "cred_status": "valid",
                "cred_password_valid": True,
                "cred_hijackable": True,
                "cred_last_run": "2023-06-15 10:30:00",
            },
        )

        text = "\n".join(lines)
        assert "Last Run           : 2023-06-15 10:30:00" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_shows_return_code_with_description(self, mock_resolve):
        """Should show return code with description."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Test",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            cred_validation={
                "cred_status": "unknown",
                "cred_return_code": "0x00041303",
            },
        )

        text = "\n".join(lines)
        assert "Return Code        : 0x00041303" in text
        assert "Task not yet run" in text  # Updated to match new TASK_SCHEDULER_CODES
