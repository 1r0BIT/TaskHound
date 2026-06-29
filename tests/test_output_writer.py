"""
Test suite for output writer functions.

Tests cover:
- _rows_to_dicts helper function
- write_json function
- write_csv function
- write_rich_plain function
"""

import csv
import json
from unittest.mock import MagicMock, patch

import pytest

from taskhound.output.writer import (
    _format_task_table,
    _rows_to_dicts,
    write_csv,
    write_json,
    write_rich_plain,
)

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create a temporary directory for output files"""
    return tmp_path


@pytest.fixture
def sample_task_dict():
    """Sample task as dictionary"""
    return {
        "host": "DC01.example.com",
        "path": "\\BackupTask",
        "type": "PRIV",
        "runas": "EXAMPLE\\backupuser",
        "command": "backup.exe",
        "arguments": "-full",
        "author": "Administrator",
        "date": "2024-01-15",
        "logon_type": "Password",
        "enabled": "true"
    }


@pytest.fixture
def sample_task_object():
    """Sample task as object with to_dict method"""
    task = MagicMock()
    task.to_dict.return_value = {
        "host": "WS01.example.com",
        "path": "\\MaintTask",
        "type": "TASK"
    }
    return task


# ============================================================================
# Unit Tests: _rows_to_dicts
# ============================================================================


class TestRowsToDicts:
    """Tests for _rows_to_dicts helper function"""

    def test_empty_list(self):
        """Should return empty list for empty input"""
        result = _rows_to_dicts([])
        assert result == []

    def test_dict_passthrough(self, sample_task_dict):
        """Should pass dictionaries through unchanged"""
        result = _rows_to_dicts([sample_task_dict])
        assert result == [sample_task_dict]

    def test_object_with_to_dict(self, sample_task_object):
        """Should call to_dict on objects that have it"""
        result = _rows_to_dicts([sample_task_object])

        sample_task_object.to_dict.assert_called_once()
        assert result == [{"host": "WS01.example.com", "path": "\\MaintTask", "type": "TASK"}]

    def test_mixed_objects_and_dicts(self, sample_task_dict, sample_task_object):
        """Should handle mixed list of dicts and objects"""
        result = _rows_to_dicts([sample_task_dict, sample_task_object])

        assert len(result) == 2
        assert result[0] == sample_task_dict
        assert result[1] == {"host": "WS01.example.com", "path": "\\MaintTask", "type": "TASK"}


# ============================================================================
# Unit Tests: write_json
# ============================================================================


class TestWriteJson:
    """Tests for write_json function"""

    @patch('taskhound.output.writer.good')
    def test_writes_json_file(self, mock_good, temp_output_dir, sample_task_dict):
        """Should write JSON file with proper formatting"""
        output_file = temp_output_dir / "output.json"

        write_json(str(output_file), [sample_task_dict])

        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)

        assert len(data) == 1
        assert data[0]["host"] == "DC01.example.com"

    @patch('taskhound.output.writer.good')
    def test_empty_list_writes_empty_array(self, mock_good, temp_output_dir):
        """Should write empty JSON array for empty input"""
        output_file = temp_output_dir / "output.json"

        write_json(str(output_file), [])

        with open(output_file) as f:
            data = json.load(f)

        assert data == []

    @patch('taskhound.output.writer.good')
    def test_json_indented(self, mock_good, temp_output_dir, sample_task_dict):
        """Should write indented JSON for readability"""
        output_file = temp_output_dir / "output.json"

        write_json(str(output_file), [sample_task_dict])

        content = output_file.read_text()
        # Indented JSON has newlines and spaces
        assert "\n" in content
        assert "  " in content

    @patch('taskhound.output.writer.good')
    def test_converts_objects(self, mock_good, temp_output_dir, sample_task_object):
        """Should convert objects with to_dict method"""
        output_file = temp_output_dir / "output.json"

        write_json(str(output_file), [sample_task_object])

        with open(output_file) as f:
            data = json.load(f)

        assert data[0]["host"] == "WS01.example.com"

    @patch('taskhound.output.writer.good')
    def test_logs_success_message(self, mock_good, temp_output_dir):
        """Should log success message"""
        output_file = temp_output_dir / "output.json"

        write_json(str(output_file), [])

        mock_good.assert_called_once()
        call_arg = mock_good.call_args[0][0]
        assert "Wrote JSON results to" in call_arg


# ============================================================================
# Unit Tests: write_csv
# ============================================================================


class TestWriteCsv:
    """Tests for write_csv function"""

    @patch('taskhound.output.writer.good')
    def test_writes_csv_file(self, mock_good, temp_output_dir, sample_task_dict):
        """Should write CSV file with headers"""
        output_file = temp_output_dir / "output.csv"

        write_csv(str(output_file), [sample_task_dict])

        assert output_file.exists()

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert rows[0]["host"] == "DC01.example.com"

    @patch('taskhound.output.writer.good')
    def test_csv_headers_present(self, mock_good, temp_output_dir):
        """Should write CSV with all expected headers"""
        output_file = temp_output_dir / "output.csv"

        write_csv(str(output_file), [])

        with open(output_file) as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames

        expected_fields = [
            "host", "target_ip", "computer_sid", "path", "type",
            "runas", "command", "arguments", "author", "date",
            "logon_type", "enabled", "trigger_type"
        ]
        for field in expected_fields:
            assert field in fieldnames

    @patch('taskhound.output.writer.good')
    def test_empty_list_writes_headers_only(self, mock_good, temp_output_dir):
        """Should write headers even with empty input"""
        output_file = temp_output_dir / "output.csv"

        write_csv(str(output_file), [])

        content = output_file.read_text()
        assert "host" in content
        assert "path" in content

    @patch('taskhound.output.writer.good')
    def test_converts_objects(self, mock_good, temp_output_dir, sample_task_object):
        """Should convert objects with to_dict method"""
        output_file = temp_output_dir / "output.csv"

        write_csv(str(output_file), [sample_task_object])

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert rows[0]["host"] == "WS01.example.com"

    @patch('taskhound.output.writer.good')
    def test_logs_success_message(self, mock_good, temp_output_dir):
        """Should log success message"""
        output_file = temp_output_dir / "output.csv"

        write_csv(str(output_file), [])

        mock_good.assert_called_once()
        call_arg = mock_good.call_args[0][0]
        assert "Wrote CSV results to" in call_arg

    @patch('taskhound.output.writer.good')
    def test_multiple_rows(self, mock_good, temp_output_dir, sample_task_dict):
        """Should handle multiple rows"""
        output_file = temp_output_dir / "output.csv"

        task2 = sample_task_dict.copy()
        task2["host"] = "WS02.example.com"

        write_csv(str(output_file), [sample_task_dict, task2])

        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["host"] == "DC01.example.com"
        assert rows[1]["host"] == "WS02.example.com"


# ============================================================================
# Unit Tests: write_rich_plain
# ============================================================================


class TestWriteRichPlain:
    """Tests for write_rich_plain function"""

    @patch('taskhound.output.writer.good')
    def test_creates_output_directory(self, mock_good, temp_output_dir):
        """Should create output directory if it doesn't exist"""
        subdir = temp_output_dir / "nested" / "output"
        rows = [{"host": "DC01.example.com", "path": "\\Task1", "type": "TASK"}]

        write_rich_plain(str(subdir), rows)

        assert subdir.exists()

    @patch('taskhound.output.writer.good')
    def test_writes_summary_and_host_dirs(self, mock_good, temp_output_dir):
        """Should write summary.txt and create host subdirectories"""
        rows = [
            {"host": "DC01.example.com", "path": "\\Task1", "type": "TASK"},
            {"host": "DC01.example.com", "path": "\\Task2", "type": "PRIV"},
            {"host": "WS01.example.com", "path": "\\Task3", "type": "TIER-0"},
        ]

        write_rich_plain(str(temp_output_dir), rows)

        # Check summary file exists
        assert (temp_output_dir / "summary.txt").exists()
        # Check host subdirectories with tasks.txt
        assert (temp_output_dir / "DC01.example.com" / "tasks.txt").exists()
        assert (temp_output_dir / "WS01.example.com" / "tasks.txt").exists()

    @patch('taskhound.output.writer.good')
    def test_includes_task_type_in_output(self, mock_good, temp_output_dir):
        """Should include task type tags in output"""
        rows = [
            {"host": "DC01.example.com", "path": "\\Task1", "type": "TIER-0", "reason": "High privilege"},
        ]

        write_rich_plain(str(temp_output_dir), rows)

        content = (temp_output_dir / "DC01.example.com" / "tasks.txt").read_text()
        assert "TIER-0" in content
        assert "Task1" in content

    @patch('taskhound.output.writer.good')
    def test_includes_decrypted_password(self, mock_good, temp_output_dir):
        """Should include decrypted password in output"""
        rows = [
            {
                "host": "DC01.example.com",
                "path": "\\Task1",
                "type": "PRIV",
                "runas": "DOMAIN\\user",
                "decrypted_password": "SecretPass123!",
            },
        ]

        write_rich_plain(str(temp_output_dir), rows)

        # Check in tasks file
        content = (temp_output_dir / "DC01.example.com" / "tasks.txt").read_text()
        assert "SecretPass123!" in content
        # Also check in summary
        summary = (temp_output_dir / "summary.txt").read_text()
        assert "SecretPass123!" in summary

    @patch('taskhound.output.writer.good')
    def test_sorts_by_task_type(self, mock_good, temp_output_dir):
        """Should sort tasks with TIER-0 first, then PRIV, then TASK"""
        rows = [
            {"host": "DC01.example.com", "path": "\\TaskNormal", "type": "TASK"},
            {"host": "DC01.example.com", "path": "\\TaskTier0", "type": "TIER-0"},
            {"host": "DC01.example.com", "path": "\\TaskPriv", "type": "PRIV"},
        ]

        write_rich_plain(str(temp_output_dir), rows)

        content = (temp_output_dir / "DC01.example.com" / "tasks.txt").read_text()
        # TIER-0 should appear before PRIV which should appear before TASK
        tier0_pos = content.find("TaskTier0")
        priv_pos = content.find("TaskPriv")
        task_pos = content.find("TaskNormal")

        assert tier0_pos < priv_pos < task_pos

    @patch('taskhound.output.writer.good')
    def test_handles_taskrow_objects(self, mock_good, temp_output_dir, sample_task_object):
        """Should handle TaskRow objects with to_dict method"""
        sample_task_object.to_dict.return_value = {
            "host": "WS01.example.com",
            "path": "\\MaintTask",
            "type": "TASK"
        }

        write_rich_plain(str(temp_output_dir), [sample_task_object])

        assert (temp_output_dir / "WS01.example.com" / "tasks.txt").exists()
        sample_task_object.to_dict.assert_called()

    @patch('taskhound.output.writer.good')
    def test_logs_success_message(self, mock_good, temp_output_dir):
        """Should log success message with host count"""
        rows = [
            {"host": "DC01.example.com", "path": "\\Task1", "type": "TASK"},
        ]

        write_rich_plain(str(temp_output_dir), rows)

        mock_good.assert_called_once()
        call_arg = mock_good.call_args[0][0]
        assert "Wrote results to" in call_arg
        assert "1 hosts" in call_arg

    @patch('taskhound.output.writer.good')
    def test_handles_failure_type(self, mock_good, temp_output_dir):
        """Should handle FAILURE type tasks"""
        rows = [
            {"host": "DC01.example.com", "path": "", "type": "FAILURE", "reason": "Connection refused"},
        ]

        write_rich_plain(str(temp_output_dir), rows)

        content = (temp_output_dir / "DC01.example.com" / "tasks.txt").read_text()
        assert "FAILURE" in content
        assert "Connection refused" in content

    @patch('taskhound.output.writer.good')
    def test_summary_contains_stats(self, mock_good, temp_output_dir):
        """Summary file should contain overall statistics"""
        rows = [
            {"host": "DC01.example.com", "path": "\\Task1", "type": "TIER-0"},
            {"host": "DC01.example.com", "path": "\\Task2", "type": "PRIV"},
            {"host": "WS01.example.com", "path": "\\Task3", "type": "TASK"},
        ]

        write_rich_plain(str(temp_output_dir), rows)

        summary = (temp_output_dir / "summary.txt").read_text()
        assert "Hosts Scanned" in summary
        # Summary shows "Tier-0" in table header (title case)
        assert "Tier-0" in summary
        assert "Privileged" in summary


class TestFormatTaskTable:
    """Tests for _format_task_table helper function"""

    def test_tier0_styling(self):
        """Should include TIER-0 tag in header column"""
        table = _format_task_table({"type": "TIER-0", "path": "\\Task1"})
        # Title is now in the column header, not table.title
        assert table.columns[0].header is not None
        assert "TIER-0" in str(table.columns[0].header)

    def test_priv_styling(self):
        """Should include PRIV tag in header column"""
        table = _format_task_table({"type": "PRIV", "path": "\\Task1"})
        assert "PRIV" in str(table.columns[0].header)

    def test_task_styling(self):
        """Should include TASK tag in header column"""
        table = _format_task_table({"type": "TASK", "path": "\\Task1"})
        assert "TASK" in str(table.columns[0].header)

    def test_includes_runas(self):
        """Should include RunAs in table"""
        table = _format_task_table({
            "type": "TASK",
            "path": "\\Task1",
            "runas": "DOMAIN\\user"
        })
        # Table should have rows
        assert table.row_count > 0

    def test_resolved_runas_display(self):
        """Should format resolved SID with original SID"""
        table = _format_task_table({
            "type": "TASK",
            "path": "\\Task1",
            "runas": "S-1-5-21-123-456-789-1001",
            "resolved_runas": "DOMAIN\\user"
        })
        assert table.row_count > 0

    def test_trigger_info_calendar(self):
        """Should include trigger information for calendar triggers"""
        table = _format_task_table({
            "type": "TASK",
            "path": "\\Task1",
            "trigger_type": "Calendar",
            "start_boundary": "2024-01-01T08:00:00",
            "interval": "PT30M",
            "days_interval": "1"
        })
        assert table.row_count > 0

    def test_cred_validation_with_last_run(self):
        """Should include last run time in credential validation output"""
        table = _format_task_table({
            "type": "TASK",
            "path": "\\Task1",
            "cred_status": "valid",
            "cred_password_valid": True,
            "cred_last_run": "2024-01-15T10:30:00",
            "cred_return_code": "0x0"
        })
        assert table.row_count > 0

    def test_trigger_display_formatting(self):
        """Should format trigger display with details"""
        from taskhound.output.writer import _format_trigger_display

        # Calendar with interval
        result = _format_trigger_display({
            "trigger_type": "Calendar",
            "interval": "PT5M",
            "days_interval": "1"
        })
        assert "Calendar" in result
        assert "5min" in result
        assert "daily" in result

        # Time trigger with start boundary
        result = _format_trigger_display({
            "trigger_type": "Time",
            "start_boundary": "2024-01-01T08:00:00"
        })
        assert "Time" in result
        assert "2024-01-01" in result
