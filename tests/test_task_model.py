# Tests for TaskRow dataclass.


from taskhound.models.task import TaskRow, TaskType


class TestTaskType:
    """Tests for TaskType enum."""

    def test_tier0_value(self):
        assert TaskType.TIER0.value == "TIER-0"

    def test_priv_value(self):
        assert TaskType.PRIV.value == "PRIV"

    def test_task_value(self):
        assert TaskType.TASK.value == "TASK"

    def test_failure_value(self):
        assert TaskType.FAILURE.value == "FAILURE"

    def test_is_string_enum(self):
        # TaskType should be usable as a string
        assert TaskType.TIER0 == "TIER-0"
        assert TaskType.PRIV == "PRIV"


class TestTaskRowBasic:
    """Basic TaskRow construction tests."""

    def test_minimal_construction(self):
        row = TaskRow(host="DC.example.com", path="Windows\\System32\\Tasks\\Test")
        assert row.host == "DC.example.com"
        assert row.path == "Windows\\System32\\Tasks\\Test"
        assert row.type == "TASK"  # Default

    def test_default_values(self):
        row = TaskRow(host="host", path="path")
        assert row.target_ip is None
        assert row.computer_sid is None
        assert row.type == "TASK"
        assert row.reason is None
        assert row.runas is None
        assert row.command is None
        assert row.credentials_hint is None
        assert row.credential_guard is None
        assert row.cred_status is None

    def test_full_construction(self):
        row = TaskRow(
            host="DC.example.com",
            path="Test\\MyTask",
            target_ip="192.168.1.1",
            computer_sid="S-1-5-21-123-456-789-1001",
            type=TaskType.TIER0.value,
            reason="Domain Admin",
            runas="DOMAIN\\admin",
            command="cmd.exe",
            arguments="/c whoami",
            author="DOMAIN\\creator",
            date="2024-01-15T10:00:00",
            logon_type="Password",
            enabled="true",
            credentials_hint="stored_credentials",
            credential_guard=False,
            password_analysis="HIGH: Password older than task",
        )
        assert row.host == "DC.example.com"
        assert row.type == "TIER-0"
        assert row.reason == "Domain Admin"
        assert row.credential_guard is False


class TestTaskRowToDict:
    """Tests for TaskRow.to_dict() method."""

    def test_to_dict_minimal(self):
        row = TaskRow(host="host", path="path")
        d = row.to_dict()

        assert isinstance(d, dict)
        assert d["host"] == "host"
        assert d["path"] == "path"
        assert d["type"] == "TASK"
        assert d["runas"] is None

    def test_to_dict_includes_all_fields(self):
        row = TaskRow(
            host="DC.example.com",
            path="Test",
            target_ip="192.168.1.1",
            type=TaskType.PRIV.value,
            reason="High Value",
            cred_status="valid",
            cred_password_valid=True,
        )
        d = row.to_dict()

        # Check all expected keys exist
        expected_keys = {
            "host", "path", "target_ip", "computer_sid", "type", "reason",
            "password_analysis", "runas", "resolved_runas", "resolved_runas_sid",
            "command", "arguments", "author",
            "date", "logon_type", "enabled", "trigger_type", "start_boundary",
            "interval", "duration", "days_interval", "credentials_hint",
            "credential_guard", "cred_status", "cred_password_valid",
            "cred_hijackable", "cred_last_run", "cred_return_code", "cred_detail",
            "decrypted_password"
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_preserves_values(self):
        row = TaskRow(
            host="DC.example.com",
            path="Test",
            cred_password_valid=True,
            credential_guard=False,
        )
        d = row.to_dict()

        assert d["cred_password_valid"] is True
        assert d["credential_guard"] is False


class TestTaskRowFromMeta:
    """Tests for TaskRow.from_meta() factory method."""

    def test_from_meta_basic(self):
        meta = {
            "runas": "DOMAIN\\user",
            "command": "notepad.exe",
            "arguments": "test.txt",
            "author": "admin",
            "date": "2024-01-15",
            "logon_type": "Password",
            "enabled": "true",
        }
        row = TaskRow.from_meta("DC.example.com", "Test\\Task", meta)

        assert row.host == "DC.example.com"
        assert row.path == "Test\\Task"
        assert row.runas == "DOMAIN\\user"
        assert row.command == "notepad.exe"
        assert row.arguments == "test.txt"
        assert row.credentials_hint == "stored_credentials"

    def test_from_meta_with_target_ip_and_sid(self):
        meta = {"runas": "user", "logon_type": "Password"}
        row = TaskRow.from_meta(
            "DC.example.com",
            "Test",
            meta,
            target_ip="192.168.1.1",
            computer_sid="S-1-5-21-123",
        )

        assert row.target_ip == "192.168.1.1"
        assert row.computer_sid == "S-1-5-21-123"

    def test_from_meta_password_logon_type(self):
        meta = {"logon_type": "Password"}
        row = TaskRow.from_meta("host", "path", meta)
        assert row.credentials_hint == "stored_credentials"

    def test_from_meta_password_logon_type_mixed_case(self):
        meta = {"logon_type": "PASSWORD"}
        row = TaskRow.from_meta("host", "path", meta)
        assert row.credentials_hint == "stored_credentials"

    def test_from_meta_interactive_token_logon_type(self):
        meta = {"logon_type": "InteractiveToken"}
        row = TaskRow.from_meta("host", "path", meta)
        assert row.credentials_hint == "no_saved_credentials"

    def test_from_meta_s4u_logon_type(self):
        meta = {"logon_type": "S4U"}
        row = TaskRow.from_meta("host", "path", meta)
        assert row.credentials_hint == "no_saved_credentials"

    def test_from_meta_interactive_logon_type(self):
        meta = {"logon_type": "Interactive"}
        row = TaskRow.from_meta("host", "path", meta)
        assert row.credentials_hint == "no_saved_credentials"

    def test_from_meta_unknown_logon_type(self):
        meta = {"logon_type": "SomeNewType"}
        row = TaskRow.from_meta("host", "path", meta)
        assert row.credentials_hint is None

    def test_from_meta_no_logon_type(self):
        meta = {"runas": "user"}
        row = TaskRow.from_meta("host", "path", meta)
        assert row.credentials_hint is None

    def test_from_meta_empty_meta(self):
        row = TaskRow.from_meta("host", "path", {})
        assert row.runas is None
        assert row.command is None
        assert row.credentials_hint is None

    def test_from_meta_logon_type_with_whitespace(self):
        meta = {"logon_type": "  Password  "}
        row = TaskRow.from_meta("host", "path", meta)
        assert row.credentials_hint == "stored_credentials"


class TestTaskRowFailure:
    """Tests for TaskRow.failure() factory method."""

    def test_failure_basic(self):
        row = TaskRow.failure("192.168.1.1", "SMB connection failed")

        assert row.host == "192.168.1.1"
        assert row.path == ""
        assert row.type == "FAILURE"
        assert row.reason == "SMB connection failed"

    def test_failure_with_target_ip(self):
        row = TaskRow.failure(
            "DC.example.com",
            "Access Denied",
            target_ip="192.168.1.1",
        )

        assert row.host == "DC.example.com"
        assert row.target_ip == "192.168.1.1"
        assert row.type == "FAILURE"

    def test_failure_type_is_failure_enum(self):
        row = TaskRow.failure("host", "error")
        assert row.type == TaskType.FAILURE.value
        assert row.type == "FAILURE"


class TestTaskRowMutation:
    """Tests for TaskRow field mutations (as done in engine.py)."""

    def test_can_set_type(self):
        row = TaskRow(host="host", path="path")
        assert row.type == "TASK"

        row.type = TaskType.TIER0.value
        assert row.type == "TIER-0"

    def test_can_set_reason(self):
        row = TaskRow(host="host", path="path")
        row.reason = "Domain Admin; Enterprise Admin"
        assert row.reason == "Domain Admin; Enterprise Admin"

    def test_can_set_password_analysis(self):
        row = TaskRow(host="host", path="path")
        row.password_analysis = "HIGH: Password older than task creation"
        assert row.password_analysis == "HIGH: Password older than task creation"

    def test_can_set_credentials_hint(self):
        row = TaskRow(host="host", path="path")
        row.credentials_hint = "no_saved_credentials"
        assert row.credentials_hint == "no_saved_credentials"

    def test_can_set_cred_validation_fields(self):
        row = TaskRow(host="host", path="path")
        row.cred_status = "valid"
        row.cred_password_valid = True
        row.cred_hijackable = True
        row.cred_last_run = "2024-01-15T10:00:00"
        row.cred_return_code = "0x00000000"
        row.cred_detail = "Password VALID - task can be hijacked"

        assert row.cred_status == "valid"
        assert row.cred_password_valid is True
        assert row.cred_hijackable is True
        assert row.cred_detail == "Password VALID - task can be hijacked"

    def test_can_set_credential_guard(self):
        row = TaskRow(host="host", path="path")
        row.credential_guard = True
        assert row.credential_guard is True


class TestTaskRowCompatibility:
    """Tests ensuring TaskRow is compatible with existing code patterns."""

    def test_to_dict_works_with_json_dump(self):
        import json

        row = TaskRow(
            host="DC.example.com",
            path="Test",
            type=TaskType.TIER0.value,
            cred_password_valid=True,
        )
        # Should not raise
        json_str = json.dumps(row.to_dict())
        assert "DC.example.com" in json_str
        assert "TIER-0" in json_str

    def test_to_dict_works_with_csv_dictwriter(self):
        import csv
        import io

        row = TaskRow(host="DC.example.com", path="Test", runas="admin")
        d = row.to_dict()

        # Should work with DictWriter
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(d.keys()))
        writer.writeheader()
        writer.writerow(d)

        csv_content = output.getvalue()
        assert "DC.example.com" in csv_content
        assert "admin" in csv_content

    def test_dict_access_pattern_via_to_dict(self):
        """Ensure code using row["field"] pattern can migrate to row.to_dict()["field"]."""
        row = TaskRow(host="host", path="path", runas="admin")
        d = row.to_dict()

        # Old pattern: row["runas"]
        # New pattern: row.runas or row.to_dict()["runas"]
        assert d["runas"] == "admin"
        assert row.runas == "admin"
