"""
Tests for OpenGraph builder module.
"""
from unittest.mock import MagicMock, patch

import pytest

from taskhound.opengraph.builder import (
    _create_principal_id,
    _create_task_node,
    _create_task_object_id,
)


class TestCreateTaskObjectId:
    """Tests for _create_task_object_id function"""

    def test_basic_creation(self):
        """Should create deterministic object ID"""
        result = _create_task_object_id("DC01.DOMAIN.LAB", "\\Tasks\\UpdateTask")

        assert "DC01.DOMAIN.LAB" in result
        assert "UPDATETASK" in result
        # Should have hash component (8 hex chars)
        parts = result.split("_")
        assert len(parts) >= 3
        assert len(parts[1]) == 8  # Hash portion

    def test_deterministic_output(self):
        """Should produce same ID for same input"""
        id1 = _create_task_object_id("DC01.DOMAIN.LAB", "\\Tasks\\MyTask")
        id2 = _create_task_object_id("DC01.DOMAIN.LAB", "\\Tasks\\MyTask")

        assert id1 == id2

    def test_case_insensitive(self):
        """Should be case-insensitive for hostname"""
        id1 = _create_task_object_id("dc01.domain.lab", "\\Tasks\\MyTask")
        id2 = _create_task_object_id("DC01.DOMAIN.LAB", "\\Tasks\\MyTask")

        # Hash portion should be the same (both get uppercased internally)
        # The hostname preserves original case in output
        parts1 = id1.split("_")
        parts2 = id2.split("_")
        assert parts1[1] == parts2[1]  # Hash portion should match

    def test_different_paths_produce_different_ids(self):
        """Different paths should produce different IDs"""
        id1 = _create_task_object_id("DC01.DOMAIN.LAB", "\\Tasks\\Task1")
        id2 = _create_task_object_id("DC01.DOMAIN.LAB", "\\Tasks\\Task2")

        assert id1 != id2

    def test_different_hosts_produce_different_ids(self):
        """Different hosts should produce different IDs"""
        id1 = _create_task_object_id("DC01.DOMAIN.LAB", "\\Tasks\\Task1")
        id2 = _create_task_object_id("DC02.DOMAIN.LAB", "\\Tasks\\Task1")

        assert id1 != id2

    def test_handles_spaces_in_task_name(self):
        """Should handle spaces in task name"""
        result = _create_task_object_id("DC01.DOMAIN.LAB", "\\Tasks\\My Task Name")

        assert "MY_TASK_NAME" in result

    def test_handles_long_task_names(self):
        """Should truncate long task names"""
        long_name = "A" * 100
        result = _create_task_object_id("DC01.DOMAIN.LAB", f"\\Tasks\\{long_name}")

        # Task name portion should be limited
        assert len(result) < 150

    def test_handles_nested_paths(self):
        """Should handle nested task paths"""
        result = _create_task_object_id("DC01.DOMAIN.LAB", "\\Microsoft\\Windows\\UpdateTask")

        assert "UPDATETASK" in result


class TestCreateTaskNode:
    """Tests for _create_task_node function"""

    def test_creates_valid_node(self):
        """Should create a valid Node instance"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
            "runas": "DOMAIN\\admin",
            "enabled": "true"
        }

        node = _create_task_node(task)

        assert node is not None
        assert "TH_ScheduledTask" in node.kinds
        assert "Base" in node.kinds
        assert "TaskHound" in node.kinds

    def test_raises_on_missing_host(self):
        """Should raise ValueError if host is missing"""
        task = {
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe"
        }

        with pytest.raises(ValueError, match="missing 'host' field"):
            _create_task_node(task)

    def test_raises_on_missing_path(self):
        """Should raise ValueError if path is missing"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "command": "cmd.exe"
        }

        with pytest.raises(ValueError, match="missing 'path' field"):
            _create_task_node(task)

    def test_raises_on_empty_host(self):
        """Should raise ValueError if host is empty"""
        task = {
            "host": "  ",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe"
        }

        with pytest.raises(ValueError, match="missing 'host' field"):
            _create_task_node(task)

    def test_raises_on_unknown_host(self):
        """Should raise ValueError for UNKNOWN_HOST"""
        task = {
            "host": "UNKNOWN_HOST",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe"
        }

        with pytest.raises(ValueError, match="Invalid hostname"):
            _create_task_node(task)

    def test_combines_command_and_arguments(self):
        """Should combine command and arguments"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
            "arguments": "/c whoami",
            "runas": "admin"
        }

        node = _create_task_node(task)

        # Access properties as dict
        props = node.properties.to_dict() if hasattr(node.properties, 'to_dict') else dict(node.properties)
        assert props.get("command") == "cmd.exe /c whoami"

    def test_handles_null_logon_type(self):
        """Should handle null/None logon_type"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
            "logon_type": None,
            "runas": "admin"
        }

        node = _create_task_node(task)

        props = node.properties.to_dict() if hasattr(node.properties, 'to_dict') else dict(node.properties)
        assert props.get("logontype") == "Unknown"

    def test_enabled_true_conversion(self):
        """Should convert enabled string to boolean"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
            "enabled": "true",
            "runas": "admin"
        }

        node = _create_task_node(task)

        props = node.properties.to_dict() if hasattr(node.properties, 'to_dict') else dict(node.properties)
        assert props.get("enabled") is True

    def test_enabled_false_conversion(self):
        """Should convert enabled false to boolean"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
            "enabled": "false",
            "runas": "admin"
        }

        node = _create_task_node(task)

        props = node.properties.to_dict() if hasattr(node.properties, 'to_dict') else dict(node.properties)
        assert props.get("enabled") is False

    def test_objectid_not_in_properties(self):
        """objectid is reserved in BH v8.9.0+ and must not appear in node properties"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
        }
        node = _create_task_node(task)
        props = node.properties.to_dict() if hasattr(node.properties, 'to_dict') else dict(node.properties)
        assert "objectid" not in props

    def test_credentials_stored_flag(self):
        """Should set credentialsstored based on credentials_hint"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
            "credentials_hint": "stored_credentials",
            "runas": "admin"
        }

        node = _create_task_node(task)

        props = node.properties.to_dict() if hasattr(node.properties, 'to_dict') else dict(node.properties)
        assert props.get("credentialsstored") is True

    def test_credentials_not_stored(self):
        """Should set credentialsstored to false for other hints"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
            "credentials_hint": "interactive",
            "runas": "admin"
        }

        node = _create_task_node(task)

        props = node.properties.to_dict() if hasattr(node.properties, 'to_dict') else dict(node.properties)
        assert props.get("credentialsstored") is False

    def test_includes_optional_properties(self):
        """Should include optional properties when present"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
            "author": "John Doe",
            "date": "2024-01-01",
            "runas": "admin"
        }

        node = _create_task_node(task)

        props = node.properties.to_dict() if hasattr(node.properties, 'to_dict') else dict(node.properties)
        assert props.get("author") == "John Doe"
        assert props.get("date") == "2024-01-01"

    def test_includes_trigger_info(self):
        """Should include trigger information"""
        task = {
            "host": "DC01.DOMAIN.LAB",
            "path": "\\Tasks\\TestTask",
            "command": "cmd.exe",
            "trigger_type": "Calendar",
            "start_boundary": "2024-01-01T00:00:00",
            "interval": "PT1H",
            "runas": "admin"
        }

        node = _create_task_node(task)

        props = node.properties.to_dict() if hasattr(node.properties, 'to_dict') else dict(node.properties)
        assert props.get("triggertype") == "Calendar"
        assert props.get("startboundary") == "2024-01-01T00:00:00"
        assert props.get("interval") == "PT1H"


class TestCreatePrincipalId:
    """Tests for _create_principal_id function"""

    def test_returns_none_for_empty_user(self):
        """Should return None for empty runas user"""
        result = _create_principal_id("", "DOMAIN.LAB", {})

        assert result is None

    def test_returns_none_for_na_user(self):
        """Should return None for N/A runas user"""
        result = _create_principal_id("N/A", "DOMAIN.LAB", {})

        assert result is None

    def test_filters_system_account(self):
        """Should return None for NT AUTHORITY\\SYSTEM"""
        result = _create_principal_id("NT AUTHORITY\\SYSTEM", "DOMAIN.LAB", {})

        assert result is None

    def test_filters_local_service(self):
        """Should return None for NT AUTHORITY\\LOCAL SERVICE"""
        result = _create_principal_id("NT AUTHORITY\\LOCAL SERVICE", "DOMAIN.LAB", {})

        assert result is None

    def test_filters_network_service(self):
        """Should return None for NT AUTHORITY\\NETWORK SERVICE"""
        result = _create_principal_id("NT AUTHORITY\\NETWORK SERVICE", "DOMAIN.LAB", {})

        assert result is None

    def test_filters_system_sid(self):
        """Should return None for well-known system SIDs"""
        # Local System SID
        result = _create_principal_id("S-1-5-18", "DOMAIN.LAB", {})
        assert result is None

        # Local Service SID
        result = _create_principal_id("S-1-5-19", "DOMAIN.LAB", {})
        assert result is None

        # Network Service SID
        result = _create_principal_id("S-1-5-20", "DOMAIN.LAB", {})
        assert result is None

    def test_filters_builtin_sid(self):
        """Should return None for builtin SIDs"""
        # Builtin Administrators
        result = _create_principal_id("S-1-5-32-544", "DOMAIN.LAB", {})
        assert result is None

    def test_returns_domain_sid(self):
        """Should return domain SIDs as-is"""
        sid = "S-1-5-21-123456789-123456789-123456789-1001"
        result = _create_principal_id(sid, "DOMAIN.LAB", {})

        assert result == sid

    def test_handles_upn_format_same_domain(self):
        """Should handle UPN format when domain matches"""
        result = _create_principal_id("admin@domain.lab", "DOMAIN.LAB", {})

        assert result == "ADMIN@DOMAIN.LAB"

    def test_handles_netbios_format_same_domain(self):
        """Should handle NETBIOS format when domain matches"""
        task = {"host": "DC01.DOMAIN.LAB"}
        result = _create_principal_id("DOMAIN\\admin", "DOMAIN.LAB", task)

        assert result == "ADMIN@DOMAIN.LAB"

    def test_handles_plain_username(self):
        """Bare ambiguous samaccountname (not a known local name) assumes domain"""
        result = _create_principal_id("svcbackup", "DOMAIN.LAB", {})

        assert result == "SVCBACKUP@DOMAIN.LAB"

    def test_filters_bare_administrator(self):
        """Bare 'Administrator' is always a local account per LookupAccountName() order"""
        result = _create_principal_id("Administrator", "DOMAIN.LAB", {})
        assert result is None

        result = _create_principal_id("administrator", "DOMAIN.LAB", {})
        assert result is None

    def test_filters_bare_guest(self):
        """Bare 'Guest' is always a local account"""
        assert _create_principal_id("Guest", "DOMAIN.LAB", {}) is None
        assert _create_principal_id("guest", "DOMAIN.LAB", {}) is None

    def test_filters_bare_defaultaccount(self):
        """Bare 'DefaultAccount' and 'WDAGUtilityAccount' are local accounts"""
        assert _create_principal_id("DefaultAccount", "DOMAIN.LAB", {}) is None
        assert _create_principal_id("WDAGUtilityAccount", "DOMAIN.LAB", {}) is None

    def test_filters_dot_prefix_local_account(self):
        """.\\username is the explicit MS-TSCH local account format — always skip"""
        task = {"host": "DC01.DOMAIN.LAB", "path": "\\Tasks\\Test"}
        assert _create_principal_id(".\\Administrator", "DOMAIN.LAB", task) is None
        assert _create_principal_id(".\\svcaccount", "DOMAIN.LAB", task) is None
        assert _create_principal_id(".\\localuser", "DOMAIN.LAB", task) is None

    def test_filters_local_account(self):
        """Should filter local accounts (domain matches hostname)"""
        task = {"host": "CLIENT01.DOMAIN.LAB"}
        result = _create_principal_id("CLIENT01\\localuser", "DOMAIN.LAB", task)

        assert result is None

    def test_filters_builtin_administrators(self):
        """Should filter BUILTIN\\ADMINISTRATORS"""
        result = _create_principal_id("BUILTIN\\ADMINISTRATORS", "DOMAIN.LAB", {})

        assert result is None

    def test_handles_case_variations(self):
        """Should handle case variations in built-in accounts"""
        # Lowercase
        result = _create_principal_id("nt authority\\system", "DOMAIN.LAB", {})
        assert result is None

        # Mixed case
        result = _create_principal_id("NT Authority\\System", "DOMAIN.LAB", {})
        assert result is None

    def test_cross_domain_without_connector(self):
        """Should return None for cross-domain without connector"""
        task = {"host": "DC01.DOMAIN.LAB"}
        result = _create_principal_id("OTHER\\admin", "DOMAIN.LAB", task, bh_connector=None)

        assert result is None

    def test_cross_domain_upn_without_connector(self):
        """Should return None for cross-domain UPN without connector"""
        result = _create_principal_id("admin@other.lab", "DOMAIN.LAB", {}, bh_connector=None)

        assert result is None

    @patch('taskhound.opengraph.builder.warn')
    def test_cross_domain_logs_warning(self, mock_warn):
        """Should log warning for cross-domain without connector"""
        task = {"host": "DC01.DOMAIN.LAB"}
        _create_principal_id("OTHER\\admin", "DOMAIN.LAB", task, bh_connector=None)

        assert mock_warn.called

    def test_domain_with_fqdn_prefix(self):
        """Should handle FQDN-style domain prefix"""
        task = {"host": "DC01.DOMAIN.LAB"}
        result = _create_principal_id("DOMAIN.LAB\\admin", "DOMAIN.LAB", task)

        assert result == "ADMIN@DOMAIN.LAB"

    def test_netbios_name_differs_from_fqdn(self):
        """Should correctly match when NetBIOS name differs from FQDN first part.

        Bug scenario: domain is corp.example.com but NetBIOS name is YOURCOMPANY (not CORP).
        Without local_netbios param, YOURCOMPANY\\admin would be treated as cross-domain.
        """
        task = {"host": "DC01.CORP.EXAMPLE.COM"}

        # Without local_netbios - would incorrectly think YOURCOMPANY is cross-domain
        # because CORP != YOURCOMPANY
        result_without = _create_principal_id("YOURCOMPANY\\admin", "CORP.EXAMPLE.COM", task, local_netbios=None)
        # This fails without a connector, so it returns None for cross-domain
        assert result_without is None

        # With local_netbios - correctly matches YOURCOMPANY as local domain
        result_with = _create_principal_id("YOURCOMPANY\\admin", "CORP.EXAMPLE.COM", task, local_netbios="YOURCOMPANY")
        assert result_with == "ADMIN@CORP.EXAMPLE.COM"

    def test_netbios_case_insensitive(self):
        """NetBIOS comparison should be case-insensitive"""
        task = {"host": "DC01.DOMAIN.LAB"}

        # lowercase netbios
        result = _create_principal_id("CORP\\admin", "DOMAIN.LAB", task, local_netbios="corp")
        assert result == "ADMIN@DOMAIN.LAB"

        # uppercase runas domain
        result2 = _create_principal_id("corp\\admin", "DOMAIN.LAB", task, local_netbios="CORP")
        assert result2 == "ADMIN@DOMAIN.LAB"

    def test_bare_name_skipped_if_in_host_local_cache(self):
        """Bare name matching a per-host SAMR cache entry should return None"""
        from taskhound.utils.cache_manager import get_cache
        get_cache().set("local_users", "DC01.DOMAIN.LAB", {"svclocal": 1001, "backupadmin": 1002})

        task = {"host": "DC01.DOMAIN.LAB", "path": "\\Tasks\\Test"}
        assert _create_principal_id("svclocal", "DOMAIN.LAB", task) is None
        assert _create_principal_id("BackupAdmin", "DOMAIN.LAB", task) is None

    def test_bare_name_falls_through_if_not_in_cache(self):
        """Bare name NOT in per-host cache falls through to domain assumption"""
        from taskhound.utils.cache_manager import get_cache
        get_cache().set("local_users", "DC01.DOMAIN.LAB", {"svclocal": 1001})

        task = {"host": "DC01.DOMAIN.LAB", "path": "\\Tasks\\Test"}
        # svcbackup is not in the local cache — should assume domain
        result = _create_principal_id("svcbackup", "DOMAIN.LAB", task)
        assert result == "SVCBACKUP@DOMAIN.LAB"

    def test_bare_name_no_host_in_task(self):
        """Bare name with no host in task dict falls through normally (no cache lookup)"""
        task = {}
        result = _create_principal_id("svcaccount", "DOMAIN.LAB", task)
        assert result == "SVCACCOUNT@DOMAIN.LAB"


class TestCreatePrincipalIdWithConnector:
    """Tests for _create_principal_id with BloodHound connector"""

    def test_cross_domain_validated_success(self):
        """Should return validated UPN for valid cross-domain user"""
        mock_connector = MagicMock()
        mock_connector.validate_and_resolve_cross_domain_user.return_value = {
            'name': 'ADMIN@OTHER.LAB',
            'domain_fqdn': 'OTHER.LAB',
            'objectid': 'S-1-5-21-xxx',
            'username': 'ADMIN'
        }

        task = {"host": "DC01.DOMAIN.LAB", "path": "\\Tasks\\Test"}
        result = _create_principal_id("OTHER\\admin", "DOMAIN.LAB", task, bh_connector=mock_connector)

        assert result == "ADMIN@OTHER.LAB"
        mock_connector.validate_and_resolve_cross_domain_user.assert_called_once()

    @patch('taskhound.opengraph.builder.warn')
    def test_cross_domain_domain_not_found(self, mock_warn):
        """Should return None when domain not found in BloodHound"""
        mock_connector = MagicMock()
        mock_connector.validate_and_resolve_cross_domain_user.return_value = {
            'error_reason': 'domain_not_found'
        }

        task = {"host": "DC01.DOMAIN.LAB", "path": "\\Tasks\\Test"}
        result = _create_principal_id("OTHER\\admin", "DOMAIN.LAB", task, bh_connector=mock_connector)

        assert result is None
        assert mock_warn.called

    @patch('taskhound.opengraph.builder.warn')
    def test_cross_domain_user_not_found(self, mock_warn):
        """Should return None when user not found in BloodHound"""
        mock_connector = MagicMock()
        mock_connector.validate_and_resolve_cross_domain_user.return_value = {
            'error_reason': 'user_not_found',
            'domain_fqdn': 'OTHER.LAB',
            'username': 'ADMIN'
        }

        task = {"host": "DC01.DOMAIN.LAB", "path": "\\Tasks\\Test"}
        result = _create_principal_id("OTHER\\admin", "DOMAIN.LAB", task, bh_connector=mock_connector)

        assert result is None
        assert mock_warn.called

    def test_cross_domain_upn_validated(self):
        """Should validate cross-domain UPN format"""
        mock_connector = MagicMock()
        mock_connector.validate_and_resolve_cross_domain_user.return_value = {
            'name': 'ADMIN@OTHER.LAB',
            'domain_fqdn': 'OTHER.LAB',
            'objectid': 'S-1-5-21-xxx',
            'username': 'ADMIN'
        }

        task = {"host": "DC01.DOMAIN.LAB", "path": "\\Tasks\\Test"}
        result = _create_principal_id("admin@other.lab", "DOMAIN.LAB", task, bh_connector=mock_connector)

        assert result == "ADMIN@OTHER.LAB"
