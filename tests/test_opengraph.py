"""
Comprehensive test suite for OpenGraph functionality.

Tests cover:
- Task node creation with proper IDs and properties
- Edge creation (HasTask, HasTaskWithStoredCreds, RunsAs)
- Principal ID formatting (local vs domain accounts)
- SID conversion utilities
- BloodHound API integration
- Password viability analysis
"""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from taskhound.opengraph import generate_opengraph_files
from taskhound.opengraph.builder import (
    _create_principal_id,
    _create_relationship_edges,
    _create_task_node,
    _create_task_object_id,
)
from taskhound.resolver import binary_to_sid, sid_to_binary
from taskhound.utils.bh_api import get_bloodhound_token as _get_bloodhound_token

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_task_with_creds():
    """Sample task with stored credentials (DPAPI extractable)."""
    return {
        "host": "DC.EXAMPLE.LAB",
        "path": "\\ImportantBackup",
        "name": "ImportantBackup",
        "enabled": "true",
        "author": "EXAMPLE\\Administrator",
        "runas": "EXAMPLE\\backupuser",
        "command": "C:\\Scripts\\backup.ps1",
        "arguments": "-Full",
        "date": "2024-01-15T10:30:00",
        "trigger_type": "Daily",
        "trigger_details": "At 2:00 AM every day",
        "logontype": "Password",
        "credentials_hint": "stored_credentials",
        "passwordlastset": "2024-01-10T08:00:00",
        "passwordanalysis": "Password set BEFORE task creation (High-value target)",
        "taskcreationtime": "2024-01-15T10:30:00",
    }


@pytest.fixture
def sample_task_no_creds():
    """Sample task without stored credentials."""
    return {
        "host": "WS01.EXAMPLE.LAB",
        "path": "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot",
        "name": "Reboot",
        "enabled": "true",
        "runas": "SYSTEM",
        "command": "shutdown.exe",
        "arguments": "/r /t 300",
        "logontype": "ServiceAccount",
        "credentials_hint": "unknown",
    }


@pytest.fixture
def sample_task_local_account():
    """Sample task running as local account (should be filtered)."""
    return {
        "host": "WS01.EXAMPLE.LAB",
        "path": "\\LocalMaintenance",
        "runas": "WS01\\LocalUser",
        "credentials_hint": "unknown",
    }


@pytest.fixture
def sample_task_null_logontype():
    """Sample task with null logontype."""
    return {
        "host": "DC.EXAMPLE.LAB",
        "path": "\\TestTask",
        "runas": "EXAMPLE\\serviceacct",
        "logontype": None,
        "credentials_hint": "unknown",
    }


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create a temporary directory for test output."""
    return tmp_path


# ============================================================================
# Unit Tests
# ============================================================================


class TestTaskObjectID:
    """Tests for _create_task_object_id function."""

    def test_basic_task_id_creation(self):
        task_id = _create_task_object_id("DC.EXAMPLE.LAB", "\\ImportantBackup")
        assert task_id.startswith("DC.EXAMPLE.LAB_")
        assert "IMPORTANTBACKUP" in task_id


class TestTaskNodeCreation:
    """Tests for _create_task_node function."""

    def test_node_creation_with_creds(self, sample_task_with_creds):
        node = _create_task_node(sample_task_with_creds)
        assert "ScheduledTask" in node.kinds
        props_dict = node.properties._properties
        assert props_dict["credentialsstored"] is True

    def test_node_creation_null_logontype(self, sample_task_null_logontype):
        node = _create_task_node(sample_task_null_logontype)
        props_dict = node.properties._properties
        assert props_dict["logontype"] == "Unknown"


class TestPrincipalIDCreation:
    """Tests for _create_principal_id function."""

    def test_domain_user_with_backslash(self, sample_task_with_creds):
        principal_id = _create_principal_id("EXAMPLE\\backupuser", "EXAMPLE.LAB", sample_task_with_creds)
        assert principal_id == "BACKUPUSER@EXAMPLE.LAB"

    def test_local_account_filtered(self, sample_task_local_account):
        principal_id = _create_principal_id("WS01\\LocalUser", "EXAMPLE.LAB", sample_task_local_account)
        assert principal_id is None

    def test_fqdn_domain_prefix_lowercase(self):
        """Test that FQDN domain prefix (lowercase) is correctly recognized as same domain."""
        task = {"host": "evergreen.thesimpsons.springfield.local", "path": "\\Windows\\System32\\Tasks\\ntlm_bot"}
        # Domain prefix with FQDN in lowercase should match uppercase local domain
        principal_id = _create_principal_id(
            "thesimpsons.springfield.local\\homer.simpson", "THESIMPSONS.SPRINGFIELD.LOCAL", task
        )
        # Should NOT be None (not filtered as cross-domain)
        assert principal_id == "HOMER.SIMPSON@THESIMPSONS.SPRINGFIELD.LOCAL"

    def test_fqdn_domain_prefix_uppercase(self):
        """Test that FQDN domain prefix (uppercase) is correctly recognized as same domain."""
        task = {"host": "evergreen.thesimpsons.springfield.local", "path": "\\Windows\\System32\\Tasks\\ntlm_bot"}
        # Domain prefix with FQDN in uppercase should match uppercase local domain
        principal_id = _create_principal_id(
            "THESIMPSONS.SPRINGFIELD.LOCAL\\homer.simpson", "THESIMPSONS.SPRINGFIELD.LOCAL", task
        )
        # Should NOT be None (not filtered as cross-domain)
        assert principal_id == "HOMER.SIMPSON@THESIMPSONS.SPRINGFIELD.LOCAL"


class TestRelationshipEdges:
    """Tests for _create_relationship_edges function."""

    def test_edges_with_stored_creds(self, sample_task_with_creds):
        edges, skipped = _create_relationship_edges(sample_task_with_creds, {}, {}, allow_orphans=True)
        assert len(edges) == 2
        assert edges[0].kind == "HasTaskWithStoredCreds"
        assert edges[1].kind == "RunsAs"


class TestSIDConversion:
    """Tests for SID conversion utilities."""

    def test_sid_to_binary_roundtrip(self):
        original_sid = "S-1-5-21-1234567890-1234567890-1234567890-1000"
        binary = sid_to_binary(original_sid)
        converted_sid = binary_to_sid(binary)
        assert converted_sid == original_sid


class TestOpenGraphGeneration:
    """Integration tests for full OpenGraph file generation."""

    def test_generate_opengraph_files_basic(self, temp_output_dir, sample_task_with_creds, sample_task_no_creds):
        tasks = [sample_task_with_creds, sample_task_no_creds]
        output_file = generate_opengraph_files(str(temp_output_dir), tasks, allow_orphans=True)

        assert Path(output_file).exists()
        assert "taskhound_opengraph.json" in output_file

        with open(output_file) as f:
            data = json.load(f)

        assert "graph" in data
        # Expect 5 nodes:
        # 1. Task 1 (ImportantBackup)
        # 2. Task 2 (Reboot)
        # 3. Computer 1 (DC.BADSUCCESSOR.LAB) - Placeholder
        # 4. Computer 2 (WS01.BADSUCCESSOR.LAB) - Placeholder
        # 5. User 1 (BACKUPUSER@BADSUCCESSOR.LAB) - Placeholder
        assert len(data["graph"]["nodes"]) == 5

        # Verify placeholder nodes exist
        node_ids = [n["id"] for n in data["graph"]["nodes"]]
        assert "DC.EXAMPLE.LAB" in node_ids
        assert "WS01.EXAMPLE.LAB" in node_ids
        assert "BACKUPUSER@EXAMPLE.LAB" in node_ids


class TestBloodHoundAPI:
    """Tests for BloodHound API integration."""

    @patch("requests.post")
    def test_get_bloodhound_token_success(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"session_token": "test_token_123"}}
        mock_post.return_value = mock_response

        token = _get_bloodhound_token("http://localhost:8080", "admin", "password")
        assert token == "test_token_123"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_task_with_missing_fields(self):
        minimal_task = {"host": "DC.LAB", "path": "\\MinimalTask"}
        node = _create_task_node(minimal_task)
        props_dict = node.properties._properties
        assert props_dict["hostname"] == "DC.LAB"

    def test_generate_with_empty_task_list(self, temp_output_dir):
        output_file = generate_opengraph_files(str(temp_output_dir), [])
        assert Path(output_file).exists()


class TestPasswordViability:
    """Tests for password viability analysis."""

    def test_password_set_before_task(self):
        task = {
            "host": "DC.LAB",
            "path": "\\Task",
            "credentials_hint": "stored_credentials",
            "password_analysis": "Password set BEFORE task creation",
        }
        node = _create_task_node(task)
        props_dict = node.properties._properties
        assert "BEFORE" in props_dict["passwordanalysis"]


class TestTaskObjectIDCollisions:
    """Tests for _create_task_object_id to ensure no collisions."""

    def test_different_paths_different_ids(self):
        """Different task paths should produce different IDs."""
        id1 = _create_task_object_id("DC.LAB", "\\Tasks\\Task1")
        id2 = _create_task_object_id("DC.LAB", "\\Tasks\\Task2")
        assert id1 != id2

    def test_similar_paths_different_ids(self):
        """Similar paths that could collide should produce different IDs."""
        id1 = _create_task_object_id("DC.LAB", "\\Tasks\\My_Task")
        id2 = _create_task_object_id("DC.LAB", "\\Tasks_My\\Task")
        assert id1 != id2

    def test_same_path_same_id(self):
        """Same hostname and path should produce identical IDs."""
        id1 = _create_task_object_id("DC.LAB", "\\Tasks\\Task1")
        id2 = _create_task_object_id("DC.LAB", "\\Tasks\\Task1")
        assert id1 == id2

    def test_case_insensitive_hash_component(self):
        """Hash component should be case-insensitive (same hash for different hostname cases)."""
        id1 = _create_task_object_id("DC.LAB", "\\Tasks\\Task1")
        id2 = _create_task_object_id("dc.lab", "\\Tasks\\Task1")
        # Hash portion is identical (case-insensitive), but hostname preserves original case
        hash1 = id1.split("_")[1]
        hash2 = id2.split("_")[1]
        assert hash1 == hash2  # Same hash
        # Hostname portion preserves original case
        assert id1.startswith("DC.LAB_")
        assert id2.startswith("dc.lab_")

    def test_id_contains_task_name(self):
        """Object ID should contain the task name for readability."""
        task_id = _create_task_object_id("DC.LAB", "\\Microsoft\\Windows\\Backup")
        assert "BACKUP" in task_id

    def test_long_task_name_truncated(self):
        """Long task names should be truncated in the ID."""
        long_path = "\\Tasks\\ThisIsAVeryLongTaskNameThatExceedsFiftyCharactersInLength"
        task_id = _create_task_object_id("DC.LAB", long_path)
        # Should still work and not raise an error
        assert task_id.startswith("DC.LAB_")


class TestTaskNodeValidation:
    """Tests for _create_task_node validation."""

    def test_missing_host_raises_error(self):
        """Should raise ValueError when host is missing."""
        task = {"path": "\\Task"}
        with pytest.raises(ValueError, match="missing 'host'"):
            _create_task_node(task)

    def test_missing_path_raises_error(self):
        """Should raise ValueError when path is missing."""
        task = {"host": "DC.LAB"}
        with pytest.raises(ValueError, match="missing 'path'"):
            _create_task_node(task)

    def test_unknown_host_raises_error(self):
        """Should raise ValueError when host is UNKNOWN."""
        task = {"host": "UNKNOWN", "path": "\\Task"}
        with pytest.raises(ValueError, match="Invalid hostname"):
            _create_task_node(task)

    def test_empty_host_raises_error(self):
        """Should raise ValueError when host is empty string."""
        task = {"host": "", "path": "\\Task"}
        with pytest.raises(ValueError, match="missing 'host'"):
            _create_task_node(task)

    def test_whitespace_only_host_raises_error(self):
        """Should raise ValueError when host is only whitespace."""
        task = {"host": "   ", "path": "\\Task"}
        with pytest.raises(ValueError, match="missing 'host'"):
            _create_task_node(task)


class TestTaskNodeProperties:
    """Tests for task node property handling."""

    def test_node_has_correct_kinds(self):
        """Node should have ScheduledTask, Base, and TaskHound kinds."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        node = _create_task_node(task)
        assert "ScheduledTask" in node.kinds
        assert "Base" in node.kinds
        assert "TaskHound" in node.kinds

    def test_command_with_arguments(self):
        """Command should include arguments when present."""
        task = {
            "host": "DC.LAB",
            "path": "\\Task",
            "command": "cmd.exe",
            "arguments": "/c echo hello",
        }
        node = _create_task_node(task)
        props = node.properties._properties
        assert props["command"] == "cmd.exe /c echo hello"

    def test_command_without_arguments(self):
        """Command should work without arguments."""
        task = {
            "host": "DC.LAB",
            "path": "\\Task",
            "command": "notepad.exe",
        }
        node = _create_task_node(task)
        props = node.properties._properties
        assert props["command"] == "notepad.exe"

    def test_enabled_true_string(self):
        """enabled='true' string should become boolean True."""
        task = {"host": "DC.LAB", "path": "\\Task", "enabled": "true"}
        node = _create_task_node(task)
        props = node.properties._properties
        assert props["enabled"] is True

    def test_enabled_false_string(self):
        """enabled='false' string should become boolean False."""
        task = {"host": "DC.LAB", "path": "\\Task", "enabled": "false"}
        node = _create_task_node(task)
        props = node.properties._properties
        assert props["enabled"] is False

    def test_credentials_stored_true(self):
        """credentials_hint='stored_credentials' should set credentialsstored=True."""
        task = {"host": "DC.LAB", "path": "\\Task", "credentials_hint": "stored_credentials"}
        node = _create_task_node(task)
        props = node.properties._properties
        assert props["credentialsstored"] is True

    def test_credentials_stored_false(self):
        """Other credentials_hint values should set credentialsstored=False."""
        task = {"host": "DC.LAB", "path": "\\Task", "credentials_hint": "no_saved_credentials"}
        node = _create_task_node(task)
        props = node.properties._properties
        assert props["credentialsstored"] is False

    def test_optional_properties_included(self):
        """Optional properties should be included when present."""
        task = {
            "host": "DC.LAB",
            "path": "\\Task",
            "author": "DOMAIN\\admin",
            "date": "2024-01-15T10:00:00",
            "trigger_type": "Calendar",
            "start_boundary": "2024-01-15T02:00:00",
            "interval": "PT1H",
            "duration": "P1D",
            "days_interval": "1",
            "password_analysis": "Password is valid",
            "type": "TIER-0",
            "reason": "AdminSDHolder protected",
        }
        node = _create_task_node(task)
        props = node.properties._properties
        assert props["author"] == "DOMAIN\\admin"
        assert props["date"] == "2024-01-15T10:00:00"
        assert props["triggertype"] == "Calendar"
        assert props["startboundary"] == "2024-01-15T02:00:00"
        assert props["interval"] == "PT1H"
        assert props["duration"] == "P1D"
        assert props["daysinterval"] == "1"
        assert props["passwordanalysis"] == "Password is valid"
        assert props["tasktype"] == "TIER-0"
        assert props["classification"] == "AdminSDHolder protected"


class TestPrincipalIDBuiltinAccounts:
    """Tests for _create_principal_id built-in account filtering."""

    def test_filter_system_account(self):
        """Should filter NT AUTHORITY\\SYSTEM."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("NT AUTHORITY\\SYSTEM", "DOMAIN.LAB", task)
        assert result is None

    def test_filter_local_service(self):
        """Should filter NT AUTHORITY\\LOCAL SERVICE."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("NT AUTHORITY\\LOCAL SERVICE", "DOMAIN.LAB", task)
        assert result is None

    def test_filter_network_service(self):
        """Should filter NT AUTHORITY\\NETWORK SERVICE."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("NT AUTHORITY\\NETWORK SERVICE", "DOMAIN.LAB", task)
        assert result is None

    def test_filter_system_short(self):
        """Should filter SYSTEM without prefix."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("SYSTEM", "DOMAIN.LAB", task)
        assert result is None

    def test_filter_builtin_administrators(self):
        """Should filter BUILTIN\\ADMINISTRATORS."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("BUILTIN\\ADMINISTRATORS", "DOMAIN.LAB", task)
        assert result is None


class TestPrincipalIDSIDHandling:
    """Tests for _create_principal_id SID handling."""

    def test_filter_local_system_sid(self):
        """Should filter S-1-5-18 (Local System)."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("S-1-5-18", "DOMAIN.LAB", task)
        assert result is None

    def test_filter_local_service_sid(self):
        """Should filter S-1-5-19 (Local Service)."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("S-1-5-19", "DOMAIN.LAB", task)
        assert result is None

    def test_filter_network_service_sid(self):
        """Should filter S-1-5-20 (Network Service)."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("S-1-5-20", "DOMAIN.LAB", task)
        assert result is None

    def test_filter_builtin_sid(self):
        """Should filter S-1-5-32-* (Builtin domain)."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("S-1-5-32-544", "DOMAIN.LAB", task)  # Administrators
        assert result is None

    def test_domain_sid_returned_as_is(self):
        """Domain SIDs should be returned for resolution."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        sid = "S-1-5-21-1234567890-1234567890-1234567890-1000"
        result = _create_principal_id(sid, "DOMAIN.LAB", task)
        assert result == sid


class TestPrincipalIDFormats:
    """Tests for _create_principal_id various input formats."""

    def test_empty_runas_returns_none(self):
        """Empty runas should return None."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("", "DOMAIN.LAB", task)
        assert result is None

    def test_na_runas_returns_none(self):
        """N/A runas should return None."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("N/A", "DOMAIN.LAB", task)
        assert result is None

    def test_simple_username_uses_local_domain(self):
        """Simple username without domain should use local domain."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("admin", "DOMAIN.LAB", task)
        assert result == "ADMIN@DOMAIN.LAB"

    def test_upn_format_same_domain(self):
        """UPN format with same domain should work."""
        task = {"host": "DC.LAB", "path": "\\Task"}
        result = _create_principal_id("admin@domain.lab", "DOMAIN.LAB", task)
        assert result == "ADMIN@DOMAIN.LAB"

    def test_netbios_format_same_domain(self):
        """NETBIOS format with same domain should work."""
        task = {"host": "DC.DOMAIN.LAB", "path": "\\Task"}
        result = _create_principal_id("DOMAIN\\admin", "DOMAIN.LAB", task)
        assert result == "ADMIN@DOMAIN.LAB"

