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

from taskhound.output.opengraph import (
    generate_opengraph_files,
    _create_task_object_id,
    _create_task_node,
    _create_principal_id,
    _create_relationship_edges,
    _get_bloodhound_token,
)
from taskhound.utils.sid_resolver import binary_to_sid, sid_to_binary


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def sample_task_with_creds():
    """Sample task with stored credentials (DPAPI extractable)."""
    return {
        "host": "DC.BADSUCCESSOR.LAB",
        "path": "\\ImportantBackup",
        "name": "ImportantBackup",
        "enabled": "true",
        "author": "BADSUCCESSOR\\Administrator",
        "runas": "BADSUCCESSOR\\backupuser",
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
        "host": "WS01.BADSUCCESSOR.LAB",
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
        "host": "WS01.BADSUCCESSOR.LAB",
        "path": "\\LocalMaintenance",
        "runas": "WS01\\LocalUser",
        "credentials_hint": "unknown",
    }


@pytest.fixture
def sample_task_null_logontype():
    """Sample task with null logontype."""
    return {
        "host": "DC.BADSUCCESSOR.LAB",
        "path": "\\TestTask",
        "runas": "BADSUCCESSOR\\serviceacct",
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
        task_id = _create_task_object_id("DC.BADSUCCESSOR.LAB", "\\ImportantBackup")
        assert task_id.startswith("DC.BADSUCCESSOR.LAB_")
        assert "IMPORTANTBACKUP" in task_id


class TestTaskNodeCreation:
    """Tests for _create_task_node function."""
    
    def test_node_creation_with_creds(self, sample_task_with_creds):
        node = _create_task_node(sample_task_with_creds)
        assert "scheduledtask" in node.kinds
        props_dict = node.properties._properties
        assert props_dict["credentialsstored"] is True
    
    def test_node_creation_null_logontype(self, sample_task_null_logontype):
        node = _create_task_node(sample_task_null_logontype)
        props_dict = node.properties._properties
        assert props_dict["logontype"] == "Unknown"


class TestPrincipalIDCreation:
    """Tests for _create_principal_id function."""
    
    def test_domain_user_with_backslash(self, sample_task_with_creds):
        principal_id = _create_principal_id(
            "BADSUCCESSOR\\backupuser",
            "BADSUCCESSOR.LAB",
            sample_task_with_creds
        )
        assert principal_id == "BACKUPUSER@BADSUCCESSOR.LAB"
    
    def test_local_account_filtered(self, sample_task_local_account):
        principal_id = _create_principal_id(
            "WS01\\LocalUser",
            "BADSUCCESSOR.LAB",
            sample_task_local_account
        )
        assert principal_id is None


class TestRelationshipEdges:
    """Tests for _create_relationship_edges function."""
    
    def test_edges_with_stored_creds(self, sample_task_with_creds):
        edges = _create_relationship_edges(sample_task_with_creds, {}, {})
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
    
    def test_generate_opengraph_files_basic(
        self, temp_output_dir, sample_task_with_creds, sample_task_no_creds
    ):
        tasks = [sample_task_with_creds, sample_task_no_creds]
        output_file = generate_opengraph_files(str(temp_output_dir), tasks)
        
        assert Path(output_file).exists()
        assert "taskhound_opengraph.json" in output_file
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert "graph" in data
        assert len(data["graph"]["nodes"]) == 2


class TestBloodHoundAPI:
    """Tests for BloodHound API integration."""
    
    @patch('requests.post')
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
            "password_analysis": "Password set BEFORE task creation"
        }
        node = _create_task_node(task)
        props_dict = node.properties._properties
        assert "BEFORE" in props_dict["passwordanalysis"]
