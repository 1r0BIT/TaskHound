"""
Pytest configuration and shared fixtures for TaskHound tests.
"""
import json
from pathlib import Path

import pytest


@pytest.fixture
def test_data_dir():
    """Return path to test data directory."""
    return Path(__file__).parent / "data"


@pytest.fixture(scope="module")
def live_config():
    """
    Load live test configuration from file.
    
    Create a file: tests/live_test_config.json based on live_test_config.json.example
    """
    config_file = Path(__file__).parent / "live_test_config.json"

    if not config_file.exists():
        pytest.skip(f"Live test config not found: {config_file}\n"
                   f"Copy live_test_config.json.example to live_test_config.json and edit with your lab details")

    with open(config_file) as f:
        config = json.load(f)

    # Validate required fields
    required = ["domain", "username", "password", "targets", "dc_ip"]
    for field in required:
        if field not in config:
            pytest.skip(f"Required field '{field}' missing in live_test_config.json")

    return config


@pytest.fixture
def target_dc(live_config):
    """Get DC target from config."""
    return live_config["targets"]["dc"]


@pytest.fixture
def target_client(live_config):
    """Get test client target from config."""
    return live_config["targets"]["testclient"]


@pytest.fixture
def dpapi_key_dc(live_config):
    """Get DPAPI key for DC."""
    return live_config["dpapi_keys"]["dc"]


@pytest.fixture
def dpapi_key_client(live_config):
    """Get DPAPI key for test client."""
    return live_config["dpapi_keys"]["testclient"]


@pytest.fixture
def sample_output_dir(tmp_path):
    """Create temporary directory for test outputs."""
    output_dir = tmp_path / "live_test_output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def sample_dpapi_key():
    """Sample DPAPI key for testing."""
    return "0x51e43225e5b43b25d3768a2ae7f99934cb35d3ea"


@pytest.fixture
def sample_task_xml():
    """Sample task XML for parsing tests."""
    return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-01-15T10:30:00</Date>
    <Author>DOMAIN\\Administrator</Author>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-123456789-123456789-123456789-500</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-File C:\\Scripts\\backup.ps1</Arguments>
    </Exec>
  </Actions>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2023-01-15T02:00:00</StartBoundary>
    </TimeTrigger>
  </Triggers>
</Task>"""


@pytest.fixture
def mock_smb_connection(mocker):
    """Mock SMB connection to avoid real network calls."""
    mock_conn = mocker.MagicMock()
    mock_conn.listPath.return_value = []
    return mock_conn
