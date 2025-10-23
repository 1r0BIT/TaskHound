"""
Live tests for basic TaskHound functionality.
"""
import pytest
import subprocess
import json
from pathlib import Path


pytestmark = [pytest.mark.slow, pytest.mark.live]


def run_taskhound(target, args, live_config):
    """Helper to run taskhound with common auth parameters."""
    cmd = [
        "python", "-m", "taskhound",
        "--target", target,
        "--username", live_config["username"],
        "--password", live_config["password"],
        "--domain", live_config["domain"],
    ]
    cmd.extend(args)
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=Path(__file__).parent.parent
    )
    return result


def test_basic_enumeration(live_config, target_dc):
    """Test basic task enumeration against live target."""
    result = run_taskhound(target_dc, [], live_config)
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    assert "Found" in result.stdout or "tasks" in result.stdout.lower()


def test_json_output(live_config, target_dc, sample_output_dir):
    """Test JSON export functionality."""
    json_file = sample_output_dir / "tasks.json"
    
    result = run_taskhound(
        target_dc,
        ["--json", str(json_file)],
        live_config
    )
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    assert json_file.exists(), "JSON file not created"
    
    # Validate JSON structure
    with open(json_file) as f:
        data = json.load(f)
    
    assert isinstance(data, list), "JSON should be a list of tasks"
    if data:  # If tasks found
        task = data[0]
        assert "host" in task
        assert "path" in task


def test_xml_backup(live_config, target_dc, sample_output_dir):
    """Test XML backup functionality."""
    backup_dir = sample_output_dir / "xml_backup"
    
    result = run_taskhound(
        target_dc,
        ["--backup", str(backup_dir)],
        live_config
    )
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    
    # Check target-specific subdirectory
    target_backup_dir = backup_dir / target_dc
    if target_backup_dir.exists():
        # Check if task files were backed up (they don't have .xml extension)
        # Look for files in the Tasks directory
        tasks_dir = target_backup_dir / "Windows" / "System32" / "Tasks"
        if tasks_dir.exists():
            task_files = [f for f in tasks_dir.rglob("*") if f.is_file()]
            assert len(task_files) > 0, f"No task files backed up in {tasks_dir}"


def test_credguard_detection(live_config, target_dc):
    """Test Credential Guard detection."""
    result = run_taskhound(
        target_dc,
        ["--credguard-detect"],
        live_config
    )
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    # Output should mention credential guard status
    assert "credential" in result.stdout.lower()


def test_no_ldap_mode(live_config, target_dc):
    """Test --no-ldap flag to skip LDAP lookups."""
    result = run_taskhound(
        target_dc,
        ["--no-ldap"],
        live_config
    )
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    assert "Found" in result.stdout or "tasks" in result.stdout.lower()
