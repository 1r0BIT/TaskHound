"""
Live tests for DPAPI credential extraction feature.
"""
import pytest
import subprocess
import json
from pathlib import Path


pytestmark = pytest.mark.live


def run_taskhound(args, live_config, target=None):
    """Helper to run taskhound with common auth parameters."""
    target_host = target or live_config["targets"]["dc"]
    
    cmd = [
        "python", "-m", "taskhound",
        "-u", live_config["username"],
        "-p", live_config["password"],
        "-d", live_config["domain"],
        "-t", target_host
    ]
    
    # Add DC IP if specified
    if "dc_ip" in live_config:
        cmd.extend(["--dc-ip", live_config["dc_ip"]])
    
    cmd.extend(args)
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120  # DPAPI operations can take longer
    )
    return result


def test_dpapi_collection_only_dc(live_config, target_dc, sample_output_dir):
    """Test DPAPI blob collection without decryption (DC)."""
    result = run_taskhound(
        ["--loot"],
        live_config,
        target=target_dc
    )
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    
    # Check if dpapi_loot directory was created
    dpapi_dir = Path("dpapi_loot") / target_dc
    if dpapi_dir.exists():
        # Verify structure
        assert (dpapi_dir / "masterkeys").exists(), "Masterkeys directory not created"
        assert (dpapi_dir / "credentials").exists(), "Credentials directory not created"
        
        # Check for collected files
        masterkeys = list((dpapi_dir / "masterkeys").glob("*"))
        creds = list((dpapi_dir / "credentials").glob("*"))
        
        print(f"DC - Collected {len(masterkeys)} masterkeys and {len(creds)} credential files")


def test_dpapi_live_decryption_dc(live_config, target_dc, dpapi_key_dc):
    """Test live DPAPI decryption with key (DC)."""
    result = run_taskhound(
        ["--loot", "--dpapi-key", dpapi_key_dc],
        live_config,
        target=target_dc
    )
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    
    # Check for decrypted credentials in output
    output_lower = result.stdout.lower()
    if "credential" in output_lower:
        # Look for password indicators
        assert "password:" in output_lower or "decrypted" in output_lower
        print(f"✓ DC - Found decrypted credentials in output")


def test_dpapi_live_decryption_client(live_config, target_client, dpapi_key_client):
    """Test live DPAPI decryption with key (TestClient)."""
    result = run_taskhound(
        ["--loot", "--dpapi-key", dpapi_key_client],
        live_config,
        target=target_client
    )
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    
    # Check for decrypted credentials in output
    output_lower = result.stdout.lower()
    if "credential" in output_lower:
        # Look for password indicators
        assert "password:" in output_lower or "decrypted" in output_lower
        print(f"✓ TestClient - Found decrypted credentials in output")


def test_dpapi_offline_decryption(live_config, sample_output_dir):
    """Test offline DPAPI decryption from collected files."""
    if "dpapi_key" not in live_config:
        pytest.skip("No DPAPI key configured")
    
    # First, collect files
    collect_result = run_taskhound(["--loot"], live_config)
    
    if collect_result.returncode != 0:
        pytest.skip("Collection failed, skipping offline test")
    
    dpapi_dir = Path("dpapi_loot") / live_config["target"]
    if not dpapi_dir.exists():
        pytest.skip("No DPAPI files collected")
    
    # Now decrypt offline
    result = subprocess.run(
        [
            "python", "-m", "taskhound",
            "--offline", str(dpapi_dir),
            "--dpapi-key", live_config["dpapi_key"]
        ],
        capture_output=True,
        text=True,
        timeout=60
    )
    
    assert result.returncode == 0, f"Offline decryption failed: {result.stderr}"
    
    output_lower = result.stdout.lower()
    if "credential" in output_lower:
        assert "password:" in output_lower or "decrypted" in output_lower


def test_dpapi_credguard_compatibility(live_config):
    """Test DPAPI with Credential Guard detection."""
    if "dpapi_key" not in live_config:
        pytest.skip("No DPAPI key configured")
    
    result = run_taskhound(
        ["--loot", "--dpapi-key", live_config["dpapi_key"], "--credguard-detect"],
        live_config
    )
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    
    # Should show both credential guard status and DPAPI results
    output_lower = result.stdout.lower()
    assert "credential" in output_lower


def test_dpapi_with_json_export(live_config, sample_output_dir):
    """Test DPAPI with JSON export."""
    if "dpapi_key" not in live_config:
        pytest.skip("No DPAPI key configured")
    
    json_file = sample_output_dir / "dpapi_tasks.json"
    
    result = run_taskhound(
        ["--loot", "--dpapi-key", live_config["dpapi_key"], "--json", str(json_file)],
        live_config
    )
    
    assert result.returncode == 0, f"Command failed: {result.stderr}"
    
    if json_file.exists():
        with open(json_file) as f:
            data = json.load(f)
        
        # JSON should contain tasks
        assert isinstance(data, list)
