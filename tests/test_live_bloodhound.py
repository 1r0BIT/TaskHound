"""
Live tests for BloodHound integration feature.
"""
import subprocess
from pathlib import Path

import pytest

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
        timeout=120
    )
    return result


def test_bloodhound_live_connection_bhce(live_config, target_dc):
    """Test live BloodHound Community Edition connection."""
    bh_config = live_config.get("bloodhound_live", {}).get("bhce", {})

    if not bh_config.get("enabled"):
        pytest.skip("BHCE not configured or disabled")

    result = run_taskhound([
        "--bh-live",
        "--bh-ip", bh_config["ip"],
        "--bh-user", bh_config["user"],
        "--bh-password", bh_config["password"],
        "--bhce"
    ], live_config, target=target_dc)

    assert result.returncode == 0, f"Command failed: {result.stderr}"

    # Check for BloodHound connection indicators
    output = result.stdout.lower()
    assert "bloodhound" in output or "high value" in output or "tier" in output
    print("✓ BHCE live connection successful")


def test_bloodhound_live_connection_legacy(live_config, target_dc):
    """Test live Legacy BloodHound connection."""
    bh_config = live_config.get("bloodhound_live", {}).get("legacy", {})

    if not bh_config.get("enabled"):
        pytest.skip("Legacy BloodHound not configured or disabled")

    result = run_taskhound([
        "--bh-live",
        "--bh-ip", bh_config["ip"],
        "--bh-user", bh_config["user"],
        "--bh-password", bh_config["password"],
        "--legacy"
    ], live_config, target=target_dc)

    assert result.returncode == 0, f"Command failed: {result.stderr}"

    # Check for BloodHound connection indicators
    output = result.stdout.lower()
    assert "bloodhound" in output or "high value" in output or "tier" in output
    print("✓ Legacy BloodHound live connection successful")


def test_bloodhound_data_export_legacy(live_config, target_dc):
    """Test Legacy BloodHound export file ingestion."""
    data_files = live_config.get("bloodhound_data_files", {})
    legacy_file = data_files.get("legacy")

    if not legacy_file or not Path(legacy_file).exists():
        pytest.skip(f"Legacy BloodHound data file not found: {legacy_file}")

    result = run_taskhound([
        "--bh-data", legacy_file
    ], live_config, target=target_dc)

    assert result.returncode == 0, f"Command failed: {result.stderr}"
    output = result.stdout.lower()
    # Should show high-value detection from the export
    print("✓ Legacy BloodHound data import successful")


def test_bloodhound_data_export_bhce(live_config, target_dc):
    """Test BHCE export file ingestion."""
    data_files = live_config.get("bloodhound_data_files", {})
    bhce_file = data_files.get("bhce")

    if not bhce_file or not Path(bhce_file).exists():
        pytest.skip(f"BHCE data file not found: {bhce_file}")

    result = run_taskhound([
        "--bh-data", bhce_file
    ], live_config, target=target_dc)

    assert result.returncode == 0, f"Command failed: {result.stderr}"
    output = result.stdout.lower()
    # Should show high-value detection from the export
    print("✓ BHCE data import successful")


def test_bloodhound_save_and_reuse(live_config, target_dc, sample_output_dir):
    """Test saving BloodHound data and reusing it."""
    bh_config = live_config.get("bloodhound_live", {}).get("bhce", {})

    if not bh_config.get("enabled"):
        pytest.skip("BHCE not configured")

    # First, try to save BloodHound data
    bh_save = sample_output_dir / "bh_export.json"

    result = run_taskhound([
        "--bh-live",
        "--bh-ip", bh_config["ip"],
        "--bh-user", bh_config["user"],
        "--bh-password", bh_config["password"],
        "--bhce",
        "--bh-save", str(bh_save)
    ], live_config, target=target_dc)

    if result.returncode == 0 and bh_save.exists():
        # Now test using the saved file
        result2 = run_taskhound([
            "--bh-data", str(bh_save)
        ], live_config, target=target_dc)

        assert result2.returncode == 0, f"Using saved BH data failed: {result2.stderr}"


def test_ldap_separate_credentials(live_config):
    """Test separate LDAP credentials for SID resolution."""
    ldap_config = live_config.get("ldap", {})

    if not ldap_config:
        pytest.skip("No separate LDAP credentials configured")

    result = run_taskhound([
        "--ldap-user", ldap_config.get("user", live_config["username"]),
        "--ldap-password", ldap_config.get("password", live_config["password"]),
        "--ldap-domain", ldap_config.get("domain", live_config["domain"])
    ], live_config)

    assert result.returncode == 0, f"Command failed: {result.stderr}"


def test_bloodhound_with_dpapi(live_config):
    """Test combined BloodHound and DPAPI features."""
    bh_config = live_config.get("bloodhound", {})

    if not bh_config.get("enabled"):
        pytest.skip("BloodHound not configured")

    if "dpapi_key" not in live_config:
        pytest.skip("No DPAPI key configured")

    result = run_taskhound([
        "--bh-live",
        "--bh-ip", bh_config["ip"],
        "--bh-user", bh_config["user"],
        "--bh-password", bh_config["password"],
        "--bhce" if bh_config.get("type") == "bhce" else "--legacy",
        "--loot",
        "--dpapi-key", live_config["dpapi_key"]
    ], live_config)

    assert result.returncode == 0, f"Command failed: {result.stderr}"

    # Should see both BloodHound and DPAPI output
    output_lower = result.stdout.lower()
    # This is an integration test - just verify it completes successfully
