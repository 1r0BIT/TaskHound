"""
Test engine functionality and merged feature integration.
"""
import inspect

from taskhound.engine import _format_block, process_target


def test_process_target_signature_has_dpapi_params():
    """Test that process_target has DPAPI parameters."""
    sig = inspect.signature(process_target)
    params = list(sig.parameters.keys())

    assert 'loot' in params, "Missing 'loot' parameter"
    assert 'dpapi_key' in params, "Missing 'dpapi_key' parameter"


def test_process_target_signature_has_bloodhound_params():
    """Test that process_target has BloodHound/LDAP parameters."""
    sig = inspect.signature(process_target)
    params = list(sig.parameters.keys())

    assert 'ldap_domain' in params, "Missing 'ldap_domain' parameter"
    assert 'ldap_user' in params, "Missing 'ldap_user' parameter"
    assert 'ldap_password' in params, "Missing 'ldap_password' parameter"


def test_format_block_signature_has_all_params():
    """Test that _format_block has parameters from both features."""
    sig = inspect.signature(_format_block)
    params = list(sig.parameters.keys())

    # DPAPI parameter
    assert 'decrypted_creds' in params, "Missing 'decrypted_creds' parameter"

    # BloodHound parameters
    assert 'ldap_domain' in params, "Missing 'ldap_domain' parameter"
    assert 'meta' in params, "Missing 'meta' parameter"


def test_process_target_parameter_count():
    """Test that process_target has expected number of parameters."""
    sig = inspect.signature(process_target)
    params = list(sig.parameters.keys())

    # Should have parameters from both features merged
    assert len(params) >= 20, f"Expected at least 20 parameters, got {len(params)}"


def test_format_block_parameter_count():
    """Test that _format_block has expected number of parameters."""
    sig = inspect.signature(_format_block)
    params = list(sig.parameters.keys())

    # Should have parameters from both features merged
    assert len(params) >= 20, f"Expected at least 20 parameters, got {len(params)}"
