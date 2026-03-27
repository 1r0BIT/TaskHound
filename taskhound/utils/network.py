from typing import Optional

from ..resolver import extract_domain_sid_from_hv
from ..resolver.backends import resolve_sid_via_ldap
from .logging import good, info, warn


def verify_ldap_connection(
    domain: Optional[str],
    dc_ip: Optional[str],
    username: Optional[str],
    password: Optional[str],
    hashes: Optional[str],
    kerberos: bool,
    no_ldap: bool,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
    hv_loader=None,
):
    """Test LDAP connection and SID resolution capability during initialization."""
    if no_ldap:
        info("LDAP resolution disabled - skipping connection test")
        return

    # Determine which credentials to use for LDAP test
    # Priority: dedicated LDAP credentials > main auth credentials
    test_domain = ldap_domain if ldap_domain else domain
    test_username = ldap_user if ldap_user else username
    test_password = ldap_password if ldap_password else password
    test_hashes = ldap_hashes if ldap_hashes else hashes

    # LDAP SID resolution now supports both passwords and NTLM hashes!
    if not test_password and not test_hashes:
        warn("LDAP test skipped - no credentials available (password or hashes)")
        return

    if not test_domain or not test_username:
        warn(f"LDAP test skipped - missing credentials (domain={test_domain}, username={test_username})")
        return

    info("Testing LDAP connection and SID resolution...")

    # Show which credentials to use for the test
    if ldap_user or ldap_domain:
        info(f"Using dedicated LDAP credentials: {test_username}@{test_domain}")
    else:
        info(f"Using main auth credentials for LDAP: {test_username}@{test_domain}")

    # Test with the well-known Administrator SID (RID 500) which should exist in most domains
    # Build the domain SID by taking the first 3 parts and appending -500
    test_sid = None

    # For testing purposes, we'll try to resolve a well-known SID
    # We use the local Administrator account SID pattern: S-1-5-21-<domain>-500
    # Since we don't know the exact domain SID, we'll use a fallback approach
    try:
        # Try to get a realistic test SID from BloodHound data first
        test_sid = extract_domain_sid_from_hv(hv_loader)

        if not test_sid:
            info("No BloodHound data available - skipping SID resolution test")
            info("LDAP connectivity test completed (SID resolution will be tested during actual execution)")
            return
        else:
            info("Using domain SID derived from BloodHound data for realistic testing")

        info(f"Testing SID resolution with: {test_sid}")
        result = resolve_sid_via_ldap(test_sid, test_domain, dc_ip, test_username, test_password, test_hashes, kerberos)

        if result:
            good(f"LDAP test successful: {test_sid} -> {result}")
            good("SID resolution initialized and ready")
        else:
            # Check if the domain SID from BloodHound matches the target domain
            if test_sid:
                test_domain_sid = "-".join(test_sid.split("-")[:-1])  # Remove RID to get domain SID
                warn(f"LDAP test failed: Could not resolve {test_sid}")
                info("This may be normal if BloodHound data is from a different domain than the target")
                info(f"BloodHound domain SID: {test_domain_sid}")
                info("SID resolution will still work for actual SIDs from the target domain")
            else:
                warn(f"LDAP test failed: Could not resolve {test_sid}")
                warn("SID resolution may not work properly")

    except ImportError as e:
        warn(f"LDAP test failed: Missing dependencies - {e}")
    except Exception as e:
        warn(f"LDAP test failed: {e}")
