import sys
from typing import Optional

from ..resolver import extract_domain_sid_from_hv
from ..resolver.backends import resolve_sid_via_ldap
from .logging import good, info, warn


def preflight_credential_check(
    domain: Optional[str],
    username: Optional[str],
    password: Optional[str],
    hashes: Optional[str],
    kerberos: bool,
    dc_ip: Optional[str],
    timeout: int,
    aes_key: Optional[str] = None,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
    no_ldap: bool = False,
    targets: Optional[list] = None,
):
    """Validate credentials before scanning to prevent account lockout.

    Tests main auth (SMB) and dedicated LDAP auth (if specified) with a
    single authentication attempt each.  If either fails, the tool aborts
    immediately so the operator can fix the issue before lockout policies
    are triggered across multiple targets.

    Skipped for local auth (domain='.') since there is no domain lockout risk.
    """
    if not domain or not username:
        return  # offline mode or missing args — validate_args handles this
    if domain == ".":
        return  # local auth — no domain lockout risk

    info("Pre-flight credential check...")

    # --- 1. Main auth: test SMB against DC or first target ---
    smb_target = dc_ip
    if not smb_target and targets:
        smb_target = targets[0]
    if not smb_target:
        warn("Pre-flight: no --dc-ip or target available for credential test — skipping")
        return

    try:
        from ..smb.connection import smb_connect

        smb = smb_connect(
            target=smb_target,
            domain=domain,
            username=username,
            password=hashes or password,
            kerberos=kerberos,
            dc_ip=dc_ip,
            timeout=timeout,
            aes_key=aes_key,
        )
        smb.close()
        good(f"Pre-flight: main credentials validated ({username}@{domain} → {smb_target})")
    except Exception as e:
        err_str = str(e)
        # Detect common auth failures
        is_auth_failure = any(tok in err_str.upper() for tok in [
            "STATUS_LOGON_FAILURE",
            "STATUS_ACCOUNT_DISABLED",
            "STATUS_ACCOUNT_LOCKED_OUT",
            "STATUS_PASSWORD_EXPIRED",
            "STATUS_PASSWORD_MUST_CHANGE",
            "KDC_ERR_PREAUTH_FAILED",
            "KDC_ERR_CLIENT_REVOKED",
            "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        ])
        if is_auth_failure:
            from .console import console
            console.print(
                f"\n[bold red]CREDENTIAL CHECK FAILED[/] — main auth ({username}@{domain}) "
                f"against {smb_target}:\n  {err_str}\n\n"
                "[bold yellow]Aborting to prevent account lockout.[/]\n"
                "Fix credentials and retry. "
                "If you are sure the creds are correct, check lockout threshold and DC reachability."
            )
            sys.exit(1)
        else:
            # Non-auth error (network timeout, connection refused, etc.)
            # Warn but don't abort — the target might just be unreachable
            warn(f"Pre-flight: could not verify main credentials against {smb_target}: {err_str}")
            warn("Proceeding anyway — this may be a connectivity issue, not a credential problem")

    # --- 2. Dedicated LDAP auth (if different from main) ---
    if no_ldap:
        return
    has_dedicated_ldap = ldap_user or ldap_domain or ldap_password or ldap_hashes
    if not has_dedicated_ldap:
        return  # LDAP uses same creds as main — already validated above

    eff_ldap_domain = ldap_domain or domain
    eff_ldap_user = ldap_user or username
    eff_ldap_pass = ldap_password or password
    eff_ldap_hashes = ldap_hashes or hashes

    if not eff_ldap_pass and not eff_ldap_hashes:
        return  # nothing to test

    ldap_target = dc_ip
    if not ldap_target:
        warn("Pre-flight: no --dc-ip for LDAP credential test — skipping")
        return

    try:
        from impacket.ldap import ldap as ldap_mod

        base_dn = ",".join(f"DC={part}" for part in eff_ldap_domain.split("."))
        conn = ldap_mod.LDAPConnection(f"ldap://{ldap_target}", base_dn)
        conn.login(eff_ldap_user, eff_ldap_pass or "", eff_ldap_domain)
        # Quick search to confirm we have read access
        conn.search(searchFilter="(objectClass=domain)", attributes=["distinguishedName"], sizeLimit=1)
        good(f"Pre-flight: LDAP credentials validated ({eff_ldap_user}@{eff_ldap_domain} → {ldap_target})")
    except Exception as e:
        err_str = str(e)
        is_auth_failure = any(tok in err_str.lower() for tok in [
            "invalidcredentials",
            "data 52e",   # AD error code for invalid credentials
            "data 532",   # password expired
            "data 533",   # account disabled
            "data 701",   # account expired
            "data 775",   # account locked
        ])
        if is_auth_failure:
            from .console import console
            console.print(
                f"\n[bold red]CREDENTIAL CHECK FAILED[/] — LDAP auth ({eff_ldap_user}@{eff_ldap_domain}) "
                f"against {ldap_target}:\n  {err_str}\n\n"
                "[bold yellow]Aborting to prevent account lockout.[/]\n"
                "Fix --ldap-user / --ldap-password and retry."
            )
            sys.exit(1)
        else:
            warn(f"Pre-flight: could not verify LDAP credentials against {ldap_target}: {err_str}")
            warn("Proceeding anyway — this may be a connectivity issue")


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
