# Online processing for live target hosts via SMB.
#
# This module handles connecting to targets via SMB, enumerating scheduled
# tasks, and processing them with privilege detection. The main entry point
# is `process_target()` which returns printable output and populates the
# result rows for export.

import contextlib
import os
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union

from impacket.smbconnection import SessionError

from ..auth import AuthContext
from ..classification import PwdLastSetCache, classify_task
from ..laps import (
    LAPS_ERRORS,
    LAPSCache,
    LAPSFailure,
    get_laps_credential_for_host,
)
from ..models.task import TaskRow
from ..output.printer import format_block
from ..parsers.highvalue import HighValueLoader
from ..parsers.task_xml import parse_task_xml
from ..smb.connection import (
    _dns_ptr_lookup,
    get_server_fqdn,
    get_server_sid,
    smb_connect,
    smb_login,
    smb_negotiate,
)
from ..smb.credguard import check_credential_guard
from ..smb.task_rpc import CredentialStatus, TaskRunInfo
from ..smb.tasks import crawl_tasks, smb_listdir
from ..utils.credentials import find_password_for_user
from ..utils.helpers import is_ipv4
from ..utils.logging import debug as log_debug
from ..utils.logging import good, info, status, warn
from ..resolver import (
    format_runas_with_sid_resolution,
    is_sid,
)
from .helpers import (
    perform_credential_validation,
    perform_dpapi_looting,
    prefetch_pwd_last_set,
    prefetch_tier0_members,
    setup_backup_directory,
    sort_tasks_by_priority,
)


def _match_decrypted_password(runas: str, decrypted_creds: List, resolved_runas: Optional[str] = None) -> Optional[str]:
    """
    Match a task's runas field to decrypted credentials and return the password.

    Handles various runas formats:
    - Simple username: "highpriv"
    - Domain\\user: "DOMAIN\\highpriv"
    - Raw SID: "S-1-5-21-..." (uses resolved_runas if provided)

    Args:
        runas: The RunAs field from the task (may be raw SID)
        decrypted_creds: List of ScheduledTaskCredential objects
        resolved_runas: Pre-resolved username if runas was a SID (from earlier resolution)

    Returns:
        Decrypted password if found, None otherwise
    """
    if not decrypted_creds or not runas:
        return None

    # Use the resolved username if the original is a SID
    username = runas if not is_sid(runas) else (resolved_runas or runas)

    return find_password_for_user(username, decrypted_creds, resolved_runas)


def process_target(
    target: str,
    all_rows: List[TaskRow],
    *,
    auth: AuthContext,
    include_ms: bool = False,
    include_local: bool = False,
    hv: Optional[HighValueLoader] = None,
    debug: bool = False,
    show_unsaved_creds: bool = False,
    backup_dir: Optional[str] = None,
    credguard_detect: bool = False,
    no_ldap: bool = False,
    no_rpc: bool = False,
    loot: bool = False,
    dpapi_key: Optional[str] = None,
    bh_connector: Optional[Any] = None,
    concise: bool = False,
    opsec: bool = False,
    laps_cache: Optional[LAPSCache] = None,
    validate_creds: bool = False,
    ldap_tier0: bool = False,
) -> Tuple[List[str], Optional[Union[bool, LAPSFailure]]]:
    """
    Connect to `target`, enumerate scheduled tasks, and return printable lines.

    Args:
        target: Target IP or hostname
        all_rows: List to append result rows to
        auth: AuthContext containing all authentication parameters
        include_ms: Include Microsoft scheduled tasks
        include_local: Include local system account tasks
        hv: HighValueLoader for privilege detection
        debug: Enable debug output
        show_unsaved_creds: Show tasks without saved credentials
        backup_dir: Directory to backup raw XML files
        credguard_detect: Detect Credential Guard (requires RPC)
        no_ldap: Disable LDAP SID resolution
        no_rpc: Disable RPC operations (LSARPC SID lookup, CredGuard, cred validation)
        loot: Enable DPAPI credential looting
        dpapi_key: DPAPI key for decryption
        bh_connector: BloodHound connector
        concise: Use concise output format
        opsec: Enable OPSEC mode (implies no_ldap + no_rpc)
        laps_cache: LAPS credential cache (if LAPS mode enabled)
        validate_creds: Query Task Scheduler RPC to validate stored credentials
        ldap_tier0: Check Tier-0 group membership via LDAP (when no BloodHound data)

    Returns:
        Tuple of (lines, laps_result) where:
        - lines: List of printable output strings
        - laps_result: None if LAPS not used, True if LAPS succeeded,
                       LAPSFailure if LAPS failed for this target
    """
    # Extract values from auth for use throughout the function
    domain = auth.domain
    username = auth.username
    password = auth.password
    hashes = auth.hashes
    aes_key = auth.aes_key
    kerberos = auth.kerberos
    dc_ip = auth.dc_ip
    timeout = auth.timeout
    dns_tcp = auth.dns_tcp
    ldap_domain = auth.ldap_domain
    ldap_user = auth.ldap_user
    ldap_password = auth.ldap_password
    ldap_hashes = auth.ldap_hashes
    gc_server = auth.gc_server

    out_lines: List[str] = []
    laps_result: Optional[Union[bool, LAPSFailure]] = None

    status(f"[Collecting] {target} ...")

    # Log OPSEC status based on which flags are active
    if opsec:
        info(f"{target}: OPSEC mode enabled (--no-ldap --no-rpc)")
    elif no_ldap and no_rpc:
        info(f"{target}: Stealth mode (--no-ldap --no-rpc)")
    elif no_ldap:
        info(f"{target}: LDAP disabled (--no-ldap)")
    elif no_rpc:
        info(f"{target}: RPC disabled (--no-rpc)")

    credguard_status = None
    server_fqdn = None  # Will store the resolved FQDN from SMB
    smb = None
    laps_used = False
    laps_type_used = None
    laps_cred = None  # Track LAPS credentials for RPC reuse
    discovered_hostname = None
    cred_validation_results: Dict[str, TaskRunInfo] = {}  # RPC credential validation cache

    try:
        # LAPS Mode: Two-phase connection (negotiate -> lookup -> auth)
        if laps_cache is not None:
            # Phase 1: Negotiate to discover hostname
            smb = smb_negotiate(target, timeout=timeout)
            discovered_hostname = smb.getServerName()

            if not discovered_hostname:
                # SMBv3 doesn't populate server name during negotiate
                # Try DNS reverse lookup as fallback
                if is_ipv4(target):
                    # Try DC first, then system DNS
                    if dc_ip:
                        discovered_hostname = _dns_ptr_lookup(target, nameserver=dc_ip, use_tcp=dns_tcp)
                    if not discovered_hostname:
                        discovered_hostname = _dns_ptr_lookup(target, nameserver=None, use_tcp=dns_tcp)

                    if discovered_hostname:
                        # Extract just the hostname part (before first dot) for LAPS lookup
                        info(f"{target}: Resolved hostname via DNS: {discovered_hostname}")
                    else:
                        warn(f"{target}: Could not resolve hostname via SMB or DNS")
                        discovered_hostname = target
                else:
                    # Target is already a hostname
                    discovered_hostname = target
            else:
                info(f"{target}: Discovered hostname from SMB: {discovered_hostname}")

            # Phase 2: Look up LAPS credentials
            laps_cred, laps_failure = get_laps_credential_for_host(laps_cache, discovered_hostname)

            if laps_failure:
                # No LAPS password for this host - skip target
                warn(laps_failure.message, verbose_only=True)
                status(f"[Collecting] {target} [-] (No LAPS password)")
                # Map failure types to human-readable messages
                laps_failure_labels = {
                    "not_found": "LAPS: No password in cache",
                    "encrypted": "LAPS: Encrypted (unsupported)",
                    "auth_failed": "LAPS: Auth failed",
                    "remote_uac": "LAPS: Remote UAC blocked",
                }
                failure_reason = laps_failure_labels.get(laps_failure.failure_type, f"LAPS: {laps_failure.failure_type}")
                all_rows.append(TaskRow.failure(
                    discovered_hostname,
                    failure_reason,
                    target_ip=target,
                ))
                with contextlib.suppress(Exception):
                    smb.close()
                return out_lines, laps_failure

            # Phase 3: Authenticate with LAPS credentials
            try:
                smb_login(
                    smb,
                    domain=".",  # Local account for LAPS
                    username=laps_cred.username,
                    password=laps_cred.password,
                    kerberos=False,  # LAPS is always NTLM
                )
                laps_used = True
                laps_type_used = laps_cred.laps_type
                laps_result = True
                good(f"{target}: LAPS authentication successful ({laps_cred.laps_type}, user: {laps_cred.username})")
            except Exception as e:
                # LAPS auth failed
                if debug:
                    traceback.print_exc()
                warn(LAPS_ERRORS["auth_failed"].format(hostname=discovered_hostname), verbose_only=True)
                status(f"[Collecting] {target} [-] (LAPS auth failed)")
                laps_failure = LAPSFailure(
                    hostname=discovered_hostname,
                    failure_type="auth_failed",
                    message=f"LAPS authentication failed: {e}",
                    laps_user_tried=laps_cred.username,
                    laps_type_tried=laps_cred.laps_type,
                )
                all_rows.append(TaskRow.failure(
                    discovered_hostname,
                    f"LAPS auth failed: {e}",
                    target_ip=target,
                ))
                with contextlib.suppress(Exception):
                    smb.close()
                return out_lines, laps_failure
        else:
            # Standard mode: Direct SMB connection
            smb = smb_connect(
                target, domain, username, hashes or password, kerberos=kerberos, dc_ip=dc_ip, timeout=timeout, aes_key=aes_key
            )

        good(f"{target}: Connected via SMB")

        # Resolve the actual FQDN from SMB connection
        # This is critical when target is an IP address - BloodHound needs FQDNs
        # Tries: 1) SMB hostname, 2) DNS via DC, 3) System DNS

        server_fqdn = get_server_fqdn(smb, target_ip=target, dc_ip=dc_ip, dns_tcp=dns_tcp)
        if server_fqdn and server_fqdn != "UNKNOWN_HOST":
            if server_fqdn.upper() != target.upper():
                info(f"{target}: Resolved FQDN: {server_fqdn}")
        else:
            warn(f"{target}: Could not resolve FQDN - using target as-is")
            server_fqdn = target

        # Dual-homed host deduplication:
        # Check if we've already processed this host via a different IP/interface
        # This prevents duplicate entries when the same machine has multiple NICs
        # Uses atomic try_mark_host_processed() to avoid TOCTOU race conditions
        from ..utils.cache_manager import get_cache
        cache = get_cache()
        if cache and server_fqdn != "UNKNOWN_HOST":
            was_first, previous_target = cache.try_mark_host_processed(server_fqdn, target)
            if not was_first:
                warn(f"{target}: Skipping - already processed as {previous_target} (dual-homed host: {server_fqdn})", verbose_only=True)
                status(f"[Collecting] {target} [SKIP] (duplicate of {previous_target})")
                # Add SKIPPED row so async_runner can detect this was a dual-homed skip
                all_rows.append(TaskRow.skipped(
                    host=server_fqdn,
                    reason=f"duplicate of {previous_target}",
                    target_ip=target,
                ))
                # Close SMB connection before returning
                if smb:
                    with contextlib.suppress(Exception):
                        smb.close()
                return [], None

        # Extract the computer account SID using unified resolution
        # Fallback chain: Cache → BloodHound data → LSARPC
        # Skipped when RPC is disabled (LSARPC uses SMB named pipe)
        server_sid = None
        if not no_rpc:
            server_sid = get_server_sid(
                smb, dc_ip=dc_ip, username=username, password=password, hashes=hashes, kerberos=kerberos,
                hv_loader=hv
            )
            if debug:
                if server_sid:
                    log_debug(f"{target}: Computer SID: {server_sid}")
                else:
                    log_debug(f"{target}: Could not retrieve computer SID")
        elif debug:
            log_debug(f"{target}: Skipping SID lookup (--no-rpc mode)")

        # Credential Guard detection (EXPERIMENTAL, only if enabled)
        # Skipped when RPC is disabled (remote registry requires RPC)
        if credguard_detect and not no_rpc:
            credguard_status = check_credential_guard(smb, target)
            if credguard_status is True:
                warn(f"{target}: Credential Guard detected - DPAPI credential extraction will fail")
            elif credguard_status is False:
                log_debug(f"{target}: Credential Guard not detected")
            else:
                # None = couldn't check (Remote Registry service disabled)
                log_debug(f"{target}: Credential Guard status unknown (Remote Registry service likely disabled)")
        elif credguard_detect and no_rpc:
            log_debug(f"{target}: Skipping Credential Guard check (--no-rpc mode)")
    except Exception as e:
        if debug:
            traceback.print_exc()
        msg = str(e)
        status(f"[Collecting] {target} [-] ({msg})")
        all_rows.append(TaskRow.failure(
            target,
            f"SMB connection failed: {msg}",
        ))
        if "STATUS_MORE_PROCESSING_REQUIRED" in msg:
            warn(f"{target}: Kerberos auth failed (SPN not found?). Try using FQDNs or switch to NTLM (-k off).", verbose_only=True)
        else:
            warn(f"{target}: SMB connection failed: {e}", verbose_only=True)
        return out_lines, laps_result

    # Quick local admin presence check
    # For LAPS mode, this also detects Remote UAC (LocalAccountTokenFilterPolicy)
    try:
        _ = smb_listdir(smb, "C$", r"\Windows\System32\Tasks")
        good(f"{target}: Local Admin Access confirmed")
    except Exception as e:
        if debug:
            traceback.print_exc()

        error_msg = str(e)

        # Check if this is Remote UAC blocking LAPS
        if laps_used and "STATUS_ACCESS_DENIED" in error_msg:
            warn(LAPS_ERRORS["remote_uac_short"].format(hostname=discovered_hostname or target), verbose_only=True)
            info("Remote UAC (LocalAccountTokenFilterPolicy=0) is filtering the local admin token", verbose_only=True)
            info("This is common on workstations. Servers typically don't have this issue.", verbose_only=True)
            status(f"[Collecting] {target} [-] (Remote UAC)")
            laps_failure = LAPSFailure(
                hostname=discovered_hostname or target,
                failure_type="remote_uac",
                message=LAPS_ERRORS["remote_uac"].format(hostname=discovered_hostname or target),
                laps_user_tried=laps_cred.username if laps_cache else None,
                laps_type_tried=laps_type_used,
            )
            all_rows.append(TaskRow.failure(
                discovered_hostname or target,
                "Remote UAC (token filtered)",
                target_ip=target,
            ))
            return out_lines, laps_failure

        # Check if C$ admin share doesn't exist (DCs, hardened servers, non-Windows)
        elif "STATUS_BAD_NETWORK_NAME" in error_msg:
            warn(f"{target}: C$ admin share not found (may be disabled or non-Windows host)", verbose_only=True)
            status(f"[Collecting] {target} [-] (No C$ share)")
            all_rows.append(TaskRow.failure(
                discovered_hostname or target,
                "C$ admin share not found",
                target_ip=target,
            ))
            return out_lines, laps_result

        # General access denied (not LAPS-specific)
        elif "STATUS_ACCESS_DENIED" in error_msg:
            warn(f"{target}: Access denied to C$ share", verbose_only=True)
            status(f"[Collecting] {target} [-] (Access Denied)")
            all_rows.append(TaskRow.failure(
                discovered_hostname or target,
                "Access Denied to C$ share",
                target_ip=target,
            ))
            return out_lines, laps_result

        else:
            warn(f"{target}: Local admin check failed: {e}", verbose_only=True)
            status(f"[Collecting] {target} [-] (Admin check failed)")
            all_rows.append(TaskRow.failure(
                discovered_hostname or target,
                f"Admin check failed: {e}",
                target_ip=target,
            ))
            return out_lines, laps_result

    if not include_ms:
        info(f"{target}: Crawling Scheduled Tasks (skipping \\Microsoft for speed)")
    else:
        warn(f"{target}: Crawling ALL Scheduled Tasks, including \\Microsoft (this may be slow!)")

    try:
        items = crawl_tasks(smb, include_ms=include_ms)
    except SessionError:
        if debug:
            traceback.print_exc()
        status(f"[Collecting] {target} [-] (Access Denied)")
        all_rows.append(TaskRow.failure(
            target,
            "Access Denied (Failed to crawl tasks)",
        ))
        warn(f"{target}: Failed to Crawl Tasks. Skipping... (Are you Local Admin?)", verbose_only=True)
        return out_lines, laps_result
    except Exception as e:
        if debug:
            traceback.print_exc()
        status(f"[Collecting] {target} [-] ({e})")
        all_rows.append(TaskRow.failure(
            target,
            f"Crawling failed: {e}",
        ))
        warn(f"{target}: Unexpected error while crawling tasks: {e}", verbose_only=True)
        return out_lines, laps_result

    # First pass: identify tasks with Password logon type for credential validation
    # Credential validation requires RPC (Task Scheduler pipe), skip if no_rpc is set
    password_task_paths: list[str] = []
    if validate_creds and not no_rpc:
        for rel_path, xml_bytes in items:
            meta = parse_task_xml(xml_bytes)
            logon_type = (meta.get("logon_type") or "").strip().lower()
            if logon_type == "password":
                password_task_paths.append(rel_path)

        if password_task_paths:
            info(f"{target}: Found {len(password_task_paths)} tasks with stored credentials to validate")

    # Credential validation via Task Scheduler RPC (if requested and RPC not disabled)
    # When LAPS is used, authenticate with LAPS credentials (local admin) instead of domain creds
    if validate_creds and password_task_paths:
        rpc_domain = domain
        rpc_username = username
        rpc_password = password
        rpc_hashes = hashes
        rpc_aes_key = aes_key
        rpc_kerberos = kerberos

        if laps_used and laps_cred:
            # LAPS credentials are local admin on the target - use them for RPC
            rpc_domain = "."  # Local account
            rpc_username = laps_cred.username
            rpc_password = laps_cred.password
            rpc_hashes = None  # LAPS provides plaintext password
            rpc_aes_key = None
            rpc_kerberos = False  # LAPS is always NTLM
            log_debug(f"{target}: Using LAPS credentials for Task Scheduler RPC")

        cred_validation_results = perform_credential_validation(
            target,
            password_task_paths,
            domain=rpc_domain,
            username=rpc_username,
            password=rpc_password,
            hashes=rpc_hashes,
            aes_key=rpc_aes_key,
            kerberos=rpc_kerberos,
            dc_ip=dc_ip,
            opsec=no_rpc,  # Use no_rpc flag (opsec sets this)
            debug=debug,
        )

    # Create backup directory structure if backup is requested
    backup_target_dir = setup_backup_directory(target, backup_dir, debug=debug)

    # Perform automatic credential looting if requested
    decrypted_creds: List[Any] = []
    if loot:
        decrypted_creds, loot_lines = perform_dpapi_looting(
            target,
            smb,
            dpapi_key=dpapi_key,
            backup_target_dir=backup_target_dir,
            debug=debug,
        )
        out_lines.extend(loot_lines)

    total = len(items)
    filtered_count = 0  # Count of tasks that pass should_include filter
    priv_count = 0
    priv_lines: List[str] = []
    task_lines: List[str] = []

    # Pre-fetch pwdLastSet for all unique users via single LDAP batch query
    pwd_cache: PwdLastSetCache = prefetch_pwd_last_set(
        target,
        items,
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        hashes=hashes,
        kerberos=kerberos,
        aes_key=aes_key,
        ldap_domain=ldap_domain,
        ldap_user=ldap_user,
        ldap_password=ldap_password,
        ldap_hashes=ldap_hashes,
        no_ldap=no_ldap,
        opsec=opsec,
        hv=hv,
        debug=debug,
    )

    # Pre-fetch Tier-0 group members via LDAP (pre-flight approach)
    tier0_cache: Dict[str, Tuple[bool, list]] = prefetch_tier0_members(
        target,
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        hashes=hashes,
        kerberos=kerberos,
        aes_key=aes_key,
        ldap_domain=ldap_domain,
        ldap_user=ldap_user,
        ldap_password=ldap_password,
        ldap_hashes=ldap_hashes,
        no_ldap=no_ldap,
        ldap_tier0=ldap_tier0,
        hv=hv,
        debug=debug,
    )

    for rel_path, xml_bytes in items:
        meta = parse_task_xml(xml_bytes)
        # Save raw XML to backup directory if requested
        if backup_target_dir:
            try:
                # Create subdirectories as needed (mirroring the original structure)
                backup_file_path = os.path.join(backup_target_dir, rel_path.replace("\\", os.sep))
                backup_file_dir = os.path.dirname(backup_file_path)
                os.makedirs(backup_file_dir, exist_ok=True)
                with open(backup_file_path, "wb") as f:
                    f.write(xml_bytes)
            except Exception as e:
                if debug:
                    warn(f"{target}: Failed to backup {rel_path}: {e}")

        runas = meta.get("runas")
        if not runas:
            continue
        what = meta.get("command") or ""
        if meta.get("arguments"):
            what = f"{what} {meta.get('arguments')}"

        # Use resolved FQDN as host, keep original target as IP
        # This ensures BloodHound gets proper FQDNs even when connecting via IP
        hostname = server_fqdn if server_fqdn else target
        row = TaskRow.from_meta(hostname, rel_path, meta, target_ip=target, computer_sid=server_sid)

        # Enrich row with credential validation data if available
        # Task paths need normalization: SMB uses "TaskName", RPC uses "\TaskName"
        if cred_validation_results:
            # Try both with and without leading backslash
            rpc_path = "\\" + rel_path if not rel_path.startswith("\\") else rel_path
            rpc_path_alt = rel_path.lstrip("\\")

            task_run_info = cred_validation_results.get(rpc_path) or cred_validation_results.get(rpc_path_alt)
            if task_run_info:
                row.cred_status = task_run_info.credential_status.value
                row.cred_password_valid = task_run_info.password_valid
                row.cred_hijackable = task_run_info.task_hijackable
                row.cred_last_run = task_run_info.last_run.isoformat() if task_run_info.last_run else None
                row.cred_return_code = f"0x{task_run_info.return_code:08X}" if task_run_info.return_code is not None else None
                # Only set cred_detail for VALID_RESTRICTED - it explains the specific restriction
                # Other statuses: Return Code description is sufficient (shown in printer)
                if task_run_info.credential_status == CredentialStatus.VALID_RESTRICTED:
                    row.cred_detail = task_run_info.status_detail

        # Resolve SID early if runas is a SID - store result for credential matching and output
        # This ensures we only resolve once per task, and the result is available for all uses
        # Skipped in OPSEC mode to avoid SMB/LSARPC and LDAP queries
        # Also skip well-known local SIDs (S-1-5-18 SYSTEM, S-1-5-19, S-1-5-20) - they'll be filtered anyway
        if is_sid(runas) and not opsec:
            # Skip SID resolution for well-known local SIDs that will be filtered out
            # This avoids unnecessary cache lookups for SYSTEM (S-1-5-18), etc.
            from ..resolver import looks_like_domain_user
            if not looks_like_domain_user(runas) and not include_local:
                # This SID is a local/system account and we're not including locals
                # Skip resolution - the task will be filtered out in classify_task()
                pass
            else:
                # Derive local domain SID prefix from computer SID for foreign domain detection
                from ..resolver import get_domain_sid_prefix
                local_domain_prefix = get_domain_sid_prefix(server_sid) if server_sid else None

                # Get known domain SID prefixes for unknown domain detection
                # Pass full dict (prefix -> FQDN) for trust-aware display
                known_prefixes = hv.hv_domain_sids if hv and hasattr(hv, 'hv_domain_sids') and hv.hv_domain_sids else None

                _, row.resolved_runas = format_runas_with_sid_resolution(
                    runas,
                    hv_loader=hv,
                    bh_connector=bh_connector,
                    smb_connection=None if no_rpc else smb,  # Skip target LSARPC if --no-rpc
                    no_ldap=no_ldap,
                    no_rpc=no_rpc,  # Also controls DC LSARPC for cross-trust resolution
                    domain=domain,
                    dc_ip=dc_ip,
                    username=username,
                    password=password,
                    hashes=hashes,
                    kerberos=kerberos,
                    aes_key=aes_key,
                    ldap_domain=ldap_domain,
                    ldap_user=ldap_user,
                    ldap_password=ldap_password,
                    ldap_hashes=ldap_hashes,
                    local_domain_sid_prefix=local_domain_prefix,
                    known_domain_prefixes=known_prefixes,
                    gc_server=gc_server,
                )

        # Enrich row with decrypted password if available from DPAPI loot
        if decrypted_creds:
            row.decrypted_password = _match_decrypted_password(runas, decrypted_creds, row.resolved_runas)

        # Add Credential Guard status to each row
        row.credential_guard = credguard_status
        # Determine if the task stores credentials or runs with token/S4U (no saved credentials)
        logon_type = (meta.get("logon_type") or "").strip()
        no_saved_creds = (not logon_type) or logon_type.lower() in (
            "interactivetoken",
            "s4u",
            "interactivetokenorpassword",
        )
        if no_saved_creds:
            row.credentials_hint = "no_saved_credentials"
        elif logon_type.lower() == "password":
            row.credentials_hint = "stored_credentials"

        # Use shared classification logic
        # pwd_cache was pre-fetched before the loop for password freshness analysis
        # tier0_cache was pre-fetched for LDAP-based Tier-0 detection (when --ldap-tier0)
        result = classify_task(
            row=row,
            meta=meta,
            runas=runas,
            rel_path=rel_path,
            hv=hv,
            show_unsaved_creds=show_unsaved_creds,
            include_local=include_local,
            pwd_cache=pwd_cache,
            tier0_cache=tier0_cache,
            resolved_runas=row.resolved_runas,
        )

        if not result.should_include:
            continue

        filtered_count += 1  # Task passed the filter

        # Format output block based on classification
        if result.task_type in ("TIER-0", "PRIV"):
            priv_lines.extend(
                format_block(
                    result.task_type,
                    rel_path,
                    runas,
                    what,
                    meta.get("author"),
                    meta.get("date"),
                    extra_reason=result.reason,
                    password_analysis=result.password_analysis,
                    hv=hv,
                    bh_connector=bh_connector,
                    smb_connection=None if no_rpc else smb,  # Skip LSARPC if --no-rpc
                    no_ldap=no_ldap,
                    domain=domain,
                    dc_ip=dc_ip,
                    hostname=hostname,
                    username=username,
                    password=password,
                    hashes=hashes,
                    kerberos=kerberos,
                    enabled=meta.get("enabled"),
                    ldap_domain=ldap_domain,
                    ldap_user=ldap_user,
                    ldap_password=ldap_password,
                    ldap_hashes=ldap_hashes,
                    meta=meta,
                    decrypted_creds=decrypted_creds,
                    concise=concise,
                    cred_validation=row.to_dict() if row.cred_status else None,
                    resolved_runas=row.resolved_runas,
                    credential_guard=credguard_status,
                    cache_manager=cache,
                )
            )
            priv_count += 1
        else:
            # Regular TASK
            task_lines.extend(
                format_block(
                    "TASK",
                    rel_path,
                    runas,
                    what,
                    meta.get("author"),
                    meta.get("date"),
                    password_analysis=result.password_analysis,
                    hv=hv,
                    bh_connector=bh_connector,
                    smb_connection=None if no_rpc else smb,  # Skip LSARPC if --no-rpc
                    no_ldap=no_ldap,
                    domain=domain,
                    dc_ip=dc_ip,
                    hostname=hostname,
                    username=username,
                    password=password,
                    hashes=hashes,
                    kerberos=kerberos,
                    enabled=meta.get("enabled"),
                    ldap_domain=ldap_domain,
                    ldap_user=ldap_user,
                    ldap_password=ldap_password,
                    ldap_hashes=ldap_hashes,
                    meta=meta,
                    decrypted_creds=decrypted_creds,
                    concise=concise,
                    cred_validation=row.to_dict() if row.cred_status else None,
                    resolved_runas=row.resolved_runas,
                    credential_guard=credguard_status,
                    cache_manager=cache,
                )
            )

        all_rows.append(row)

    lines = priv_lines + task_lines
    # Sort tasks by priority: TIER-0 > PRIV > TASK
    sorted_lines = sort_tasks_by_priority(lines)
    backup_msg = f", {total} raw XMLs backed up" if backup_target_dir else ""
    laps_msg = f" (LAPS: {laps_type_used})" if laps_used else ""

    priv_display = priv_count if (hv and hv.loaded) else 'N/A'
    # Show filtered count (domain tasks) vs total (all tasks including SYSTEM)
    if filtered_count < total:
        status(f"[Collected] {target}: {filtered_count} domain tasks ({total} total), {priv_display} Privileged")
    else:
        status(f"[Collected] {target}: {total} Tasks, {priv_display} Privileged")
    good(f"{target}: Found {filtered_count} tasks (of {total} total), privileged {priv_display}{backup_msg}{laps_msg}")

    # Combine credential loot output with task listing output
    # Put credentials first since they're the most valuable
    return out_lines + sorted_lines, laps_result
