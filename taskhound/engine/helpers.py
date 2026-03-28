# Helper utilities for task processing.
#
# Contains shared helper functions used by both online and offline
# processing modules.

import os
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..utils.logging import good, info, warn


@dataclass
class ConnectionContext:
    """Context object holding SMB connection state and metadata."""

    smb: Any = None
    server_fqdn: Optional[str] = None
    server_sid: Optional[str] = None
    credguard_status: Optional[bool] = None
    laps_used: bool = False
    laps_type_used: Optional[str] = None
    discovered_hostname: Optional[str] = None
    laps_cred: Any = None  # LAPSCredential if LAPS mode


@dataclass
class ProcessingContext:
    """Context for task processing with validation and cache data."""

    cred_validation_results: Dict[str, Any] = field(default_factory=dict)
    decrypted_creds: List[Any] = field(default_factory=list)
    pwd_cache: Dict[str, Any] = field(default_factory=dict)
    tier0_cache: Dict[str, Tuple[bool, list]] = field(default_factory=dict)
    backup_target_dir: Optional[str] = None


def setup_backup_directory(target: str, backup_dir: Optional[str], debug: bool = False) -> Optional[str]:
    """
    Create backup directory structure for raw XML files.

    Directory structure:
        backup_dir/
        └── <target>/
            └── tasks/       <- XML files go here
                └── *.xml

    Args:
        target: Target host identifier
        backup_dir: Base backup directory path (e.g., ./output/raw_backups)
        debug: Enable debug output

    Returns:
        Path to target-specific tasks backup directory, or None if disabled/failed
    """
    if not backup_dir:
        return None

    # Create tasks subdirectory for XML files
    backup_target_dir = os.path.join(backup_dir, target, "tasks")
    try:
        os.makedirs(backup_target_dir, exist_ok=True)
        good(f"{target}: Raw XML backup enabled - saving to {backup_target_dir}")
        return backup_target_dir
    except Exception as e:
        warn(f"{target}: Failed to create backup directory {backup_target_dir}: {e}")
        return None


def perform_credential_validation(
    target: str,
    password_task_paths: List[str],
    *,
    domain: str,
    username: str,
    password: Optional[str],
    hashes: Optional[str],
    aes_key: Optional[str],
    kerberos: bool,
    dc_ip: Optional[str],
    opsec: bool,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Validate credentials for tasks via Task Scheduler RPC.

    Args:
        target: Target host
        password_task_paths: List of task paths to validate
        domain: Authentication domain
        username: Authentication username
        password: Password for authentication
        hashes: NTLM hashes
        aes_key: Kerberos AES key
        kerberos: Use Kerberos authentication
        dc_ip: Domain controller IP
        opsec: OPSEC mode (skips validation)
        debug: Enable debug output

    Returns:
        Dict mapping task paths to TaskRunInfo results
    """
    from ..smb.task_rpc import CredentialStatus, TaskSchedulerRPC

    if not password_task_paths:
        info(f"{target}: No password-authenticated tasks found - skipping credential validation")
        return {}

    if opsec:
        info(f"{target}: Skipping credential validation (OPSEC mode)")
        return {}

    # Skip if using ccache-only Kerberos
    if kerberos and not password and not hashes and not aes_key:
        warn(f"{target}: Credential validation not supported with ccache-only Kerberos")
        return {}

    info(f"{target}: Querying Task Scheduler RPC for credential validation...")

    try:
        # Parse hashes for RPC auth
        lm_hash = ""
        nt_hash = ""
        if hashes:
            hash_parts = hashes.split(":")
            if len(hash_parts) == 2:
                lm_hash, nt_hash = hash_parts
            elif len(hash_parts) == 1 and len(hash_parts[0]) == 32:
                nt_hash = hash_parts[0]

        rpc_client = TaskSchedulerRPC(
            target=target,
            domain=domain,
            username=username,
            password=password or "",
            lm_hash=lm_hash,
            nt_hash=nt_hash,
            aes_key=aes_key or "",
            kerberos=kerberos,
            dc_ip=dc_ip or "",
        )

        if not rpc_client.connect():
            warn(f"{target}: Failed to connect to Task Scheduler RPC")
            return {}

        results = rpc_client.validate_specific_tasks(password_task_paths)
        rpc_client.disconnect()

        if results:
            valid_count = sum(1 for r in results.values() if r.password_valid)
            invalid_count = sum(
                1 for r in results.values() if r.credential_status == CredentialStatus.INVALID
            )
            unknown_count = sum(
                1 for r in results.values() if r.credential_status == CredentialStatus.UNKNOWN
            )
            good(
                f"{target}: Validated {len(results)} password tasks "
                f"({valid_count} valid, {invalid_count} invalid, {unknown_count} unknown)"
            )
        else:
            info(f"{target}: No run info available for password tasks")

        return results

    except Exception as e:
        warn(f"{target}: Credential validation failed: {e}")
        if debug:
            traceback.print_exc()
        return {}


def perform_dpapi_looting(
    target: str,
    smb: Any,
    *,
    dpapi_key: Optional[str],
    backup_target_dir: Optional[str],
    debug: bool = False,
) -> Tuple[List[Any], List[str]]:
    """
    Perform DPAPI credential looting (live or offline collection).

    Args:
        target: Target host
        smb: SMB connection
        dpapi_key: DPAPI key for live decryption (None for offline collection)
        backup_target_dir: Backup directory (for nested loot storage)
        debug: Enable debug output

    Returns:
        Tuple of (decrypted_creds, output_lines)
    """
    out_lines: List[str] = []
    decrypted_creds: List[Any] = []

    if dpapi_key:
        # Mode 1: Live decryption with DPAPI key
        try:
            from ..dpapi.looter import loot_credentials

            info(f"{target}: Starting DPAPI credential looting...")
            decrypted_creds = loot_credentials(smb, dpapi_key)

            if decrypted_creds:
                good(f"{target}: Successfully decrypted {len(decrypted_creds)} Task Scheduler credentials!")
            else:
                info(f"{target}: No credentials decrypted (no matching masterkeys or no credential blobs found)")

        except Exception as e:
            warn(f"{target}: DPAPI credential looting failed: {e}")
            if debug:
                traceback.print_exc()
    else:
        # Mode 2: Offline collection without DPAPI key
        try:
            from ..dpapi.looter import collect_dpapi_files

            # Create loot directory structure
            # backup_target_dir points to raw_backups/<host>/tasks/
            # We need dpapi to go to raw_backups/<host>/dpapi_loot/
            if backup_target_dir:
                # Go up from tasks/ to host dir, then into dpapi_loot/
                host_backup_dir = os.path.dirname(backup_target_dir)
                loot_target_dir = os.path.join(host_backup_dir, "dpapi_loot")
            else:
                loot_base_dir = "dpapi_loot"
                loot_target_dir = os.path.join(loot_base_dir, target)

            os.makedirs(loot_target_dir, exist_ok=True)

            info(f"{target}: Collecting DPAPI files for offline decryption...")
            info(f"{target}: Saving to: {loot_target_dir}")

            stats = collect_dpapi_files(smb, loot_target_dir)

            good(f"{target}: Collected {stats['masterkeys']} masterkeys and {stats['credentials']} credential blobs")

            out_lines.extend([
                "",
                "=" * 80,
                "DPAPI FILES COLLECTED FOR OFFLINE DECRYPTION",
                "=" * 80,
                "",
                f"Output Directory : {loot_target_dir}",
                f"Masterkeys       : {stats['masterkeys']} files (in masterkeys/)",
                f"Credential Blobs : {stats['credentials']} files (in credentials/)",
                "",
                "NEXT STEPS:",
                "  1. Obtain DPAPI_SYSTEM userkey:",
                f"     nxc smb {target} -u <user> -p <pass> --lsa",
                "",
                "  2. Decrypt with the userkey:",
                f"     taskhound -t {target} -u <user> -p <pass> \\",
                "              --dpapi-key <dpapi_userkey>",
                "",
                f"See {os.path.join(loot_target_dir, 'README.txt')} for detailed instructions",
                "=" * 80,
                "",
            ])

        except Exception as e:
            warn(f"{target}: DPAPI file collection failed: {e}")
            if debug:
                traceback.print_exc()

    return decrypted_creds, out_lines


def prefetch_pwd_last_set(
    target: str,
    items: List[Tuple[str, bytes]],
    *,
    domain: str,
    dc_ip: Optional[str],
    username: str,
    password: Optional[str],
    hashes: Optional[str],
    kerberos: bool,
    aes_key: Optional[str],
    ldap_domain: Optional[str],
    ldap_user: Optional[str],
    ldap_password: Optional[str],
    ldap_hashes: Optional[str],
    no_ldap: bool,
    opsec: bool,
    hv: Any,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Pre-fetch pwdLastSet for all unique users via single LDAP batch query.

    Args:
        target: Target host (for logging)
        items: List of (rel_path, xml_bytes) tuples
        domain: Domain for LDAP auth
        dc_ip: Domain controller IP
        username: LDAP auth username
        password: LDAP auth password
        hashes: LDAP auth hashes
        kerberos: Use Kerberos for LDAP
        aes_key: Kerberos AES key
        ldap_domain: Override domain for LDAP
        ldap_user: Override user for LDAP
        ldap_password: Override password for LDAP
        ldap_hashes: Override hashes for LDAP
        no_ldap: Disable LDAP queries
        opsec: OPSEC mode
        hv: HighValueLoader instance
        debug: Enable debug output

    Returns:
        Dict mapping normalized username to pwdLastSet datetime
    """
    from ..parsers.task_xml import parse_task_xml
    from ..resolver import is_sid

    pwd_cache: Dict[str, Any] = {}

    if no_ldap or opsec or (hv and hv.loaded):
        return pwd_cache

    # Collect unique runas users from all tasks with stored credentials
    unique_users = set()
    for _rel_path, xml_bytes in items:
        meta = parse_task_xml(xml_bytes)
        runas = meta.get("runas")
        if not runas:
            continue
        logon_type = (meta.get("logon_type") or "").strip().lower()
        # Only query users from tasks with stored credentials (skip SIDs)
        if logon_type == "password" and not is_sid(runas):
            unique_users.add(runas)

    if not unique_users:
        return pwd_cache

    info(f"{target}: Querying LDAP for password age data ({len(unique_users)} users)...")

    try:
        from ..resolver import batch_get_user_attributes

        ldap_auth_domain = ldap_domain or domain
        ldap_auth_user = ldap_user or username
        ldap_auth_pass = ldap_password or password
        ldap_auth_hashes = ldap_hashes or hashes

        results = batch_get_user_attributes(
            usernames=list(unique_users),
            domain=ldap_auth_domain,
            dc_ip=dc_ip,
            username=ldap_auth_user,
            password=ldap_auth_pass,
            hashes=ldap_auth_hashes,
            kerberos=kerberos,
            aes_key=aes_key,
            attributes=["pwdLastSet", "sAMAccountName"],
        )

        # Build cache: normalized_username -> pwdLastSet datetime
        for norm_user, attrs in results.items():
            pwd_last_set = attrs.get("pwdLastSet")
            if pwd_last_set:
                pwd_cache[norm_user] = pwd_last_set

        if pwd_cache:
            good(f"{target}: Retrieved password age data for {len(pwd_cache)} users")
        else:
            info(f"{target}: No password age data available from LDAP")

    except Exception as e:
        warn(f"{target}: LDAP batch query failed: {e}")
        if debug:
            traceback.print_exc()

    return pwd_cache


def prefetch_tier0_members(
    target: str,
    *,
    domain: str,
    dc_ip: Optional[str],
    username: str,
    password: Optional[str],
    hashes: Optional[str],
    kerberos: bool,
    aes_key: Optional[str],
    ldap_domain: Optional[str],
    ldap_user: Optional[str],
    ldap_password: Optional[str],
    ldap_hashes: Optional[str],
    no_ldap: bool,
    ldap_tier0: bool,
    hv: Any,
    debug: bool = False,
) -> Dict[str, Tuple[bool, list]]:
    """
    Pre-fetch Tier-0 group members via LDAP.

    Args:
        target: Target host (for logging)
        domain: Domain for LDAP auth
        dc_ip: Domain controller IP
        username: LDAP auth username
        password: LDAP auth password
        hashes: LDAP auth hashes
        kerberos: Use Kerberos for LDAP
        aes_key: Kerberos AES key
        ldap_domain: Override domain for LDAP
        ldap_user: Override user for LDAP
        ldap_password: Override password for LDAP
        ldap_hashes: Override hashes for LDAP
        no_ldap: Disable LDAP queries
        ldap_tier0: Enable Tier-0 lookup
        hv: HighValueLoader instance
        debug: Enable debug output

    Returns:
        Dict mapping username to (is_tier0, group_list) tuple
    """
    tier0_cache: Dict[str, Tuple[bool, list]] = {}

    if not ldap_tier0 or no_ldap or (hv and hv.loaded):
        return tier0_cache

    info(f"{target}: Fetching Tier-0 group members via LDAP (pre-flight)...")

    try:
        from ..resolver import fetch_tier0_members

        ldap_auth_domain = ldap_domain or domain
        ldap_auth_user = ldap_user or username
        ldap_auth_pass = ldap_password or password
        ldap_auth_hashes = ldap_hashes or hashes

        tier0_cache = fetch_tier0_members(
            domain=ldap_auth_domain,
            dc_ip=dc_ip,
            auth_username=ldap_auth_user,
            auth_password=ldap_auth_pass,
            hashes=ldap_auth_hashes,
            kerberos=kerberos,
            aes_key=aes_key,
        )

        if tier0_cache:
            good(f"{target}: Loaded {len(tier0_cache)} Tier-0 users from LDAP")
        else:
            info(f"{target}: No Tier-0 users found in domain")

    except Exception as e:
        warn(f"{target}: LDAP Tier-0 pre-flight failed: {e}")
        if debug:
            traceback.print_exc()

    return tier0_cache


def perform_service_enumeration(
    target: str,
    smb: Any,
    host: str,
    *,
    target_ip: Optional[str] = None,
    computer_sid: Optional[str] = None,
    local_accounts: Optional[set] = None,
    credguard_status: Optional[bool] = None,
    hv: Optional[Any] = None,
    bh_connector: Optional[Any] = None,
    no_ldap: bool = False,
    no_rpc: bool = False,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
    pwd_cache: Optional[Dict] = None,
    tier0_cache: Optional[Dict] = None,
    debug: bool = False,
) -> List[Any]:
    """
    Enumerate Windows services via SVCCTL RPC, resolve SIDs, and classify.

    Args:
        target: Target identifier (for logging)
        smb: Authenticated SMB connection
        host: Server FQDN
        target_ip: Original target IP
        computer_sid: Computer SID
        local_accounts: Known local account names (lowercase) from SAMR
        credguard_status: Credential Guard status for the host
        hv: HighValueLoader for privilege classification
        bh_connector: BloodHound connector for SID resolution
        no_ldap: Disable LDAP queries
        no_rpc: Disable RPC operations
        domain: Domain name for SID resolution
        dc_ip: Domain controller IP
        username/password/hashes/kerberos/aes_key: Auth for SID resolution
        ldap_domain/ldap_user/ldap_password/ldap_hashes: LDAP auth overrides
        pwd_cache: Pre-fetched pwdLastSet data
        tier0_cache: Pre-fetched Tier-0 membership data
        debug: Enable debug output

    Returns:
        List of ServiceRow instances for domain-account services
    """
    from ..classification import classify_service
    from ..models.service import ServiceRow
    from ..parsers.service_filter import filter_domain_services
    from ..resolver import format_runas_with_sid_resolution, is_sid
    from ..smb.svcctl import enumerate_services

    try:
        raw_services = enumerate_services(smb, host)
    except Exception as e:
        warn(f"{target}: Service enumeration failed: {e}")
        if debug:
            traceback.print_exc()
        return []

    if not raw_services:
        info(f"{target}: No Win32 services found")
        return []

    # Filter to domain accounts only
    domain_services = filter_domain_services(raw_services, local_accounts=local_accounts)

    if not domain_services:
        info(f"{target}: No services running as domain accounts")
        return []

    good(f"{target}: Found {len(domain_services)} services running as domain accounts")

    # Build ServiceRow instances with SID resolution and classification
    rows = []
    for svc in domain_services:
        row = ServiceRow.from_svcctl(
            host=host,
            svc=svc,
            target_ip=target_ip,
            computer_sid=computer_sid,
        )
        row.credential_guard = credguard_status

        account = row.start_name or ""

        # SID resolution
        if account and is_sid(account):
            resolved = format_runas_with_sid_resolution(
                account,
                hv=hv,
                bh_connector=bh_connector,
                smb_connection=None if no_rpc else smb,
                no_ldap=no_ldap,
                domain=domain,
                dc_ip=dc_ip,
                username=username,
                password=password,
                hashes=hashes,
                kerberos=kerberos,
                ldap_domain=ldap_domain,
                ldap_user=ldap_user,
                ldap_password=ldap_password,
                ldap_hashes=ldap_hashes,
            )
            if resolved and resolved != account:
                row.resolved_runas = resolved

        # Classify
        classify_service(
            row,
            account,
            hv=hv,
            pwd_cache=pwd_cache,
            tier0_cache=tier0_cache,
            resolved_account=row.resolved_runas,
        )

        rows.append(row)

    # Summary counts
    tier0_count = sum(1 for r in rows if r.type == "TIER-0")
    priv_count = sum(1 for r in rows if r.type == "PRIV")
    if tier0_count or priv_count:
        good(f"{target}: Services classified — {tier0_count} TIER-0, {priv_count} PRIV, {len(rows) - tier0_count - priv_count} SERVICE")

    return rows


def perform_lsa_service_looting(
    target: str,
    smb: Any,
    host: str,
    service_rows: List[Any],
    *,
    kerberos: bool = False,
    dc_ip: Optional[str] = None,
    debug: bool = False,
) -> List[str]:
    """
    Extract plaintext passwords from _SC_* LSA secrets for discovered services.

    Maps extracted credentials back to ServiceRow objects, populating
    decrypted_password fields.

    Args:
        target: Target identifier (for logging)
        smb: Authenticated SMB connection
        host: Server FQDN
        service_rows: List of ServiceRow instances to match credentials against
        kerberos: Kerberos auth being used
        dc_ip: DC hostname for Kerberos
        debug: Enable debug output

    Returns:
        Output lines for credential display
    """
    from ..lsa.extractor import extract_service_credentials

    out_lines: List[str] = []

    # Collect service names for targeted extraction
    service_names = {row.service_name for row in service_rows if row.service_name}

    try:
        credentials = extract_service_credentials(
            smb, host,
            service_names=service_names,
            kerberos=kerberos,
            dc_host=dc_ip,
        )
    except Exception as e:
        warn(f"{target}: LSA service credential extraction failed: {e}")
        if debug:
            traceback.print_exc()
        return out_lines

    if not credentials:
        return out_lines

    # Map credentials back to service rows
    matched = 0
    for cred in credentials:
        for row in service_rows:
            if cred.service_name and cred.service_name == row.service_name:
                row.decrypted_password = cred.password
                matched += 1
                break
            elif cred.account and row.start_name:
                # Fall back to account name matching
                cred_user = cred.account.split("\\")[-1].lower() if "\\" in cred.account else cred.account.lower()
                row_user = row.start_name.split("\\")[-1].lower() if "\\" in row.start_name else row.start_name.lower()
                if cred_user == row_user:
                    row.decrypted_password = cred.password
                    matched += 1
                    break

    if matched:
        good(f"{target}: Matched {matched} LSA credential(s) to service accounts")

    return out_lines


def sort_tasks_by_priority(lines: List[str]) -> List[str]:
    """
    Sort task blocks by priority: TIER-0 > PRIV > TASK.

    Task blocks are separated by headers like [TIER-0], [PRIV], [TASK].
    This function groups lines into blocks and sorts them by priority.

    Args:
        lines: List of output lines containing task blocks

    Returns:
        Sorted list of lines with TIER-0 tasks first, then PRIV, then TASK
    """
    if not lines:
        return lines

    # Group lines into task blocks (each block starts with a header like [TIER-0])
    blocks = []
    current_block: list[str] = []

    for line in lines:
        if line.startswith("\n[") and current_block:
            # Start of new block, save the previous one
            blocks.append(current_block)
            current_block = [line]
        else:
            current_block.append(line)

    # Don't forget the last block
    if current_block:
        blocks.append(current_block)

    # Define priority order
    def get_block_priority(block):
        if not block:
            return 3  # Unknown/default priority

        first_line = block[0]
        if "[TIER-0]" in first_line:
            return 0
        elif "[PRIV]" in first_line:
            return 1
        elif "[TASK]" in first_line:
            return 2
        else:
            return 3

    # Sort blocks by priority
    sorted_blocks = sorted(blocks, key=get_block_priority)

    # Flatten back to a single list
    result = []
    for block in sorted_blocks:
        result.extend(block)

    return result
