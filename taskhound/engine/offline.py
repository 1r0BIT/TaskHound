# Offline processing for previously collected task XML files.
#
# This module handles processing of XML files from a directory structure
# created by the --backup option, allowing offline analysis without
# network access to the target hosts.

import os
import traceback
from typing import Any

from ..classification import classify_task
from ..models.task import TaskRow
from ..output.printer import format_block
from ..parsers.highvalue import HighValueLoader
from ..parsers.task_xml import parse_task_xml
from ..utils.logging import good, info, warn
from .helpers import sort_tasks_by_priority


def process_offline_directory(
    offline_dir: str,
    hv: HighValueLoader | None,
    show_unsaved_creds: bool,
    include_local: bool,
    all_rows: list[TaskRow],
    debug: bool,
    no_ldap: bool = False,
    dpapi_key: str | None = None,
    concise: bool = False,
) -> list[str]:
    """
    Process previously collected XML files from a directory structure.

    Expected directory structure:
        offline_dir/
        ├── hostname1/
        │   └── Windows/System32/Tasks/...
        └── hostname2/
            └── Windows/System32/Tasks/...

    Args:
        offline_dir: Path to the offline directory containing host subdirectories
        hv: HighValueLoader for privilege detection
        show_unsaved_creds: Show tasks without saved credentials
        include_local: Include local system account tasks
        all_rows: List to append result rows to
        debug: Enable debug output
        no_ldap: Disable LDAP SID resolution
        dpapi_key: DPAPI key for decryption
        concise: Use concise output format

    Returns:
        List of printable output strings
    """
    out_lines: list[str] = []

    if not os.path.exists(offline_dir) or not os.path.isdir(offline_dir):
        warn(f"Offline directory does not exist or is not a directory: {offline_dir}")
        return out_lines

    # Check if offline_dir itself is a dpapi_loot structure (for direct decryption)
    has_masterkeys = os.path.exists(os.path.join(offline_dir, "masterkeys"))
    has_credentials = os.path.exists(os.path.join(offline_dir, "credentials"))
    has_tasks_dir = os.path.exists(os.path.join(offline_dir, "Windows", "System32", "Tasks"))

    # If this looks like a single-host dpapi_loot structure, process it directly
    # This handles both: with DPAPI key (decrypt creds) and without (just process tasks)
    if has_masterkeys or has_tasks_dir:
        # This is a direct dpapi_loot directory for a single host
        hostname = os.path.basename(offline_dir)
        info(f"Detected single-host backup structure for {hostname}")

        decrypted_creds: list[Any] = []
        if has_masterkeys and has_credentials and dpapi_key:
            dpapi_lines, decrypted_creds = _process_offline_dpapi_decryption(hostname, offline_dir, dpapi_key, debug)
            out_lines.extend(dpapi_lines)

        # Also process any XML files in this directory, passing decrypted creds for matching
        lines = _process_offline_host(
            hostname, offline_dir, hv, show_unsaved_creds, include_local, all_rows, debug, no_ldap, concise,
            decrypted_creds=decrypted_creds
        )
        out_lines.extend(lines)
        return out_lines

    # Look for host directories (subdirectories of offline_dir)
    try:
        host_dirs = [
            d for d in os.listdir(offline_dir) if os.path.isdir(os.path.join(offline_dir, d)) and not d.startswith(".")
        ]
    except Exception as e:
        warn(f"Failed to list offline directory {offline_dir}: {e}")
        return out_lines

    if not host_dirs:
        warn(f"No host directories found in offline directory: {offline_dir}")
        return out_lines

    total_hosts = len(host_dirs)
    good(f"Offline mode: Found {total_hosts} host directories to process")

    # Decrypt DPAPI files and collect credentials per host
    host_decrypted_creds: dict[str, list] = {}  # hostname -> decrypted_creds
    if dpapi_key:
        info("DPAPI key provided - will decrypt collected credential files")
        for host in host_dirs:
            host_path = os.path.join(offline_dir, host)
            dpapi_lines, decrypted_creds = _process_offline_dpapi_decryption(host, host_path, dpapi_key, debug)
            out_lines.extend(dpapi_lines)
            if decrypted_creds:
                host_decrypted_creds[host] = decrypted_creds

    # Process task XML files, passing decrypted creds for matching
    for host_dir in host_dirs:
        host_path = os.path.join(offline_dir, host_dir)
        lines = _process_offline_host(
            host_dir, host_path, hv, show_unsaved_creds, include_local, all_rows, debug, no_ldap, concise,
            decrypted_creds=host_decrypted_creds.get(host_dir, [])
        )
        out_lines.extend(lines)

    return out_lines


def _process_offline_dpapi_decryption(hostname: str, host_dir: str, dpapi_key: str, debug: bool) -> tuple[list[str], list]:
    """
    Process DPAPI files from offline collection.

    Checks multiple directory structures for DPAPI loot:
    1. Direct dpapi_loot structure (host_dir/masterkeys/)
    2. Combined --backup --loot structure (host_dir/dpapi_loot/)
    3. Legacy structure (host_dir/dpapi_loot/hostname/)

    Args:
        hostname: The hostname being processed
        host_dir: Path to the host's directory
        dpapi_key: DPAPI SYSTEM userkey for decryption
        debug: Enable debug output

    Returns:
        Tuple of (out_lines, decrypted_creds) where:
        - out_lines: List of printable output strings
        - decrypted_creds: List of ScheduledTaskCredential objects for task matching
    """
    out_lines: list[str] = []
    decrypted_creds: list = []

    # Check if this directory has dpapi_loot structure
    # Priority order:
    # 1. Check if current directory has masterkeys/ (direct dpapi_loot structure)
    # 2. Check for dpapi_loot/ subdirectory (--backup --loot combined structure)
    # 3. Check for dpapi_loot/hostname subdirectory (legacy structure)

    dpapi_loot_dir = None

    if os.path.exists(os.path.join(host_dir, "masterkeys")):
        # Direct dpapi_loot structure
        dpapi_loot_dir = host_dir
    elif os.path.exists(os.path.join(host_dir, "dpapi_loot", "masterkeys")):
        # Combined --backup --loot structure: backup_dir/hostname/dpapi_loot/
        dpapi_loot_dir = os.path.join(host_dir, "dpapi_loot")
    elif os.path.exists(os.path.join(host_dir, "dpapi_loot", hostname, "masterkeys")):
        # Legacy structure: dpapi_loot/hostname/
        dpapi_loot_dir = os.path.join(host_dir, "dpapi_loot", hostname)

    if not dpapi_loot_dir:
        # No DPAPI files found for this host
        return out_lines, decrypted_creds

    try:
        from ..dpapi.looter import decrypt_offline_dpapi_files

        info(f"{hostname}: Decrypting DPAPI files from offline collection...")
        decrypted_creds = decrypt_offline_dpapi_files(dpapi_loot_dir, dpapi_key)

        if decrypted_creds:
            good(f"{hostname}: Successfully decrypted {len(decrypted_creds)} Task Scheduler credentials!")
            out_lines.append("")
            out_lines.append(f"{'=' * 80}")
            out_lines.append(f"DECRYPTED CREDENTIALS FROM OFFLINE DPAPI FILES - {hostname}")
            out_lines.append(f"{'=' * 80}")
            out_lines.append("")
            out_lines.append("NOTE: Task GUIDs from credential TargetName field:")
            out_lines.append("      Domain:batch=TaskScheduler:Task:{GUID}")
            out_lines.append("      If task is deleted, credential blob persists (orphaned credential)")
            out_lines.append("")

            for cred in decrypted_creds:
                out_lines.append("")
                out_lines.append(f"Task Name    : {cred.task_name or '(Unknown - see Task GUID)'}")
                out_lines.append(f"Task GUID    : {cred.target}")
                out_lines.append(f"Username     : {cred.username}")
                out_lines.append(f"Password     : {cred.password}")
                out_lines.append(f"Blob File    : {cred.blob_path}")
                out_lines.append(f"{'-' * 80}")

            out_lines.append(f"{'=' * 80}")
            out_lines.append("")
        else:
            info(f"{hostname}: No credentials decrypted from offline files")

    except Exception as e:
        warn(f"{hostname}: Failed to decrypt offline DPAPI files: {e}")
        if debug:
            traceback.print_exc()

    return out_lines, decrypted_creds


def _process_offline_host(
    hostname: str,
    host_dir: str,
    hv: HighValueLoader | None,
    show_unsaved_creds: bool,
    include_local: bool,
    all_rows: list[TaskRow],
    debug: bool,
    no_ldap: bool = False,
    concise: bool = False,
    decrypted_creds: list | None = None,
) -> list[str]:
    """
    Process XML files for a single host from offline directory.

    Args:
        hostname: The hostname being processed
        host_dir: Path to the host's directory
        hv: HighValueLoader for privilege detection
        show_unsaved_creds: Show tasks without saved credentials
        include_local: Include local system account tasks
        all_rows: List to append result rows to
        debug: Enable debug output
        no_ldap: Disable LDAP SID resolution
        concise: Use concise output format
        decrypted_creds: List of decrypted credentials to match with tasks

    Returns:
        List of printable output strings
    """
    # Import the credential matching function from online module
    from .online import _match_decrypted_password

    out_lines: list[str] = []
    xml_files = []

    # Walk the host directory to find all XML files
    for root, _, files in os.walk(host_dir):
        for file in files:
            # Skip system files that start with dot
            if file.startswith("."):
                continue

            file_path = os.path.join(root, file)
            # Convert absolute path back to relative path from host directory
            rel_path = os.path.relpath(file_path, host_dir)
            # Convert to Windows-style path for consistency with online mode
            rel_path = rel_path.replace(os.sep, "\\")
            xml_files.append((rel_path, file_path))

    if not xml_files:
        warn(f"{hostname}: No XML files found in offline directory")
        return out_lines

    good(f"{hostname}: Processing {len(xml_files)} XML files from offline directory")

    priv_count = 0
    priv_lines: list[str] = []
    task_lines: list[str] = []

    for rel_path, file_path in xml_files:
        try:
            with open(file_path, "rb") as f:
                xml_bytes = f.read()
        except Exception as e:
            if debug:
                warn(f"{hostname}: Failed to read {file_path}: {e}")
            continue

        meta = parse_task_xml(xml_bytes)
        runas = meta.get("runas")
        if not runas:
            # If we can't determine who the task runs as, skip it for now
            continue

        what = meta.get("command") or ""
        if meta.get("arguments"):
            what = f"{what} {meta.get('arguments')}"

        # For offline processing, target_ip is not applicable (already offline)
        row = TaskRow.from_meta(hostname, rel_path, meta, target_ip=None)

        # Determine if the task stores credentials or runs with token/S4U (no saved credentials)
        logon_type = (meta.get("logon_type") or "").strip()
        no_saved_creds = (not logon_type) or logon_type.lower() in (
            "interactivetoken",
            "s4u",
            "interactivetokenorpassword",
        )
        if no_saved_creds:
            row.credentials_hint = "no_saved_credentials"

        # Use shared classification logic
        # Note: pwd_cache is None for offline mode since we can't query LDAP
        result = classify_task(
            row=row,
            meta=meta,
            runas=runas,
            rel_path=rel_path,
            hv=hv,
            show_unsaved_creds=show_unsaved_creds,
            include_local=include_local,
            pwd_cache=None,  # No LDAP in offline mode
        )

        if not result.should_include:
            continue

        # Update row with classification results (like online mode does)
        row.type = result.task_type
        row.reason = result.reason
        row.password_analysis = result.password_analysis

        # Match decrypted credentials to this task (if we have any)
        if decrypted_creds and runas:
            matched_password = _match_decrypted_password(runas, decrypted_creds, row.resolved_runas)
            if matched_password:
                row.decrypted_password = matched_password

        # Get cache for gMSA detection
        from ..utils.cache_manager import get_cache
        cache = get_cache()

        # Format output block based on classification
        if result.task_type in ("TIER-0", "PRIV"):
            priv_lines.extend(
                format_block(
                    result.task_type,
                    rel_path,
                    runas,
                    what,
                    meta.get("author") or "",
                    meta.get("date") or "",
                    extra_reason=result.reason,
                    password_analysis=result.password_analysis,
                    hv=hv,
                    no_ldap=no_ldap,
                    dc_ip=None,
                    hostname=hostname,
                    enabled=meta.get("enabled"),
                    ldap_domain=None,
                    ldap_user=None,
                    ldap_password=None,
                    meta=meta,
                    concise=concise,
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
                    meta.get("author") or "",
                    meta.get("date") or "",
                    password_analysis=result.password_analysis,
                    hv=hv,
                    no_ldap=no_ldap,
                    dc_ip=None,
                    hostname=hostname,
                    enabled=meta.get("enabled"),
                    ldap_domain=None,
                    ldap_user=None,
                    ldap_password=None,
                    meta=meta,
                    concise=concise,
                    cache_manager=cache,
                )
            )

        all_rows.append(row)

    lines = priv_lines + task_lines
    # Sort tasks by priority: TIER-0 > PRIV > TASK
    sorted_lines = sort_tasks_by_priority(lines)
    total = len(xml_files)
    good(f"{hostname}: Found {total} tasks, privileged {priv_count if (hv and hv.loaded) else 'N/A'}")
    return sorted_lines
