# Core processing for a single target host.
#
# This module ties together SMB connection, task enumeration, XML parsing,
# and high-value enrichment. The main entry point `process_target` returns
# a list of printable strings suitable for the CLI while also appending
# structured rows to `all_rows` for export.

import os
import traceback
from typing import Dict, List, Optional

from impacket.smbconnection import SessionError

from .parsers.highvalue import HighValueLoader
from .parsers.task_xml import parse_task_xml
from .smb.connection import smb_connect
from .smb.credguard import check_credential_guard
from .smb.tasks import crawl_tasks, smb_listdir
from .utils.helpers import looks_like_domain_user
from .utils.logging import good, info, warn
from .utils.sid_resolver import format_runas_with_sid_resolution


def process_offline_directory(offline_dir: str, hv: Optional[HighValueLoader],
                             show_unsaved_creds: bool, include_local: bool, all_rows: List[Dict], debug: bool,
                             no_ldap: bool = False, dpapi_key: Optional[str] = None) -> List[str]:
    # Process previously collected XML files from a directory structure.
    #
    # Expected directory structure:
    #   offline_dir/
    #   ├── hostname1/
    #   │   └── Windows/System32/Tasks/...
    #   └── hostname2/
    #       └── Windows/System32/Tasks/...
    #
    # Returns printable lines and populates all_rows for export.
    out_lines: List[str] = []

    if not os.path.exists(offline_dir) or not os.path.isdir(offline_dir):
        warn(f"Offline directory does not exist or is not a directory: {offline_dir}")
        return out_lines

    # Check if offline_dir itself is a dpapi_loot structure (for direct decryption)
    has_masterkeys = os.path.exists(os.path.join(offline_dir, "masterkeys"))
    has_credentials = os.path.exists(os.path.join(offline_dir, "credentials"))

    if has_masterkeys and has_credentials and dpapi_key:
        # This is a direct dpapi_loot directory, process it directly
        hostname = os.path.basename(offline_dir)
        info(f"Detected DPAPI loot directory structure for {hostname}")
        dpapi_lines = _process_offline_dpapi_decryption(hostname, offline_dir, dpapi_key, debug)
        out_lines.extend(dpapi_lines)

        # Also process any XML files in this directory
        lines = _process_offline_host(hostname, offline_dir, hv, show_unsaved_creds, include_local, all_rows, debug, no_ldap)
        out_lines.extend(lines)
        return out_lines

    # Look for host directories (subdirectories of offline_dir)
    try:
        host_dirs = [d for d in os.listdir(offline_dir)
                    if os.path.isdir(os.path.join(offline_dir, d))
                    and not d.startswith('.')]
    except Exception as e:
        warn(f"Failed to list offline directory {offline_dir}: {e}")
        return out_lines

    if not host_dirs:
        warn(f"No host directories found in offline directory: {offline_dir}")
        return out_lines

    total_hosts = len(host_dirs)
    good(f"Offline mode: Found {total_hosts} host directories to process")

    # If dpapi_key provided, decrypt collected DPAPI files first
    if dpapi_key:
        info("DPAPI key provided - will decrypt collected credential files")
        for host in host_dirs:
            host_path = os.path.join(offline_dir, host)
            dpapi_lines = _process_offline_dpapi_decryption(host, host_path, dpapi_key, debug)
            out_lines.extend(dpapi_lines)

    # Process task XML files
    for host in host_dirs:
        host_path = os.path.join(offline_dir, host)
        lines = _process_offline_host(host, host_path, hv, show_unsaved_creds, include_local, all_rows, debug, no_ldap)
        out_lines.extend(lines)

    return out_lines


def _process_offline_dpapi_decryption(hostname: str, host_dir: str, dpapi_key: str, debug: bool) -> List[str]:
    """Process DPAPI files from offline collection"""
    out_lines: List[str] = []

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
        return out_lines

    try:
        from .dpapi.looter import decrypt_offline_dpapi_files

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

    return out_lines



def _process_offline_host(hostname: str, host_dir: str, hv: Optional[HighValueLoader],
                         show_unsaved_creds: bool, include_local: bool, all_rows: List[Dict], debug: bool,
                         no_ldap: bool = False) -> List[str]:
    # Process XML files for a single host from offline directory
    out_lines: List[str] = []
    xml_files = []

    # Walk the host directory to find all XML files
    for root, dirs, files in os.walk(host_dir):
        for file in files:
            # Skip system files that start with dot
            if file.startswith('.'):
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
    priv_lines: List[str] = []
    task_lines: List[str] = []

    for rel_path, file_path in xml_files:
        try:
            with open(file_path, 'rb') as f:
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
        row = _build_row(hostname, rel_path, meta, target_ip=None)

        # Determine if the task stores credentials or runs with token/S4U (no stored credentials)
        logon_type = (meta.get("logon_type") or "").strip()
        no_saved_creds = (not logon_type) or logon_type.lower() in ("interactivetoken", "s4u", "interactivetokenorpassword")
        if no_saved_creds:
            row["credentials_hint"] = "no_saved_credentials"

        # Check for Tier 0 first, then high-value
        classified = False
        if hv and hv.loaded:
            # Check Tier 0 classification
            is_tier0, tier0_reasons = hv.check_tier0(runas)
            if is_tier0:
                # Tier 0 match - analyze password age if credentials are stored
                reason = '; '.join(tier0_reasons)
                password_analysis = None

                if row.get("credentials_hint") == "no_saved_credentials":
                    reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
                else:
                    # Analyze password age for DPAPI dump viability
                    risk_level, pwd_analysis = hv.analyze_password_age(runas, meta.get("date"))
                    if risk_level != "UNKNOWN":
                        password_analysis = pwd_analysis

                # Only include tasks that store credentials (or show_unsaved_creds is True)
                if not (row.get("credentials_hint") == "no_saved_credentials" and not show_unsaved_creds):
                    priv_lines.extend(_format_block("TIER-0", rel_path, runas, what, meta.get("author"), meta.get("date"),
                                                   extra_reason=reason, password_analysis=password_analysis,
                                                   hv=hv, no_ldap=no_ldap, dc_ip=None, enabled=meta.get("enabled"), ldap_domain=None, ldap_user=None, ldap_password=None, meta=meta))
                    priv_count += 1
                    row["type"] = "TIER-0"
                    row["reason"] = reason
                    row["password_analysis"] = password_analysis
                classified = True
            elif hv.check_highvalue(runas):
                # High-value match — mark as privileged if credentials are stored (or show unsaved creds)
                reason = "High Value match found (Check BloodHound Outbound Object Control for Details)"
                password_analysis = None

                if row.get("credentials_hint") == "no_saved_credentials":
                    reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
                else:
                    # Analyze password age for DPAPI dump viability
                    risk_level, pwd_analysis = hv.analyze_password_age(runas, meta.get("date"))
                    if risk_level != "UNKNOWN":
                        password_analysis = pwd_analysis

                # Only include tasks that store credentials (or show_unsaved_creds is True)
                if not (row.get("credentials_hint") == "no_saved_credentials" and not show_unsaved_creds):
                    priv_lines.extend(_format_block("PRIV", rel_path, runas, what, meta.get("author"), meta.get("date"),
                                                   extra_reason=reason, password_analysis=password_analysis,
                                                   hv=hv, no_ldap=no_ldap, dc_ip=None, enabled=meta.get("enabled"), ldap_domain=None, ldap_user=None, ldap_password=None, meta=meta))
                    priv_count += 1
                    row["type"] = "PRIV"
                    row["reason"] = reason
                    row["password_analysis"] = password_analysis
                classified = True

        if not classified:
            # Regular tasks - still analyze password age if credentials are stored and BloodHound data available
            password_analysis = None
            if hv and hv.loaded and row.get("credentials_hint") == "stored_credentials":
                # Analyze password age even for non-privileged accounts
                risk_level, pwd_analysis = hv.analyze_password_age(runas, meta.get("date"))
                if risk_level != "UNKNOWN":
                    password_analysis = pwd_analysis

            # Only print TASK entries for domain users OR users with stored credentials OR local accounts (if requested),
            # unless they are explicitly marked as having no saved credentials (and user didn't ask to see them)
            should_include_task = (looks_like_domain_user(runas) or
                                 row.get("credentials_hint") == "stored_credentials" or
                                 (include_local and not looks_like_domain_user(runas)))
            if should_include_task:
                if not (row.get("credentials_hint") == "no_saved_credentials" and not show_unsaved_creds):
                    task_lines.extend(_format_block("TASK", rel_path, runas, what, meta.get("author"), meta.get("date"),
                                                   password_analysis=password_analysis, hv=hv, no_ldap=no_ldap, dc_ip=None,
                                                   enabled=meta.get("enabled"), ldap_domain=None, ldap_user=None, ldap_password=None, meta=meta))
            row["password_analysis"] = password_analysis

        # By default omit tasks that explicitly have no saved credentials unless the user asked to show them
        if not (row.get("credentials_hint") == "no_saved_credentials" and not show_unsaved_creds):
            all_rows.append(row)

    lines = priv_lines + task_lines
    # Sort tasks by priority: TIER-0 > PRIV > TASK
    sorted_lines = _sort_tasks_by_priority(lines)
    total = len(xml_files)
    good(f"{hostname}: Found {total} tasks, privileged {priv_count if (hv and hv.loaded) else 'N/A'}")
    return sorted_lines


def _sort_tasks_by_priority(lines: List[str]) -> List[str]:
    """Sort task blocks by priority: TIER-0 > PRIV > TASK"""
    if not lines:
        return lines

    # Group lines into task blocks (each block starts with a header like [TIER-0])
    blocks = []
    current_block = []

    for line in lines:
        if line.startswith('\n[') and current_block:
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
        if '[TIER-0]' in first_line:
            return 0
        elif '[PRIV]' in first_line:
            return 1
        elif '[TASK]' in first_line:
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


def _build_row(host: str, rel_path: str, meta: Dict[str, str], 
               target_ip: Optional[str] = None) -> Dict[str, Optional[str]]:
    # Create a structured dict for CSV/JSON export representing a task.
    #
    # Keeps the same keys used by the writer so rows can be dumped directly.
    # Now includes both FQDN (host) and IP address (target_ip) for flexibility.

    # Determine credentials hint based on logon type
    logon_type_raw = meta.get("logon_type")
    logon_type = logon_type_raw.strip().lower() if logon_type_raw else ""
    if logon_type == "password":
        credentials_hint = "stored_credentials"
    elif logon_type in ("interactive", "interactivetoken", "s4u"):
        credentials_hint = "no_saved_credentials"
    else:
        credentials_hint = None

    return {
        "host": host,
        "target_ip": target_ip,  # Store the original target (IP or hostname)
        "path": rel_path,
        "type": "TASK",
        "runas": meta.get("runas"),
        "command": meta.get("command"),
        "arguments": meta.get("arguments"),
        "author": meta.get("author"),
        "date": meta.get("date"),
        "logon_type": meta.get("logon_type"),
        "enabled": meta.get("enabled"),
        "trigger_type": meta.get("trigger_type"),
        "start_boundary": meta.get("start_boundary"),
        "interval": meta.get("interval"),
        "duration": meta.get("duration"),
        "days_interval": meta.get("days_interval"),
        "reason": None,
        "credentials_hint": credentials_hint,
    }


def _format_trigger_info(meta: Dict[str, str]) -> Optional[str]:
    """Format trigger information for display"""
    trigger_type = meta.get("trigger_type")
    if not trigger_type:
        return None

    trigger_parts = [trigger_type]

    if trigger_type == "Calendar":
        # Format calendar trigger details
        start_boundary = meta.get("start_boundary")
        interval = meta.get("interval")
        duration = meta.get("duration")
        days_interval = meta.get("days_interval")

        details = []
        if start_boundary:
            # Parse the start boundary for better display
            try:
                from datetime import datetime
                # Handle both with and without timezone
                if 'T' in start_boundary:
                    if start_boundary.endswith('Z'):
                        dt = datetime.fromisoformat(start_boundary[:-1])
                    elif '+' in start_boundary or start_boundary.count('-') > 2:
                        # Has timezone, try to parse
                        dt = datetime.fromisoformat(start_boundary.replace('Z', '+00:00'))
                    else:
                        dt = datetime.fromisoformat(start_boundary)
                    details.append(f"starts {dt.strftime('%Y-%m-%d %H:%M')}")
                else:
                    details.append(f"starts {start_boundary}")
            except Exception:
                if start_boundary:
                    details.append(f"starts {start_boundary}")

        if interval:
            # Parse ISO 8601 duration format (PT5M = 5 minutes)
            interval_display = interval
            if interval.startswith('PT'):
                interval_clean = interval[2:]  # Remove 'PT' prefix
                if interval_clean.endswith('M'):
                    minutes = interval_clean[:-1]
                    interval_display = f"{minutes} minutes"
                elif interval_clean.endswith('H'):
                    hours = interval_clean[:-1]
                    interval_display = f"{hours} hours"
                elif interval_clean.endswith('S'):
                    seconds = interval_clean[:-1]
                    interval_display = f"{seconds} seconds"
            details.append(f"every {interval_display}")

        if duration:
            # Parse ISO 8601 duration format (P1D = 1 day)
            duration_display = duration
            if duration.startswith('P'):
                duration_clean = duration[1:]  # Remove 'P' prefix
                if duration_clean.endswith('D'):
                    days = duration_clean[:-1]
                    duration_display = f"{days} day{'s' if days != '1' else ''}"
                elif 'T' in duration_clean:
                    # Has time component
                    duration_display = duration  # Keep original for complex durations
            details.append(f"for {duration_display}")

        if days_interval:
            if days_interval == "1":
                details.append("daily")
            else:
                details.append(f"every {days_interval} days")

        if details:
            trigger_parts.append(f"({', '.join(details)})")

    elif trigger_type == "Time":
        start_boundary = meta.get("start_boundary")
        if start_boundary:
            try:
                from datetime import datetime
                if 'T' in start_boundary:
                    dt = datetime.fromisoformat(start_boundary.replace('Z', '+00:00') if start_boundary.endswith('Z') else start_boundary)
                    trigger_parts.append(f"at {dt.strftime('%Y-%m-%d %H:%M')}")
                else:
                    trigger_parts.append(f"at {start_boundary}")
            except Exception:
                trigger_parts.append(f"at {start_boundary}")

    return " ".join(trigger_parts) if len(trigger_parts) > 1 else trigger_type


def _format_block(kind: str, rel_path: str, runas: str, what: str, author: str, date: str,
                  extra_reason: Optional[str] = None, password_analysis: Optional[str] = None,
                  hv: Optional[HighValueLoader] = None, no_ldap: bool = False,
                  domain: Optional[str] = None, dc_ip: Optional[str] = None, username: Optional[str] = None,
                  password: Optional[str] = None, hashes: Optional[str] = None,
                  enabled: Optional[str] = None, ldap_domain: Optional[str] = None, ldap_user: Optional[str] = None,
                  ldap_password: Optional[str] = None, meta: Optional[Dict[str, str]] = None,
                  decrypted_creds: Optional[List] = None) -> List[str]:
    # Format a small pretty-print block used by the CLI output.
    #
    # kind is either 'TIER-0', 'PRIV' (privileged/high-value) or 'TASK' (normal task).
    if kind == "TIER-0":
        header = "[TIER-0]"
    elif kind == "PRIV":
        header = "[PRIV]"
    else:
        header = "[TASK]"

    # Resolve SID in RunAs field for better display
    display_runas, resolved_username = format_runas_with_sid_resolution(
        runas, hv, no_ldap, domain, dc_ip, username, password, hashes, False, ldap_domain, ldap_user, ldap_password
    )

    base = [f"\n{header} {rel_path}"]

    # Add task state information as first field
    if enabled is not None:
        enabled_display = enabled.capitalize() if enabled.lower() in ['true', 'false'] else enabled
        base.append(f"        Enabled : {enabled_display}")

    # Add other task information with proper alignment
    base.extend([f"        RunAs   : {display_runas}", f"        What    : {what}"])
    if author:
        base.append(f"        Author  : {author}")
    if date:
        base.append(f"        Date    : {date}")

    # Add trigger information if available
    if meta:
        trigger_info = _format_trigger_info(meta)
        if trigger_info:
            base.append(f"        Trigger : {trigger_info}")

    if kind in ["TIER-0", "PRIV"]:
        if extra_reason:
            base.append(f"        Reason  : {extra_reason}")
        elif kind == "TIER-0":
            base.append("        Reason  : Tier 0 privileged group membership")
        else:
            base.append("        Reason  : High Value match found (Check BloodHound Outbound Object Control for Details)")

        # Add password analysis if available
        if password_analysis:
            base.append(f"        Password Analysis : {password_analysis}")

        # Check if we have a decrypted password for this user
        decrypted_password = None
        if decrypted_creds:
            # Normalize the runas for comparison
            runas_normalized = runas.lower()
            for cred in decrypted_creds:
                if cred.username:
                    cred_user_normalized = cred.username.lower()
                    # Match full domain\user or partial matches
                    if cred_user_normalized == runas_normalized:
                        # Exact match
                        decrypted_password = cred.password
                        break
                    elif '\\' in cred_user_normalized and '\\' not in runas_normalized:
                        # Cred has domain, runas doesn't - match on username part only
                        if cred_user_normalized.split('\\')[-1] == runas_normalized:
                            decrypted_password = cred.password
                            break
                    # Note: We DON'T match when runas has domain but cred doesn't
                    # A credential without domain is likely a local account, not domain account

        # Show decrypted password if available, otherwise show next step
        if decrypted_password:
            base.append(f"        Decrypted Password : {decrypted_password}")
        elif (not extra_reason or "no saved credentials" not in extra_reason.lower()):
            base.append("        Next Step: Try DPAPI Dump / Task Manipulation")

    # Add password analysis for regular TASK entries too (if available)
    elif kind == "TASK":
        if password_analysis:
            base.append(f"        Password Analysis : {password_analysis}")

        # Check if we have a decrypted password for this user
        decrypted_password = None
        if decrypted_creds:
            runas_normalized = runas.lower()
            for cred in decrypted_creds:
                if cred.username:
                    cred_user_normalized = cred.username.lower()
                    # Match full domain\user or partial matches
                    if cred_user_normalized == runas_normalized:
                        # Exact match
                        decrypted_password = cred.password
                        break
                    elif '\\' in cred_user_normalized and '\\' not in runas_normalized:
                        # Cred has domain, runas doesn't - match on username part only
                        if cred_user_normalized.split('\\')[-1] == runas_normalized:
                            decrypted_password = cred.password
                            break
                    # Note: We DON'T match when runas has domain but cred doesn't
                    # A credential without domain is likely a local account, not domain account

        # Show decrypted password if available, otherwise show next step (if password_analysis exists)
        if decrypted_password:
            base.append(f"        Decrypted Password : {decrypted_password}")
        elif password_analysis:
            base.append("        Next Step: Try DPAPI Dump / Task Manipulation")

    return base


def process_target(target: str, domain: str, username: str, password: Optional[str],
                   kerberos: bool, dc_ip: Optional[str], include_ms: bool, include_local: bool,
                   hv: Optional[HighValueLoader], debug: bool,
                   all_rows: List[Dict], hashes: Optional[str] = None,
                   show_unsaved_creds: bool = False, backup_dir: Optional[str] = None,
                   credguard_detect: bool = False, no_ldap: bool = False,
                   ldap_domain: Optional[str] = None, ldap_user: Optional[str] = None,
                   ldap_password: Optional[str] = None,
                   loot: bool = False, dpapi_key: Optional[str] = None) -> List[str]:
    # Connect to `target`, enumerate scheduled tasks, and return printable lines.
    #
    # TEMPORARY DEBUG: Show what credentials were received

    # - Attempts SMB authentication using either cleartext password or hashes.
    # - Performs a quick check to see if the C$ share and Tasks folder are
    #   accessible (this serves as a proxy for local admin rights).
    # - Crawls tasks, parses each XML, and marks rows as PRIV when they match
    #   the HighValue dataset and store credentials.
    #
    # The function is defensive: individual failures are logged and cause
    # the function to continue where reasonable rather than raising.

    out_lines: List[str] = []

    credguard_status = None
    server_fqdn = None  # Will store the resolved FQDN from SMB
    try:
        # Prefer explicit hashes parameter over password when provided
        smb = smb_connect(target, domain, username, hashes or password, kerberos=kerberos, dc_ip=dc_ip)
        good(f"{target}: Connected via SMB")
        
        # Resolve the actual FQDN from SMB connection
        # This is critical when target is an IP address - BloodHound needs FQDNs
        # Tries: 1) SMB hostname, 2) DNS via DC, 3) System DNS
        from .smb.connection import get_server_fqdn
        server_fqdn = get_server_fqdn(smb, target_ip=target, dc_ip=dc_ip)
        if server_fqdn and server_fqdn != "UNKNOWN_HOST":
            if server_fqdn.upper() != target.upper():
                info(f"{target}: Resolved FQDN: {server_fqdn}")
        else:
            warn(f"{target}: Could not resolve FQDN - using target as-is")
            server_fqdn = target
        
        # Credential Guard detection (EXPERIMENTAL, only if enabled)
        if credguard_detect:
            credguard_status = check_credential_guard(smb, target)
            if credguard_status:
                info(f"{target}: Credential Guard detected (LsaCfgFlags/IsolatedUserMode)")
            else:
                info(f"{target}: Credential Guard not detected")
    except Exception as e:
        if debug:
            traceback.print_exc()
        msg = str(e)
        if "STATUS_MORE_PROCESSING_REQUIRED" in msg:
            warn(f"{target}: Kerberos auth failed (SPN not found?). Try using FQDNs or switch to NTLM (-k off).")
        else:
            warn(f"{target}: SMB connection failed: {e}")
        return out_lines

    # Quick local admin presence check
    try:
        _ = smb_listdir(smb, "C$", r"\Windows\System32\Tasks")
        good(f"{target}: Local Admin Access confirmed")
    except Exception:
        if debug:
            traceback.print_exc()
        warn(f"{target}: Local admin check failed")

    if not include_ms:
        info(f"{target}: Crawling Scheduled Tasks (skipping \\Microsoft for speed)")
    else:
        warn(f"{target}: Crawling ALL Scheduled Tasks, including \\Microsoft (this may be slow!)")

    try:
        items = crawl_tasks(smb, include_ms=include_ms)
    except SessionError:
        if debug:
            traceback.print_exc()
        warn(f"{target}: Failed to Crawl Tasks. Skipping... (Are you Local Admin?)")
        return out_lines
    except Exception as e:
        if debug:
            traceback.print_exc()
        warn(f"{target}: Unexpected error while crawling tasks: {e}")
        return out_lines

    # Create backup directory structure if backup is requested
    backup_target_dir = None
    if backup_dir:
        backup_target_dir = os.path.join(backup_dir, target)
        try:
            os.makedirs(backup_target_dir, exist_ok=True)
            good(f"{target}: Raw XML backup enabled - saving to {backup_target_dir}")
        except Exception as e:
            warn(f"{target}: Failed to create backup directory {backup_target_dir}: {e}")
            backup_target_dir = None

    # Perform automatic credential looting if requested
    decrypted_creds = []  # Initialize to empty list
    if loot:
        if dpapi_key:
            # Mode 1: Live decryption with DPAPI key
            try:
                from .dpapi.looter import loot_credentials
                info(f"{target}: Starting DPAPI credential looting...")
                decrypted_creds = loot_credentials(smb, dpapi_key)

                if decrypted_creds:
                    good(f"{target}: Successfully decrypted {len(decrypted_creds)} Task Scheduler credentials!")
                    # Credentials will be displayed inline with tasks below
                else:
                    info(f"{target}: No credentials decrypted (no matching masterkeys or no credential blobs found)")

            except Exception as e:
                warn(f"{target}: DPAPI credential looting failed: {e}")
                if debug:
                    traceback.print_exc()

        else:
            # Mode 2: Offline collection without DPAPI key
            try:
                from .dpapi.looter import collect_dpapi_files

                # Create loot directory structure
                # If --backup is specified, nest DPAPI files inside backup directory
                if backup_target_dir:
                    loot_target_dir = os.path.join(backup_target_dir, "dpapi_loot")
                else:
                    loot_base_dir = "dpapi_loot"
                    loot_target_dir = os.path.join(loot_base_dir, target)

                os.makedirs(loot_target_dir, exist_ok=True)

                info(f"{target}: Collecting DPAPI files for offline decryption...")
                info(f"{target}: Saving to: {loot_target_dir}")

                stats = collect_dpapi_files(smb, loot_target_dir)

                good(f"{target}: Collected {stats['masterkeys']} masterkeys and {stats['credentials']} credential blobs")

                out_lines.append("")
                out_lines.append(f"{'=' * 80}")
                out_lines.append("DPAPI FILES COLLECTED FOR OFFLINE DECRYPTION")
                out_lines.append(f"{'=' * 80}")
                out_lines.append("")
                out_lines.append(f"Output Directory : {loot_target_dir}")
                out_lines.append(f"Masterkeys       : {stats['masterkeys']} files (in masterkeys/)")
                out_lines.append(f"Credential Blobs : {stats['credentials']} files (in credentials/)")
                out_lines.append("")
                out_lines.append("NEXT STEPS:")
                out_lines.append("  1. Obtain DPAPI_SYSTEM userkey:")
                out_lines.append(f"     nxc smb {target} -u <user> -p <pass> --lsa")
                out_lines.append("")
                out_lines.append("  2. Decrypt with the userkey:")
                out_lines.append(f"     taskhound -t {target} -u <user> -p <pass> \\")
                out_lines.append("              --loot --dpapi-key <dpapi_userkey>")
                out_lines.append("")
                out_lines.append(f"See {os.path.join(loot_target_dir, 'README.txt')} for detailed instructions")
                out_lines.append(f"{'=' * 80}")
                out_lines.append("")

            except Exception as e:
                warn(f"{target}: DPAPI file collection failed: {e}")
                if debug:
                    traceback.print_exc()

    total = len(items)
    priv_count = 0
    priv_lines: List[str] = []
    task_lines: List[str] = []


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
        row = _build_row(hostname, rel_path, meta, target_ip=target)
        
        # Add Credential Guard status to each row
        row["credential_guard"] = credguard_status
        # Determine if the task stores credentials or runs with token/S4U (no stored credentials)
        logon_type = (meta.get("logon_type") or "").strip()
        no_saved_creds = (not logon_type) or logon_type.lower() in ("interactivetoken", "s4u", "interactivetokenorpassword")
        if no_saved_creds:
            row["credentials_hint"] = "no_saved_credentials"
        elif logon_type.lower() == "password":
            row["credentials_hint"] = "stored_credentials"

        # Check for Tier 0 first, then high-value
        classified = False
        if hv and hv.loaded:
            # Check Tier 0 classification
            is_tier0, tier0_reasons = hv.check_tier0(runas)
            if is_tier0:
                # Tier 0 match - analyze password age if credentials are stored
                reason = '; '.join(tier0_reasons)
                password_analysis = None

                if row.get("credentials_hint") == "no_saved_credentials":
                    reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
                else:
                    # Analyze password age for DPAPI dump viability
                    risk_level, pwd_analysis = hv.analyze_password_age(runas, meta.get("date"))
                    if risk_level != "UNKNOWN":
                        password_analysis = pwd_analysis

                if not (row.get("credentials_hint") == "no_saved_credentials" and not show_unsaved_creds):
                    priv_lines.extend(_format_block("TIER-0", rel_path, runas, what, meta.get("author"), meta.get("date"),
                                                   extra_reason=reason, password_analysis=password_analysis,
                                                   hv=hv, no_ldap=no_ldap, domain=domain, dc_ip=dc_ip, username=username,
                                                   password=password, hashes=hashes, enabled=meta.get("enabled"),
                                                   ldap_domain=ldap_domain, ldap_user=ldap_user, ldap_password=ldap_password,
                                                   meta=meta, decrypted_creds=decrypted_creds))
                    priv_count += 1
                    row["type"] = "TIER-0"
                    row["reason"] = reason
                    row["password_analysis"] = password_analysis
                classified = True
            elif hv.check_highvalue(runas):
                reason = "High Value match found (Check BloodHound Outbound Object Control for Details)"
                password_analysis = None

                if row.get("credentials_hint") == "no_saved_credentials":
                    reason = f"{reason} (no saved credentials — DPAPI dump not applicable; manipulation requires an interactive session)"
                else:
                    # Analyze password age for DPAPI dump viability
                    risk_level, pwd_analysis = hv.analyze_password_age(runas, meta.get("date"))
                    if risk_level != "UNKNOWN":
                        password_analysis = pwd_analysis

                if not (row.get("credentials_hint") == "no_saved_credentials" and not show_unsaved_creds):
                    priv_lines.extend(_format_block("PRIV", rel_path, runas, what, meta.get("author"), meta.get("date"),
                                                   extra_reason=reason, password_analysis=password_analysis,
                                                   hv=hv, no_ldap=no_ldap, domain=domain, dc_ip=dc_ip, username=username,
                                                   password=password, hashes=hashes, enabled=meta.get("enabled"),
                                                   ldap_domain=ldap_domain, ldap_user=ldap_user, ldap_password=ldap_password,
                                                   meta=meta, decrypted_creds=decrypted_creds))
                    priv_count += 1
                    row["type"] = "PRIV"
                    row["reason"] = reason
                    row["password_analysis"] = password_analysis
                classified = True

        if not classified:
            # Regular tasks - still analyze password age if credentials are stored and BloodHound data available
            password_analysis = None
            if hv and hv.loaded and row.get("credentials_hint") == "stored_credentials":
                # Analyze password age even for non-privileged accounts
                risk_level, pwd_analysis = hv.analyze_password_age(runas, meta.get("date"))
                if risk_level != "UNKNOWN":
                    password_analysis = pwd_analysis

            # Show tasks for domain users OR users with stored credentials OR local accounts (if requested)
            should_include_task = (looks_like_domain_user(runas) or
                                 row.get("credentials_hint") == "stored_credentials" or
                                 (include_local and not looks_like_domain_user(runas)))
            if should_include_task:
                if not (row.get("credentials_hint") == "no_saved_credentials" and not show_unsaved_creds):
                    task_lines.extend(_format_block("TASK", rel_path, runas, what, meta.get("author"), meta.get("date"),
                                                   password_analysis=password_analysis, hv=hv, no_ldap=no_ldap,
                                                   domain=domain, dc_ip=dc_ip, username=username, password=password, hashes=hashes,
                                                   enabled=meta.get("enabled"), ldap_domain=ldap_domain, ldap_user=ldap_user,
                                                   ldap_password=ldap_password, meta=meta, decrypted_creds=decrypted_creds))
            row["password_analysis"] = password_analysis

        if not (row.get("credentials_hint") == "no_saved_credentials" and not show_unsaved_creds):
            all_rows.append(row)

    lines = priv_lines + task_lines
    # Sort tasks by priority: TIER-0 > PRIV > TASK
    sorted_lines = _sort_tasks_by_priority(lines)
    backup_msg = f", {total} raw XMLs backed up" if backup_target_dir else ""

    good(f"{target}: Found {total} tasks, privileged {priv_count if (hv and hv.loaded) else 'N/A'}{backup_msg}")

    # Combine credential loot output with task listing output
    # Put credentials first since they're the most valuable
    return out_lines + sorted_lines
