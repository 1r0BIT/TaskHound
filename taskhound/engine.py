# Core processing for a single target host.
#
# This module ties together SMB connection, task enumeration, XML parsing,
# and high-value enrichment. The main entry point `process_target` returns
# a list of printable strings suitable for the CLI while also appending
# structured rows to `all_rows` for export.

import traceback
import os
from typing import List, Dict, Optional, Tuple

from impacket.smbconnection import SMBConnection, SessionError

from .smb.connection import smb_connect
from .smb.tasks import smb_listdir, crawl_tasks
from .parsers.task_xml import parse_task_xml
from .parsers.highvalue import HighValueLoader
from .utils.helpers import looks_like_domain_user
from .utils.logging import good, warn, info
from .utils.sid_resolver import format_runas_with_sid_resolution
from .smb.credguard import check_credential_guard


def process_offline_directory(offline_dir: str, hv: Optional[HighValueLoader], 
                             show_unsaved_creds: bool, include_local: bool, all_rows: List[Dict], debug: bool,
                             no_ldap: bool = False) -> List[str]:
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
    
    # Look for host directories (subdirectories of offline_dir)
    try:
        host_dirs = [d for d in os.listdir(offline_dir) 
                    if os.path.isdir(os.path.join(offline_dir, d))]
    except Exception as e:
        warn(f"Failed to list offline directory {offline_dir}: {e}")
        return out_lines
    
    if not host_dirs:
        warn(f"No host directories found in offline directory: {offline_dir}")
        return out_lines
    
    total_hosts = len(host_dirs)
    good(f"Offline mode: Found {total_hosts} host directories to process")
    
    for host in host_dirs:
        host_path = os.path.join(offline_dir, host)
        lines = _process_offline_host(host, host_path, hv, show_unsaved_creds, include_local, all_rows, debug, no_ldap)
        out_lines.extend(lines)
    
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

        row = _build_row(hostname, rel_path, meta)

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
                                                   hv=hv, no_ldap=no_ldap, enabled=meta.get("enabled")))
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
                                                   hv=hv, no_ldap=no_ldap, enabled=meta.get("enabled")))
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
                                                   password_analysis=password_analysis, hv=hv, no_ldap=no_ldap, 
                                                   enabled=meta.get("enabled")))
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


def _build_row(host: str, rel_path: str, meta: Dict[str, str]) -> Dict[str, Optional[str]]:
    # Create a structured dict for CSV/JSON export representing a task.
    #
    # Keeps the same keys used by the writer so rows can be dumped directly.
    
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
        "path": rel_path,
        "type": "TASK",
        "runas": meta.get("runas"),
        "command": meta.get("command"),
        "arguments": meta.get("arguments"),
        "author": meta.get("author"),
        "date": meta.get("date"),
        "logon_type": meta.get("logon_type"),
        "enabled": meta.get("enabled"),
        "reason": None,
        "credentials_hint": credentials_hint,
    }


def _format_block(kind: str, rel_path: str, runas: str, what: str, author: str, date: str, 
                  extra_reason: Optional[str] = None, password_analysis: Optional[str] = None,
                  hv: Optional[HighValueLoader] = None, no_ldap: bool = False, 
                  domain: Optional[str] = None, username: Optional[str] = None, 
                  password: Optional[str] = None, hashes: Optional[str] = None,
                  enabled: Optional[str] = None) -> List[str]:
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
        runas, hv, no_ldap, domain, username, password, hashes
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
    
    if kind in ["TIER-0", "PRIV"]:
        if extra_reason:
            base.append(f"        Reason : {extra_reason}")
        elif kind == "TIER-0":
            base.append("        Reason : Tier 0 privileged group membership")
        else:
            base.append("        Reason : High Value match found (Check BloodHound Outbound Object Control for Details)")
        
        # Add password analysis if available
        if password_analysis:
            base.append(f"        Password Analysis : {password_analysis}")
            
        # Add consistent next step for all privileged tasks
        # This logic is only for pretty output, so we check for the typical reason string and absence of 'no_saved_credentials'
        if (not extra_reason or "no saved credentials" not in extra_reason.lower()):
            base.append("        Next Step: Try DPAPI Dump / Task Manipulation")
    
    # Add password analysis for regular TASK entries too (if available)
    elif kind == "TASK" and password_analysis:
        base.append(f"        Password Analysis : {password_analysis}")
        
        # Add consistent next step for regular tasks with password analysis
        base.append("        Next Step: Try DPAPI Dump / Task Manipulation")
    
    return base


def process_target(target: str, domain: str, username: str, password: Optional[str],
                   kerberos: bool, dc_ip: Optional[str], include_ms: bool, include_local: bool,
                   hv: Optional[HighValueLoader], debug: bool,
                   all_rows: List[Dict], hashes: Optional[str] = None,
                   show_unsaved_creds: bool = False, backup_dir: Optional[str] = None,
                   credguard_detect: bool = False, no_ldap: bool = False) -> List[str]:
    # Connect to `target`, enumerate scheduled tasks, and return printable lines.
    #
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
    try:
        # Prefer explicit hashes parameter over password when provided
        smb = smb_connect(target, domain, username, hashes or password, kerberos=kerberos, dc_ip=dc_ip)
        good(f"{target}: Connected via SMB")
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
        row = _build_row(target, rel_path, meta)
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
                                                   hv=hv, no_ldap=no_ldap, domain=domain, username=username, 
                                                   password=password, hashes=hashes, enabled=meta.get("enabled")))
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
                                                   hv=hv, no_ldap=no_ldap, domain=domain, username=username, 
                                                   password=password, hashes=hashes, enabled=meta.get("enabled")))
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
                                                   domain=domain, username=username, password=password, hashes=hashes, enabled=meta.get("enabled")))
            row["password_analysis"] = password_analysis
            
        if not (row.get("credentials_hint") == "no_saved_credentials" and not show_unsaved_creds):
            all_rows.append(row)

    lines = priv_lines + task_lines
    # Sort tasks by priority: TIER-0 > PRIV > TASK
    sorted_lines = _sort_tasks_by_priority(lines)
    backup_msg = f", {total} raw XMLs backed up" if backup_target_dir else ""
    good(f"{target}: Found {total} tasks, privileged {priv_count if (hv and hv.loaded) else 'N/A'}{backup_msg}")
    return sorted_lines
