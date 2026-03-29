from typing import Any, Dict, List, Optional

from rich.table import Table

from ..parsers.highvalue import HighValueLoader
from ..resolver import format_runas_with_sid_resolution
from ..smb.tasks import strip_task_root
from ..utils import logging as log_utils
from ..utils.console import console
from ..utils.credentials import find_password_for_user
from ..utils.date_parser import parse_iso_date
from . import COLORS


def print_task_table(
    kind: str,
    rel_path: str,
    rows: List[tuple],
    hostname: Optional[str] = None,
) -> None:
    """
    Print a task as a Rich table with colored borders.

    Args:
        kind: Task classification ('TIER-0', 'PRIV', or 'TASK')
        rel_path: Task path for the header
        rows: List of (label, value) tuples to display
        hostname: The hostname where the task was found (for multi-target scans)
    """
    if not (log_utils._VERBOSE or log_utils._DEBUG):
        return

    # Select colors based on task kind
    if kind == "TIER-0":
        header_style = COLORS["tier0_header"]
        border_style = COLORS["tier0_border"]
        tag = "[TIER-0]"
    elif kind == "PRIV":
        header_style = COLORS["priv_header"]
        border_style = COLORS["priv_border"]
        tag = "[PRIV]"
    else:
        header_style = COLORS["task_header"]
        border_style = COLORS["task_border"]
        tag = "[TASK]"

    # Build the title with tag, hostname (if provided), and path
    display_path = strip_task_root(rel_path)
    title = f"[{header_style}]{tag}[/] {hostname} - {display_path}" if hostname else f"[{header_style}]{tag}[/] {display_path}"

    # Create a simple two-column table
    table = Table(
        title=title,
        title_style=header_style,
        border_style=border_style,
        show_header=False,
        expand=False,
        padding=(0, 1),
    )

    table.add_column("Field", style=COLORS["label"], width=18)
    table.add_column("Value", style=COLORS["value"])

    # Add rows with special coloring for certain fields
    for label, value in rows:
        value_style = COLORS["value"]

        # Apply special styling to certain values
        if label == "Decrypted Pwd" and value:
            value_style = COLORS["password"]
        elif label == "Cred Validation":
            if "VALID" in value.upper() and "INVALID" not in value.upper():
                value_style = COLORS["success"]
            elif "INVALID" in value.upper() or "BLOCKED" in value.upper():
                value_style = COLORS["error"]
            elif "UNKNOWN" in value.upper():
                value_style = COLORS["warning"]
        elif label == "Pwd Analysis":
            if "GOOD" in value.upper() or "newer" in value.lower():
                value_style = COLORS["success"]
            elif "BAD" in value.upper() or "stale" in value.lower():
                value_style = COLORS["warning"]
            # Strip the GOOD:/BAD: prefix from display (used only for color detection)
            if value.upper().startswith("GOOD: "):
                value = value[6:]
            elif value.upper().startswith("BAD: "):
                value = value[5:]
        elif label == "Enabled":
            if value.lower() == "true":
                value_style = COLORS["success"]
            elif value.lower() == "false":
                value_style = COLORS["warning"]

        table.add_row(f"[{COLORS['label']}]{label}[/]", f"[{value_style}]{value}[/]")

    console.print()
    console.print(table)


def format_trigger_info(meta: Dict[str, Optional[str]]) -> Optional[str]:
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
            dt = parse_iso_date(start_boundary)
            if dt:
                details.append(f"starts {dt.strftime('%Y-%m-%d %H:%M')}")
            else:
                details.append(f"starts {start_boundary}")

        if interval:
            # Parse ISO 8601 duration format (PT5M = 5 minutes)
            interval_display = interval
            if interval.startswith("PT"):
                interval_clean = interval[2:]  # Remove 'PT' prefix
                if interval_clean.endswith("M"):
                    minutes = interval_clean[:-1]
                    interval_display = f"{minutes} minutes"
                elif interval_clean.endswith("H"):
                    hours = interval_clean[:-1]
                    interval_display = f"{hours} hours"
                elif interval_clean.endswith("S"):
                    seconds = interval_clean[:-1]
                    interval_display = f"{seconds} seconds"
            details.append(f"every {interval_display}")

        if duration:
            # Parse ISO 8601 duration format (P1D = 1 day)
            duration_display = duration
            if duration.startswith("P"):
                duration_clean = duration[1:]  # Remove 'P' prefix
                if duration_clean.endswith("D"):
                    days = duration_clean[:-1]
                    duration_display = f"{days} day{'s' if days != '1' else ''}"
                elif "T" in duration_clean:
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
            dt = parse_iso_date(start_boundary)
            if dt:
                trigger_parts.append(f"at {dt.strftime('%Y-%m-%d %H:%M')}")
            else:
                trigger_parts.append(f"at {start_boundary}")

    return " ".join(trigger_parts) if len(trigger_parts) > 1 else trigger_type


def _query_gmsa_ldap(
    username: str,
    domain: str,
    dc_ip: str,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
) -> Optional[Dict[str, bool]]:
    """
    Query LDAP directly to check if an account is a gMSA or MSA.

    Checks the objectClass attribute for:
    - msds-groupmanagedserviceaccount (gMSA)
    - msds-managedserviceaccount (MSA)

    Args:
        username: The sAMAccountName to look up (with or without $ suffix)
        domain: Domain name for constructing search base
        dc_ip: Domain controller IP address
        ldap_user: Username for LDAP authentication
        ldap_password: Password for LDAP authentication
        ldap_hashes: NTLM hashes for LDAP authentication

    Returns:
        Dict with is_gmsa and is_msa booleans, or None if query failed
    """
    from impacket.ldap.ldapasn1 import SearchResultEntry

    from ..utils.ldap import get_ldap_connection
    from ..utils.logging import debug

    # Ensure username has $ suffix for service account lookup
    sam_account_name = username if username.endswith("$") else f"{username}$"

    try:
        ldap_conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=ldap_user or "",
            password=ldap_password,
            hashes=ldap_hashes,
        )

        # Build search base from domain
        search_base = ",".join(f"DC={part}" for part in domain.split("."))

        # Search for the account by sAMAccountName, request objectClass
        search_filter = f"(sAMAccountName={sam_account_name})"

        results = ldap_conn.search(
            searchBase=search_base,
            searchFilter=search_filter,
            attributes=["objectClass", "sAMAccountName"],
        )

        # Process results - impacket returns a list of SearchResultEntry objects
        for entry in results:
            if not isinstance(entry, SearchResultEntry):
                continue

            object_classes = []

            for attr in entry["attributes"]:
                attr_type = str(attr["type"])
                if attr_type.lower() == "objectclass":
                    # Extract all objectClass values
                    for val in attr["vals"]:
                        object_classes.append(str(val).lower())
                    break

            # Check for gMSA/MSA object classes
            is_gmsa = "msds-groupmanagedserviceaccount" in object_classes
            is_msa = "msds-managedserviceaccount" in object_classes

            debug(f"[LDAP gMSA] {sam_account_name}: objectClasses={object_classes}, is_gmsa={is_gmsa}, is_msa={is_msa}")

            return {"is_gmsa": is_gmsa, "is_msa": is_msa}

        # Account not found
        debug(f"[LDAP gMSA] {sam_account_name}: account not found in LDAP")
        return None

    except Exception as e:
        debug(f"[LDAP gMSA] Query failed for {sam_account_name}: {e}")
        return None


def _check_gmsa_account(
    display_runas: str,
    resolved_username: Optional[str] = None,
    bh_connector=None,
    cache_manager=None,
    no_ldap: bool = False,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
) -> Optional[str]:
    """
    Check if the runas account is a gMSA (Group Managed Service Account).

    Uses a multi-tier detection strategy:
    1. Cache - Check if we've already determined gMSA status for this user
    2. BloodHound - Query User node for gmsa/msa boolean properties
    3. LDAP - Query AD directly for objectClass=msds-groupmanagedserviceaccount
    4. Heuristic Fallback - Username ends with '$' and not a system account

    BloodHound CE stores 'gmsa' and 'msa' properties on User nodes, derived from
    objectClass during SharpHound collection (msds-groupmanagedserviceaccount).

    Args:
        display_runas: The display string for the runas account
        resolved_username: The resolved username (if SID was resolved)
        bh_connector: BloodHound connector for API queries (optional)
        cache_manager: Cache manager for storing results (optional)
        no_ldap: Skip LDAP queries (OPSEC mode)
        domain: Domain name for LDAP connection
        dc_ip: Domain controller IP for LDAP connection
        ldap_user: Username for LDAP authentication
        ldap_password: Password for LDAP authentication
        ldap_hashes: NTLM hashes for LDAP authentication

    Returns:
        Hint message if gMSA detected, None otherwise
    """
    # Get the username to check - prefer resolved, fall back to display
    username = resolved_username or display_runas
    if not username:
        return None

    # Extract just the username part (remove domain prefix)
    clean_username = username
    if "\\" in username:
        clean_username = username.split("\\")[-1]
    elif "@" in username:
        clean_username = username.split("@")[0]

    # Skip well-known system accounts early
    well_known_skip = {
        "system", "local service", "network service",
        "nt authority", "nt service", "iis apppool"
    }
    display_lower = display_runas.lower()

    for skip in well_known_skip:
        if skip in display_lower:
            return None

    # Cache key uses the clean username (lowercase for consistency)
    cache_key = clean_username.lower().rstrip("$")

    # Tier 1: Check cache first (only for potential service accounts ending with $)
    if cache_manager and clean_username.endswith("$"):
        cached = cache_manager.get("svc_account", cache_key)
        if cached is not None:
            if cached.get("is_gmsa") or cached.get("is_msa"):
                return _format_gmsa_hint(cached.get("is_gmsa", False), cached.get("is_msa", False))
            return None

    # Tier 2: Query BloodHound for authoritative gMSA/MSA status
    if bh_connector:
        try:
            result = bh_connector.get_user_gmsa_status(username)
            if result:
                is_gmsa = result.get("is_gmsa", False)
                is_msa = result.get("is_msa", False)

                # Cache the result only for service accounts (ending with $)
                if cache_manager and clean_username.endswith("$"):
                    cache_manager.set("svc_account", cache_key, {
                        "is_gmsa": is_gmsa,
                        "is_msa": is_msa,
                        "source": "bloodhound",
                    })

                if is_gmsa or is_msa:
                    return _format_gmsa_hint(is_gmsa, is_msa)

                # BloodHound found the user but gmsa/msa properties are False
                # If the username ends with $, fall through to LDAP verification
                # (SharpHound may not have collected objectClass data)
                if not clean_username.endswith("$"):
                    return None
                # Fall through to LDAP for $ accounts
        except Exception:
            pass  # Fall through to LDAP/heuristic

    # Tier 3: LDAP query - check objectClass directly in AD
    if not no_ldap and domain and dc_ip and clean_username.endswith("$"):
        ldap_result = _query_gmsa_ldap(
            clean_username,
            domain,
            dc_ip,
            ldap_user,
            ldap_password,
            ldap_hashes,
        )
        if ldap_result is not None:
            is_gmsa = ldap_result.get("is_gmsa", False)
            is_msa = ldap_result.get("is_msa", False)

            # Cache the LDAP result
            if cache_manager:
                cache_manager.set("svc_account", cache_key, {
                    "is_gmsa": is_gmsa,
                    "is_msa": is_msa,
                    "source": "ldap",
                })

            if is_gmsa or is_msa:
                return _format_gmsa_hint(is_gmsa, is_msa)
            # LDAP confirmed account exists but is not gMSA/MSA
            return None
        # LDAP query failed, fall through to heuristic

    # Tier 4: Heuristic fallback - check if username ends with $
    if not clean_username.endswith("$"):
        return None

    # Cache heuristic result (lower confidence)
    if cache_manager:
        cache_manager.set("svc_account", cache_key, {
            "is_gmsa": True,  # Assume gMSA for $ accounts (more common than MSA)
            "is_msa": False,
            "source": "heuristic",
        })

    # At this point we have an account ending with $ - likely a gMSA
    return _format_gmsa_hint(is_gmsa=True, is_msa=False, heuristic=True)


def _format_gmsa_hint(is_gmsa: bool, is_msa: bool, heuristic: bool = False) -> str:
    """Format the gMSA/MSA hint message."""
    if is_gmsa:
        account_type = "gMSA (Group Managed Service Account)"
    elif is_msa:
        account_type = "MSA (Managed Service Account)"
    else:
        account_type = "Service Account"

    hint = f"{account_type} - credentials stored in LSA secrets, not DPAPI."
    hint += " Run without --no-lsa to extract NTLM hash automatically."

    if heuristic:
        hint += " (detected by $ suffix heuristic)"

    return hint


def format_block(
    kind: str,
    rel_path: str,
    runas: str,
    what: str,
    author: str,
    date: str,
    extra_reason: Optional[str] = None,
    password_analysis: Optional[str] = None,
    hv: Optional[HighValueLoader] = None,
    bh_connector=None,
    smb_connection=None,
    no_ldap: bool = False,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    hostname: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    enabled: Optional[str] = None,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
    meta: Optional[Dict[str, Optional[str]]] = None,
    decrypted_creds: Optional[List] = None,
    concise: bool = False,
    cred_validation: Optional[Dict[str, Any]] = None,
    resolved_runas: Optional[str] = None,
    credential_guard: Optional[bool] = None,
    cache_manager=None,
) -> List[str]:
    """
    Format a task block for CLI output.

    Returns list of strings for file output, and prints a Rich table to console.

    Args:
        kind: 'TIER-0', 'PRIV' (privileged/high-value) or 'TASK' (normal task)
        rel_path: Task path relative to Tasks folder
        runas: The RunAs user/SID
        what: Command/action the task executes
        ... (other args for enrichment)
    """
    if kind == "TIER-0":
        header = "[TIER-0]"
    elif kind == "PRIV":
        header = "[PRIV]"
    else:
        header = "[TASK]"

    # Use pre-resolved username if available, otherwise resolve now
    if resolved_runas:
        # Already resolved - format display string
        from ..resolver import is_sid
        display_runas = f"{resolved_runas} ({runas})" if is_sid(runas) else runas
        resolved_username = resolved_runas
    else:
        # Resolve SID in RunAs field for better display (uses 4-tier fallback: offline BH → API → SMB → LDAP)
        display_runas, resolved_username = format_runas_with_sid_resolution(  # type: ignore[assignment]  # resolved_username may be None
            runas,
            hv_loader=hv,
            bh_connector=bh_connector,
            smb_connection=smb_connection,
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

    display_path = strip_task_root(rel_path)

    if concise:
        # Concise output: One line per task
        # Format: [KIND] Hostname - RunAs | Path | What | (optional reason) | (optional password)
        if hostname:
            line = f"{header} {hostname} - {display_runas} | {display_path} | {what}"
        else:
            line = f"{header} {display_runas} | {display_path} | {what}"
        if extra_reason:
            line += f" | {extra_reason}"

        # In concise mode, show decrypted password inline if available for ALL task types
        if decrypted_creds:
            password = find_password_for_user(runas, decrypted_creds, resolved_username)
            if password:
                line += f" | PWD: {password}"

        return [line]

    # Build rows for table output: list of (label, value) tuples
    rows: List[tuple] = []

    # Add task state information as first field
    if enabled is not None:
        enabled_display = enabled.capitalize() if enabled.lower() in ["true", "false"] else enabled
        rows.append(("Enabled", enabled_display))

    # Core task information
    rows.append(("RunAs", display_runas))
    rows.append(("What", what))

    if author:
        rows.append(("Author", author))
    if date:
        rows.append(("Date", date))

    # Trigger information
    if meta:
        trigger_info = format_trigger_info(meta)
        if trigger_info:
            rows.append(("Trigger", trigger_info))

    # Password analysis
    if password_analysis:
        # If credential validation shows VALID, update stale warning since we've confirmed it works
        if (
            cred_validation
            and cred_validation.get("cred_password_valid") is True
            and "could be stale" in password_analysis.lower()
        ):
            # Replace the stale warning with validated message
            password_analysis = password_analysis.replace(
                "Password could be stale",
                "Credential validated as working"
            )
        rows.append(("Pwd Analysis", password_analysis))

    # Credential validation results
    if cred_validation:
        cred_status = cred_validation.get("cred_status")
        cred_valid = cred_validation.get("cred_password_valid")
        cred_hijackable = cred_validation.get("cred_hijackable")
        cred_detail = cred_validation.get("cred_detail")
        cred_code = cred_validation.get("cred_return_code")
        cred_last_run = cred_validation.get("cred_last_run")

        # Build status display
        if cred_status == "unknown":
            if password_analysis and "GOOD" in password_analysis.upper():
                status_display = "LIKELY VALID (password newer than pwdLastSet)"
            elif password_analysis and "BAD" in password_analysis.upper():
                status_display = "LIKELY INVALID (password older than pwdLastSet)"
            else:
                status_display = "UNKNOWN"
        elif cred_valid is True:
            status_display = "VALID" if cred_hijackable else f"VALID (restricted: {cred_status})"
        elif cred_status == "invalid":
            status_display = "INVALID (wrong password)"
        elif cred_status == "blocked":
            status_display = "BLOCKED (account disabled/expired)"
        else:
            status_display = f"{cred_status} ({cred_code})"

        rows.append(("Cred Validation", status_display))

        if cred_last_run:
            rows.append(("Last Run", cred_last_run))

        if cred_code:
            from ..smb.task_rpc import get_return_code_description
            try:
                code_int = int(cred_code, 16) if cred_code.startswith("0x") else int(cred_code)
                code_desc = get_return_code_description(code_int)
                rows.append(("Return Code", f"{cred_code} ({code_desc})"))
            except (ValueError, TypeError):
                rows.append(("Return Code", cred_code))

        if cred_detail and not cred_hijackable:
            rows.append(("Cred Detail", cred_detail))

    # Find decrypted password for this user
    decrypted_password = _find_decrypted_password(
        decrypted_creds, runas, display_runas, resolved_username
    )

    if decrypted_password:
        rows.append(("Decrypted Pwd", decrypted_password))

    # gMSA hint - uses multi-tier detection: Cache → BloodHound → LDAP → Heuristic
    # Suppress if we already extracted the NTLM hash (hint is redundant)
    if not decrypted_password:
        gmsa_hint = _check_gmsa_account(
            display_runas,
            resolved_username,
            bh_connector=bh_connector,
            cache_manager=cache_manager,
            no_ldap=no_ldap,
            domain=ldap_domain or domain,
            dc_ip=dc_ip,
            ldap_user=ldap_user or username,
            ldap_password=ldap_password or password,
            ldap_hashes=ldap_hashes or hashes,
        )
        if gmsa_hint:
            rows.append(("gMSA Hint", gmsa_hint))

    # Credential Guard status (shown when credguard_detect is enabled, which is default)
    if credential_guard is not None:
        if credential_guard:
            rows.append(("Cred Guard", "[red]ENABLED[/]"))
        else:
            rows.append(("Cred Guard", "[green]DISABLED[/] - DPAPI extraction possible"))

    # Reason for privileged tasks
    if kind in ["TIER-0", "PRIV"]:
        if extra_reason:
            rows.append(("Reason", extra_reason))
        elif kind == "TIER-0":
            rows.append(("Reason", "Tier 0 privileged group membership"))
        else:
            rows.append(("Reason", "High Value match found (Check BloodHound Outbound Object Control for Details)"))

        if not decrypted_password and (not extra_reason or "no saved credentials" not in extra_reason.lower()):
            rows.append(("Next Step", "Try DPAPI Dump / Task Manipulation"))

    # Print Rich table to console
    print_task_table(kind, display_path, rows, hostname=hostname)

    # Return text format for file output (backward compatibility)
    # Label width is 18 chars + 1 space before colon = 19 chars total before ":"
    base = [f"\n{header} {hostname} - {display_path}"] if hostname else [f"\n{header} {display_path}"]
    for label, value in rows:
        base.append(f"        {label:<18} : {value}")

    return base


def _find_decrypted_password(
    decrypted_creds: Optional[List],
    runas: str,
    display_runas: str,
    resolved_username: Optional[str],
) -> Optional[str]:
    """Find decrypted password matching the runas user."""
    if not decrypted_creds:
        return None

    # Use display_runas as primary (may have resolved name), runas as fallback
    primary_username = display_runas if display_runas else runas
    return find_password_for_user(primary_username, decrypted_creds, resolved_username)


def format_service_block(
    kind: str,
    service_name: str,
    display_name: Optional[str] = None,
    start_name: Optional[str] = None,
    binary_path: Optional[str] = None,
    start_type: Optional[str] = None,
    state: Optional[str] = None,
    is_gmsa: bool = False,
    hostname: Optional[str] = None,
    reason: Optional[str] = None,
    password_analysis: Optional[str] = None,
    decrypted_password: Optional[str] = None,
    resolved_runas: Optional[str] = None,
    credential_guard: Optional[bool] = None,
) -> List[str]:
    """
    Format a Windows service finding for rich console output.

    Returns a list of output lines (for compatibility with the task
    format_block pattern used by process_target).
    """
    # Build row tuples for print_service_table
    rows: List[tuple] = []

    if display_name:
        rows.append(("Display Name", display_name))
    if start_name:
        account_display = start_name
        if resolved_runas and resolved_runas != start_name:
            account_display = f"{resolved_runas} (SID: {start_name})"
        if is_gmsa:
            account_display += " \\[gMSA]"
        rows.append(("Run As", account_display))
    if binary_path:
        rows.append(("Binary Path", binary_path))
    if start_type:
        rows.append(("Start Type", start_type))
    if state:
        rows.append(("State", state))
    if reason:
        rows.append(("Reason", reason))
    if password_analysis:
        rows.append(("Pwd Analysis", password_analysis))
    if decrypted_password:
        rows.append(("Decrypted Pwd", decrypted_password))
    if credential_guard is True:
        rows.append(("Cred Guard", "DETECTED - LSA extraction may fail"))

    # Use the same table renderer as tasks
    print_service_table(kind, service_name, rows, hostname=hostname)

    # Return a summary line for the text output stream
    tag = f"[{kind}]"
    account = start_name or "?"
    if is_gmsa:
        account += " [gMSA]"
    line = f"\n{tag} {hostname or ''} - {service_name} (Run As: {account})"
    return [line]


def print_service_table(
    kind: str,
    service_name: str,
    rows: List[tuple],
    hostname: Optional[str] = None,
) -> None:
    """Print a service finding as a Rich table with colored borders."""
    if not (log_utils._VERBOSE or log_utils._DEBUG):
        return

    # Select colors based on classification
    if kind == "TIER-0":
        header_style = COLORS["tier0_header"]
        border_style = COLORS["tier0_border"]
        tag = "[TIER-0]"
    elif kind == "PRIV":
        header_style = COLORS["priv_header"]
        border_style = COLORS["priv_border"]
        tag = "[PRIV]"
    else:
        header_style = COLORS["service_header"]
        border_style = COLORS["service_border"]
        tag = "[SERVICE]"

    title = f"[{header_style}]{tag}[/] {hostname} - {service_name}" if hostname else f"[{header_style}]{tag}[/] {service_name}"

    table = Table(
        title=title,
        title_style=header_style,
        border_style=border_style,
        show_header=False,
        expand=False,
        padding=(0, 1),
    )

    table.add_column("Field", style=COLORS["label"], width=18)
    table.add_column("Value", style=COLORS["value"])

    for label, value in rows:
        value_style = COLORS["value"]
        if label == "Decrypted Pwd" and value:
            value_style = COLORS["password"]
        elif label == "Pwd Analysis":
            if "GOOD" in value.upper():
                value_style = COLORS["success"]
            elif "BAD" in value.upper():
                value_style = COLORS["warning"]
        table.add_row(f"[{COLORS['label']}]{label}[/]", f"[{value_style}]{value}[/]")

    console.print()
    console.print(table)

