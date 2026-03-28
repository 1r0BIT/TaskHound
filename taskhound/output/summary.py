from typing import Any, Dict, List, Optional

from ..utils.console import console
from ..utils.console import print_summary_table as rich_summary_table


def _clean_failure_reason(reason: str) -> str:
    """
    Clean up verbose error messages for summary display.

    Converts technical error strings into human-readable summaries.
    """
    if not reason:
        return "Unknown error"

    reason_lower = reason.lower()

    # Connection errors
    if "connection refused" in reason_lower or "errno 61" in reason_lower:
        return "Connection refused"
    if "connection error" in reason_lower:
        return "Connection error"
    if "connection timed out" in reason_lower or "timed out" in reason_lower:
        return "Connection timed out"
    if "name or service not known" in reason_lower or "getaddrinfo failed" in reason_lower:
        return "DNS resolution failed"
    if "network unreachable" in reason_lower:
        return "Network unreachable"
    if "no route to host" in reason_lower:
        return "No route to host"

    # SMB/Auth errors
    if "status_logon_failure" in reason_lower:
        return "Authentication failed"
    if "status_account_disabled" in reason_lower:
        return "Account disabled"
    if "status_account_locked_out" in reason_lower:
        return "Account locked out"
    if "status_password_expired" in reason_lower:
        return "Password expired"
    if "status_access_denied" in reason_lower:
        return "Access denied"
    if "0xc0000072" in reason_lower:  # STATUS_ACCOUNT_DISABLED
        return "Account disabled"
    if "0xc000006d" in reason_lower:  # STATUS_LOGON_FAILURE
        return "Authentication failed"
    if "0xc000006e" in reason_lower:  # STATUS_ACCOUNT_RESTRICTION
        return "Account restriction"

    # LAPS errors - match the labels from online.py
    if "laps: no password" in reason_lower or "no laps password" in reason_lower:
        return "No LAPS password"
    if "laps: encrypted" in reason_lower:
        return "LAPS encrypted"
    if "laps: auth failed" in reason_lower or "laps auth failed" in reason_lower:
        return "LAPS auth failed"
    if "laps: remote uac" in reason_lower or "remote uac" in reason_lower:
        return "Remote UAC blocked"
    if reason_lower.startswith("laps:"):
        # Generic LAPS error - return the message part
        return reason.split(": ", 1)[1] if ": " in reason else reason

    # Other common errors
    if "c$ admin share not found" in reason_lower:
        return "C$ share not found"
    if "admin check failed" in reason_lower:
        return "Admin check failed"

    # Return cleaned up version - remove stack trace details
    # Look for common patterns and extract the key part
    if ": " in reason:
        # Take the first meaningful part before technical details
        parts = reason.split(": ", 1)
        if len(parts[0]) < 40:
            return parts[0]

    # Fallback: return reason as-is (will be truncated by display)
    return reason


def print_summary_table(
    all_rows: List[Any],
    backup_dir: Optional[str] = None,
    has_hv_data: bool = False,
    has_tier0_detection: bool = False,
    service_rows: Optional[List[Any]] = None,
):
    """Print a nicely formatted summary table showing task/service counts per host."""
    if not all_rows and not service_rows:
        return

    # Support both old and new parameter names
    has_hv = has_hv_data or has_tier0_detection

    # Aggregate data by host
    host_stats: Dict[str, Dict[str, Any]] = {}
    for row in all_rows:
        # Support both dict and TaskRow objects
        row_dict = row.to_dict() if hasattr(row, "to_dict") else row

        host = row_dict.get("host", "Unknown")
        task_type = row_dict.get("type", "TASK")
        reason = row_dict.get("reason", "")

        if host not in host_stats:
            host_stats[host] = {"tier0": 0, "privileged": 0, "normal": 0, "services": 0, "status": "[+]", "failure_reason": ""}

        if task_type == "FAILURE":
            host_stats[host]["status"] = "[-]"
            host_stats[host]["failure_reason"] = _clean_failure_reason(reason)
        elif task_type == "TIER-0":
            host_stats[host]["tier0"] += 1
        elif task_type == "PRIV":
            host_stats[host]["privileged"] += 1
        else:
            host_stats[host]["normal"] += 1

    # Aggregate service data
    if service_rows:
        for row in service_rows:
            row_dict = row.to_dict() if hasattr(row, "to_dict") else row
            host = row_dict.get("host", "Unknown")
            svc_type = row_dict.get("type", "SERVICE")

            if host not in host_stats:
                host_stats[host] = {"tier0": 0, "privileged": 0, "normal": 0, "services": 0, "status": "[+]", "failure_reason": ""}

            if svc_type == "TIER-0":
                host_stats[host]["tier0"] += 1
            elif svc_type == "PRIV":
                host_stats[host]["privileged"] += 1
            else:
                host_stats[host]["services"] += 1

    if not host_stats:
        return

    # Use Rich table
    rich_summary_table(host_stats, has_hv_data=has_hv)


def print_decrypted_credentials(all_rows: List[Any]) -> int:
    """
    Print a summary of all decrypted credentials found during the scan.

    This is always shown (not just in verbose mode) because decrypted
    credentials are high-value findings that users should not miss.

    Returns:
        Number of decrypted credentials found
    """
    from rich.table import Table

    # Collect all rows with decrypted passwords
    creds_found = []
    for row in all_rows:
        row_dict = row.to_dict() if hasattr(row, "to_dict") else row

        decrypted_password = row_dict.get("decrypted_password")
        if decrypted_password:
            # Use resolved_runas if available, otherwise fall back to runas
            runas = row_dict.get("runas", "Unknown")
            resolved_runas = row_dict.get("resolved_runas")

            # Format display: if we have resolved username for a SID, show "username (SID)"
            display_runas = f"{resolved_runas} ({runas})" if resolved_runas and runas.startswith("S-1-5-") else runas

            creds_found.append({
                "host": row_dict.get("host", "Unknown"),
                "path": row_dict.get("path", "Unknown"),
                "runas": display_runas,
                "password": decrypted_password,
                "type": row_dict.get("type", "TASK"),
            })

    if not creds_found:
        return 0

    # Create a table for decrypted credentials
    table = Table(
        title=f"[bold cyan]DECRYPTED CREDENTIALS ({len(creds_found)} found)[/]",
        title_style="bold cyan",
        border_style="cyan",
        show_header=True,
        header_style="bold white",
    )

    table.add_column("Type", style="dim", width=8)
    table.add_column("Host", style="white")
    table.add_column("RunAs", style="white")
    table.add_column("Password", style="bold green")
    table.add_column("Task Path", style="dim")

    for cred in creds_found:
        task_type = cred["type"]
        if task_type == "TIER-0":
            type_style = "bold red"
        elif task_type == "PRIV":
            type_style = "bold yellow"
        else:
            type_style = "bold green"

        table.add_row(
            f"[{type_style}]{task_type}[/]",
            cred["host"],
            cred["runas"],
            cred["password"],
            cred["path"],
        )

    console.print()
    console.print(table)
    console.print()

    return len(creds_found)
