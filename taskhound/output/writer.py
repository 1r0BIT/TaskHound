import csv
import json
import os
from io import StringIO
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..smb.tasks import strip_task_root
from ..utils.logging import good
from . import COLORS, cred_status_display


def _rows_to_dicts(rows: list[Any]) -> list[dict]:
    """Convert TaskRow objects to dicts for serialization."""
    return [row.to_dict() if hasattr(row, "to_dict") else row for row in rows]


def _format_task_table(row_dict: dict[str, Any], hostname: str | None = None) -> Table:
    """
    Format a single task as a Rich table matching README demo format.

    Uses SQUARE box style with title as header row for clean output.

    Args:
        row_dict: Task data as dictionary
        hostname: Optional hostname to include in title

    Returns:
        Rich Table object
    """
    task_type = row_dict.get("type", "TASK")

    # Select colors based on task type
    if task_type == "TIER-0":
        header_style = COLORS["tier0_header"]
        border_style = COLORS["tier0_border"]
        tag = "[TIER-0]"
    elif task_type == "PRIV":
        header_style = COLORS["priv_header"]
        border_style = COLORS["priv_border"]
        tag = "[PRIV]"
    else:
        header_style = COLORS["task_header"]
        border_style = COLORS["task_border"]
        tag = "[TASK]"

    rel_path = strip_task_root(row_dict.get("path", "Unknown"))

    # Build title with hostname if provided
    title = f"[{header_style}]{tag}[/] {hostname} - {rel_path}" if hostname else f"[{header_style}]{tag}[/] {rel_path}"

    # Use SQUARE box style with title as header - matches README format
    table = Table(
        box=box.SQUARE,
        show_header=True,
        header_style=header_style,
        border_style=border_style,
        expand=False,
        padding=(0, 1),
        width=80,
    )

    # Single column with title as header
    table.add_column(title, style=COLORS["value"])

    # Helper to format field rows in README style: "Field          │ Value"
    def add_field(label: str, value: str):
        # Pad label to 16 chars for alignment
        formatted = f"[{COLORS['label']}]{label:<16}[/] │ {value}"
        table.add_row(formatted)

    # Build rows from task data
    if row_dict.get("enabled"):
        add_field("Enabled", row_dict["enabled"])

    runas = row_dict.get("runas", "")
    resolved = row_dict.get("resolved_runas")
    display_runas = f"{resolved} ({runas})" if resolved and runas.startswith("S-1-5-") else runas
    if display_runas:
        add_field("RunAs", display_runas)

    if row_dict.get("decrypted_password"):
        add_field("Decrypted Pwd", f"[{COLORS['password']}]{row_dict['decrypted_password']}[/]")

    if row_dict.get("logon_type"):
        add_field("Logon Type", row_dict["logon_type"])

    command = row_dict.get("command", "")
    args = row_dict.get("arguments", "")
    what = f"{command} {args}".strip() if args else command
    if what:
        add_field("What", what)

    if row_dict.get("author"):
        add_field("Author", row_dict["author"])

    if row_dict.get("date"):
        add_field("Date", row_dict["date"])

    # Trigger information
    trigger_type = row_dict.get("trigger_type")
    if trigger_type:
        trigger_info = _format_trigger_display(row_dict)
        add_field("Trigger", trigger_info)

    if row_dict.get("password_analysis"):
        add_field("Pwd Analysis", row_dict["password_analysis"])

    if row_dict.get("cred_status"):
        cred_status = row_dict["cred_status"]
        cred_valid = row_dict.get("cred_password_valid")
        cred_hijackable = row_dict.get("cred_hijackable")
        cred_code = row_dict.get("cred_return_code")
        password_analysis = row_dict.get("password_analysis")

        # Build status display matching printer.py verbose output format
        status_display = cred_status_display(cred_status, cred_valid, cred_hijackable, cred_code, password_analysis)

        # Color based on status
        if cred_valid:
            add_field("Cred Validation", f"[green]{status_display}[/]")
        elif cred_status == "invalid":
            add_field("Cred Validation", f"[red]{status_display}[/]")
        else:
            add_field("Cred Validation", f"[yellow]{status_display}[/]")

        # Show last run time if available
        if row_dict.get("cred_last_run"):
            add_field("Last Run", row_dict["cred_last_run"])

        # Show return code with description if available
        if row_dict.get("cred_return_code"):
            from ..smb.task_rpc import get_return_code_description

            code = row_dict["cred_return_code"]
            try:
                code_int = int(code, 16) if code.startswith("0x") else int(code)
                add_field("Return Code", f"{code} ({get_return_code_description(code_int)})")
            except (ValueError, TypeError):
                add_field("Return Code", code)

    # Credential Guard status - show both enabled and disabled states
    if row_dict.get("credential_guard") is not None:
        if row_dict["credential_guard"]:
            add_field("Cred Guard", "[red]ENABLED[/]")
        else:
            add_field("Cred Guard", "[green]DISABLED - DPAPI extraction possible[/]")

    if row_dict.get("reason"):
        add_field("Reason", row_dict["reason"])

    return table


def _format_trigger_display(row_dict: dict[str, Any]) -> str:
    """Format trigger information for plain text display."""
    trigger_type = row_dict.get("trigger_type", "")

    start_boundary = row_dict.get("start_boundary")
    interval = row_dict.get("interval")
    days_interval = row_dict.get("days_interval")

    details = []

    if start_boundary:
        # Simplify ISO date for display
        if "T" in start_boundary:
            date_part = start_boundary.split("T")[0]
            time_part = start_boundary.split("T")[1].split(".")[0].split("+")[0].split("-")[0][:5]
            details.append(f"starts {date_part} {time_part}")
        else:
            details.append(f"starts {start_boundary}")

    if interval:
        # Parse ISO 8601 duration (PT5M = 5 minutes, PT1H = 1 hour)
        if interval.startswith("PT"):
            interval_clean = interval[2:]
            if interval_clean.endswith("M"):
                details.append(f"every {interval_clean[:-1]}min")
            elif interval_clean.endswith("H"):
                details.append(f"every {interval_clean[:-1]}h")
            elif interval_clean.endswith("S"):
                details.append(f"every {interval_clean[:-1]}s")
            else:
                details.append(f"every {interval}")
        else:
            details.append(f"every {interval}")

    if days_interval:
        if days_interval == "1":
            details.append("daily")
        else:
            details.append(f"every {days_interval} days")

    if details:
        return f"{trigger_type} ({', '.join(details)})"
    return trigger_type


def write_rich_plain(outdir: str, all_rows: list[Any], force_color: bool = True):
    """
    Write Rich-formatted output files grouped by host.

    Creates a directory structure:
        outdir/
        ├── summary.txt          # Overall summary with stats
        ├── host1/
        │   └── tasks.txt        # Rich-formatted task details
        └── host2/
            └── tasks.txt

    Files use ANSI color codes by default for viewing with `cat` or `less -R`.

    Args:
        outdir: Output directory path
        all_rows: List of TaskRow objects or dicts
        force_color: Include ANSI color codes (default True)
    """
    os.makedirs(outdir, exist_ok=True)

    # Group rows by host
    hosts: dict[str, list[dict]] = {}
    for row in all_rows:
        row_dict = row.to_dict() if hasattr(row, "to_dict") else row
        host = row_dict.get("host", "unknown")
        if host not in hosts:
            hosts[host] = []
        hosts[host].append(row_dict)

    # Write summary.txt in root
    _write_summary_file(outdir, hosts, force_color)

    # Write per-host task files in subdirectories
    for host, rows in hosts.items():
        safe_host = host.replace(":", "_").replace("/", "_").replace("\\", "_")
        host_dir = os.path.join(outdir, safe_host)
        os.makedirs(host_dir, exist_ok=True)

        tasks_path = os.path.join(host_dir, "tasks.txt")
        _write_host_tasks_file(tasks_path, host, rows, force_color)

    good(f"Wrote results to {outdir}/ ({len(hosts)} hosts)")


def _write_summary_file(outdir: str, hosts: dict[str, list[dict]], force_color: bool):
    """Write summary.txt with overall stats and per-host breakdown."""
    summary_path = os.path.join(outdir, "summary.txt")

    buffer = StringIO()
    file_console = Console(file=buffer, force_terminal=force_color, width=120)

    # Overall header
    file_console.print("\n[bold cyan]╔══════════════════════════════════════════════════════════════╗[/]")
    file_console.print("[bold cyan]║               TaskHound Scan Summary                         ║[/]")
    file_console.print("[bold cyan]╚══════════════════════════════════════════════════════════════╝[/]\n")

    # Calculate totals
    total_tier0 = 0
    total_priv = 0
    total_task = 0
    total_failures = 0
    decrypted_creds = []

    for _host, rows in hosts.items():
        for r in rows:
            task_type = r.get("type", "TASK")
            if task_type == "TIER-0":
                total_tier0 += 1
            elif task_type == "PRIV":
                total_priv += 1
            elif task_type == "FAILURE":
                total_failures += 1
            else:
                total_task += 1

            if r.get("decrypted_password"):
                decrypted_creds.append(r)

    # Overall stats
    file_console.print("[bold white]Overall Statistics[/]")
    file_console.print(f"  Hosts Scanned  : {len(hosts)}")
    file_console.print(f"  [bold red]TIER-0 Tasks   : {total_tier0}[/]")
    file_console.print(f"  [bold yellow]Privileged     : {total_priv}[/]")
    file_console.print(f"  [bold green]Regular Tasks  : {total_task}[/]")
    if total_failures:
        file_console.print(f"  [red]Failures       : {total_failures}[/]")
    file_console.print()

    # Decrypted credentials highlight
    if decrypted_creds:
        file_console.print(f"[bold green]Decrypted Credentials: {len(decrypted_creds)}[/]\n")

        cred_table = Table(
            title="[bold cyan]Decrypted Credentials[/]",
            border_style="cyan",
            show_header=True,
            header_style="bold white",
        )
        cred_table.add_column("Type", style="dim", width=8)
        cred_table.add_column("Host", style="white")
        cred_table.add_column("RunAs", style="white")
        cred_table.add_column("Password", style="bold green")

        for cred in decrypted_creds:
            task_type = cred.get("type", "TASK")
            if task_type == "TIER-0":
                type_style = "bold red"
            elif task_type == "PRIV":
                type_style = "bold yellow"
            else:
                type_style = "bold green"

            runas = cred.get("runas", "")
            resolved = cred.get("resolved_runas")
            display_runas = f"{resolved}" if resolved else runas

            cred_table.add_row(
                f"[{type_style}]{task_type}[/]",
                cred.get("host", ""),
                display_runas,
                cred.get("decrypted_password", ""),
            )

        file_console.print(cred_table)
        file_console.print()

    # Per-host breakdown table
    file_console.print("[bold white]Per-Host Breakdown[/]\n")

    host_table = Table(
        border_style="dim",
        show_header=True,
        header_style="bold white",
        box=None,
    )
    host_table.add_column("Hostname", style="white")
    host_table.add_column("Tier-0", style="red", justify="center")
    host_table.add_column("Privileged", style="yellow", justify="center")
    host_table.add_column("Normal", style="green", justify="center")

    for host, rows in sorted(hosts.items()):
        t0 = sum(1 for r in rows if r.get("type") == "TIER-0")
        priv = sum(1 for r in rows if r.get("type") == "PRIV")
        task = sum(1 for r in rows if r.get("type") == "TASK")

        host_table.add_row(host, str(t0), str(priv), str(task))

    # Wrap in panel to match README demo format
    file_console.print(Panel(host_table, title="[bold]TASK SUMMARY[/]", border_style="cyan"))
    file_console.print()

    # Failed hosts section
    failed_hosts = [(h, r) for h, r in hosts.items() if any(row.get("type") == "FAILURE" for row in r)]
    if failed_hosts:
        failed_table = Table(
            border_style="dim",
            show_header=True,
            header_style="bold white",
            box=None,
        )
        failed_table.add_column("Hostname", style="white")
        failed_table.add_column("Error", style="red")

        for host, rows in failed_hosts:
            failure = next((r for r in rows if r.get("type") == "FAILURE"), None)
            if failure:
                failed_table.add_row(host, failure.get("reason", "Unknown error"))

        file_console.print(Panel(failed_table, title="[bold]FAILED HOSTS[/]", border_style="red"))
        file_console.print()

    # Footer with output location info
    file_console.print("[dim]Task details are in per-host subdirectories (host/tasks.txt)[/]")
    file_console.print()

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(buffer.getvalue())


def _write_host_tasks_file(path: str, host: str, rows: list[dict], force_color: bool):
    """Write tasks.txt for a single host."""
    buffer = StringIO()
    file_console = Console(file=buffer, force_terminal=force_color, width=120)

    # Sort rows: TIER-0 first, then PRIV, then TASK
    type_order = {"TIER-0": 0, "PRIV": 1, "TASK": 2, "FAILURE": 3}
    sorted_rows = sorted(rows, key=lambda r: type_order.get(r.get("type", "TASK"), 2))

    # Write header
    file_console.print(f"\n[bold cyan]═══ TaskHound Results: {host} ═══[/]\n")

    # Count tasks by type
    tier0_count = sum(1 for r in rows if r.get("type") == "TIER-0")
    priv_count = sum(1 for r in rows if r.get("type") == "PRIV")
    task_count = sum(1 for r in rows if r.get("type") == "TASK")

    file_console.print(f"[dim]TIER-0: {tier0_count} | PRIV: {priv_count} | TASK: {task_count}[/]\n")

    # Write each task as a table
    for row_dict in sorted_rows:
        if row_dict.get("type") == "FAILURE":
            file_console.print(f"[red][-] FAILURE: {row_dict.get('reason', 'Unknown error')}[/]\n")
            continue

        table = _format_task_table(row_dict)
        file_console.print(table)
        file_console.print()

    # Write to file
    with open(path, "w", encoding="utf-8") as f:
        f.write(buffer.getvalue())


def write_json(path: str, rows: list[Any], silent: bool = False):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_rows_to_dicts(rows), f, indent=2)
    if not silent:
        good(f"Wrote JSON results to {path}")


def write_combined_json(
    path: str,
    task_rows: list[Any],
    service_rows: list[Any],
    silent: bool = False,
):
    """Write combined JSON with separate 'tasks' and 'services' keys."""
    data = {
        "tasks": _rows_to_dicts(task_rows),
        "services": _rows_to_dicts(service_rows),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    if not silent:
        good(f"Wrote combined JSON results to {path}")


_TASK_CSV_FIELDS = [
    "host",
    "target_ip",
    "computer_sid",
    "path",
    "type",
    "runas",
    "resolved_runas",
    "command",
    "arguments",
    "author",
    "date",
    "logon_type",
    "enabled",
    "trigger_type",
    "start_boundary",
    "interval",
    "duration",
    "days_interval",
    "reason",
    "credentials_hint",
    "credential_guard",
    "password_analysis",
    "cred_status",
    "cred_password_valid",
    "cred_hijackable",
    "cred_last_run",
    "cred_return_code",
    "cred_detail",
    "decrypted_password",
]

_SERVICE_CSV_FIELDS = [
    "host",
    "target_ip",
    "computer_sid",
    "service_name",
    "display_name",
    "type",
    "start_name",
    "resolved_runas",
    "binary_path",
    "start_type",
    "service_type",
    "state",
    "is_gmsa",
    "is_disabled_account",
    "reason",
    "credential_guard",
    "password_analysis",
    "decrypted_password",
    "lsa_secret_name",
]


def write_csv(path: str, rows: list[Any]):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=_TASK_CSV_FIELDS)
        w.writeheader()
        w.writerows(_rows_to_dicts(rows))
    good(f"Wrote CSV results to {path}")


def write_service_csv(path: str, rows: list[Any]):
    """Write service results to a CSV file."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=_SERVICE_CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(_rows_to_dicts(rows))
    good(f"Wrote service CSV results to {path}")
