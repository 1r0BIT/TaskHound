# Rich-based console for thread-safe, colored terminal output.
#
# This module provides a centralized console for all TaskHound output,
# with proper handling for multi-threaded async scanning.
#
# Features:
# - Thread-safe output (no interleaving)
# - Colored status messages
# - Live progress bar for async scanning
# - Rich tables for summary output

import threading
from contextlib import contextmanager

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

# Global console instance - thread-safe by default
console = Console(highlight=False)

# Lock for complex multi-line output
_output_lock = threading.RLock()

# Global progress context for async scanning
_progress: Progress | None = None
_progress_task_id: int | None = None
_live: Live | None = None


# =============================================================================
# Banner
# =============================================================================

# TaskHound purple - matches BloodHound custom icon color
TASKHOUND_PURPLE = "#8B5CF6"

BANNER_ART = f"""
[bold {TASKHOUND_PURPLE}]TTTTT  AAA   SSS  K   K H   H  OOO  U   U N   N DDDD[/]
[bold {TASKHOUND_PURPLE}]  T   A   A S     K  K  H   H O   O U   U NN  N D   D[/]
[bold {TASKHOUND_PURPLE}]  T   AAAAA  SSS  KKK   HHHHH O   O U   U N N N D   D[/]
[bold {TASKHOUND_PURPLE}]  T   A   A     S K  K  H   H O   O U   U N  NN D   D[/]
[bold {TASKHOUND_PURPLE}]  T   A   A SSSS  K   K H   H  OOO   UUU  N   N DDDD[/]

                     [dim]by[/] [bold white]0xr0BIT[/]
"""


def print_banner():
    """Print the colored TaskHound banner."""
    console.print(BANNER_ART)


# =============================================================================
# Status Messages (thread-safe)
# =============================================================================

def status(msg: str):
    """Print a status message (always visible). Thread-safe."""
    with _output_lock:
        console.print(msg)


def good(msg: str, verbose_only: bool = False):
    """Print a success message in green. Thread-safe."""
    if verbose_only and not _is_verbose():
        return
    with _output_lock:
        console.print(f"[green][+][/] {msg}")


def warn(msg: str, verbose_only: bool = False):
    """Print a warning message in yellow. Thread-safe.

    Args:
        msg: Message to print
        verbose_only: If True, only print in verbose mode
    """
    if verbose_only and not _is_verbose():
        return
    with _output_lock:
        console.print(f"[yellow][!][/] {msg}")


def error(msg: str):
    """Print an error message in red. Thread-safe."""
    with _output_lock:
        console.print(f"[red][-][/] {msg}")


def info(msg: str, verbose_only: bool = False):
    """Print an info message in blue. Thread-safe."""
    if verbose_only and not _is_verbose():
        return
    with _output_lock:
        console.print(f"[blue][*][/] {msg}")


def debug(msg: str, exc_info: bool = False):
    """Print a debug message in dim text. Thread-safe."""
    if not _is_debug():
        return
    with _output_lock:
        console.print(f"[dim][DEBUG][/] {msg}")
        if exc_info:
            console.print_exception()


# =============================================================================
# Verbosity Control
# =============================================================================

_VERBOSE = False
_DEBUG = False


def set_verbosity(verbose: bool, debug: bool):
    """Set verbosity levels."""
    global _VERBOSE, _DEBUG
    _VERBOSE = verbose
    _DEBUG = debug


def _is_verbose() -> bool:
    return _VERBOSE or _DEBUG


def _is_debug() -> bool:
    return _DEBUG


# =============================================================================
# Progress Bar for Async Scanning
# =============================================================================

@contextmanager
def scan_progress(total: int, description: str = "Scanning"):
    """
    Context manager for showing a progress bar during async scanning.

    Usage:
        with scan_progress(len(targets), "Scanning targets") as update:
            for target in targets:
                process(target)
                update(target)  # Updates progress and shows current target

    Args:
        total: Total number of items to process
        description: Description shown in progress bar

    Yields:
        update function that takes (current_item, success=True, error_msg=None)
    """
    global _progress, _progress_task_id, _live

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[status]}"),
        console=console,
        transient=False,
    )

    task_id = progress.add_task(description, total=total, status="")

    # Track statistics
    stats = {"success": 0, "failed": 0}

    def update(item: str, success: bool = True, error_msg: str | None = None):
        """Update progress with current item status."""
        if success:
            stats["success"] += 1
            status_text = f"[green][+][/] {item}"
        else:
            stats["failed"] += 1
            status_text = f"[red][-][/] {item}: {error_msg[:30]}" if error_msg else f"[red][-][/] {item}"

        progress.update(task_id, advance=1, status=status_text)

    _progress = progress
    _progress_task_id = task_id

    try:
        with progress:
            yield update
    finally:
        _progress = None
        _progress_task_id = None

        # Print summary after progress completes
        total_done = stats["success"] + stats["failed"]
        if stats["failed"] > 0:
            console.print(
                f"\n[green][+] {stats['success']}[/] succeeded, "
                f"[red][-] {stats['failed']}[/] failed out of {total_done} targets"
            )


@contextmanager
def spinner(description: str = "Processing"):
    """
    Context manager for showing an indeterminate spinner during long operations.

    Use for operations where we don't know the total progress (e.g., API calls,
    waiting for remote processing).

    Example:
        with spinner("Uploading to BloodHound"):
            upload_data()
            wait_for_processing()

    Args:
        description: Text to show next to the spinner
    """
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,  # Remove when done
    )

    progress.add_task(description, total=None)  # None = indeterminate

    try:
        with progress:
            yield
    finally:
        pass  # Spinner removed automatically (transient=True)


# =============================================================================
# Summary Table
# =============================================================================

def print_summary_table(
    host_stats: dict,
    has_hv_data: bool = False,
    has_tier0_detection: bool = False,
):
    """
    Print a rich summary table with host statistics.

    Shows successful hosts first with task counts, then failed hosts in a separate table.

    Args:
        host_stats: Dict of {hostname: {tier0, privileged, normal, status, failure_reason}}
        has_hv_data: Whether high-value data was loaded (deprecated, use has_tier0_detection)
        has_tier0_detection: Whether tier-0 detection was enabled
    """
    # Support both old and new parameter names
    has_hv = has_hv_data or has_tier0_detection

    if not host_stats:
        return

    # Separate successful and failed hosts
    success_hosts = {}
    failed_hosts = {}
    for host, stats in host_stats.items():
        if stats["status"] == "[+]":
            success_hosts[host] = stats
        else:
            failed_hosts[host] = stats

    total_tier0 = 0
    total_priv = 0
    total_normal = 0
    total_services = 0

    # Check if any host has service data
    has_services = any(stats.get("services", 0) > 0 for stats in host_stats.values())

    # Print successful hosts table
    if success_hosts:
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            box=None,
        )

        table.add_column("Hostname", style="white", no_wrap=True)
        table.add_column("Tier-0", justify="center", style="red")
        table.add_column("Privileged", justify="center", style="yellow")
        table.add_column("Normal", justify="center", style="green")
        if has_services:
            table.add_column("Services", justify="center", style="cyan")

        for host in sorted(success_hosts.keys()):
            stats = success_hosts[host]
            tier0 = str(stats["tier0"]) if has_hv else "N/A"
            priv = str(stats["privileged"]) if has_hv else "N/A"
            normal = str(stats["normal"])

            total_tier0 += stats["tier0"]
            total_priv += stats["privileged"]
            total_normal += stats["normal"]
            total_services += stats.get("services", 0)

            row_values = [host, tier0, priv, normal]
            if has_services:
                row_values.append(str(stats.get("services", 0)))
            table.add_row(*row_values)

        # Add totals row if multiple hosts
        if len(success_hosts) > 1:
            table.add_section()
            tier0_total = str(total_tier0) if has_hv else "N/A"
            priv_total = str(total_priv) if has_hv else "N/A"
            row_values = [
                "[bold]TOTAL[/]",
                f"[bold]{tier0_total}[/]",
                f"[bold]{priv_total}[/]",
                f"[bold]{total_normal}[/]",
            ]
            if has_services:
                row_values.append(f"[bold]{total_services}[/]")
            table.add_row(*row_values)

        panel_title = "[bold]TASK & SERVICE SUMMARY[/]" if has_services else "[bold]TASK SUMMARY[/]"
        console.print()
        console.print(
            Panel(
                table,
                title=panel_title,
                border_style="cyan",
            )
        )

    # Print failed hosts table
    if failed_hosts:
        fail_table = Table(
            show_header=True,
            header_style="bold red",
            border_style="dim red",
            box=None,
        )

        fail_table.add_column("Hostname", style="white", no_wrap=True)
        fail_table.add_column("Reason", style="dim")

        for host in sorted(failed_hosts.keys()):
            stats = failed_hosts[host]
            reason = stats.get("failure_reason", "Unknown error")
            if len(reason) > 60:
                reason = reason[:57] + "..."
            fail_table.add_row(host, reason)

        console.print()
        console.print(
            Panel(
                fail_table,
                title=f"[bold red]FAILED HOSTS ({len(failed_hosts)})[/]",
                border_style="red",
            )
        )

    console.print()

    # Additional hints
    if not has_hv and success_hosts:
        console.print(
            "[dim]Note: Tier-0/Privileged detection requires --bh-data, --bh-live, or --ldap-tier0[/]"
        )


# =============================================================================
# Scan Complete Summary
# =============================================================================

def print_scan_complete(
    succeeded: int,
    failed: int,
    total_time: float,
    avg_time_ms: float,
    skipped: int = 0,
):
    """Print scan completion summary."""
    console.print()

    # Build the content lines
    content_lines = [
        f"  [green][+][/] Succeeded: [bold]{succeeded}[/]",
    ]

    if skipped > 0:
        content_lines.append(f"  [yellow][~][/] Skipped: [bold]{skipped}[/] [dim](dual-homed)[/]")

    content_lines.extend([
        f"  [red][-][/] Failed: [bold]{failed}[/]",
        f"  [dim]Total time: {total_time:.2f}s[/]",
        f"  [dim]Avg per target: {avg_time_ms:.0f}ms[/]",
    ])

    console.print(
        Panel(
            "\n".join(content_lines),
            title="[bold]SCAN COMPLETE[/]",
            border_style="green" if failed == 0 else "yellow",
        )
    )


# =============================================================================
# Task Output Formatting
# =============================================================================

def format_task_line(
    task_name: str,
    run_as: str,
    is_tier0: bool = False,
    is_privileged: bool = False,
    command: str | None = None,
) -> str:
    """Format a single task line with colors."""
    if is_tier0:
        prefix = "[bold red][TIER-0][/]"
    elif is_privileged:
        prefix = "[yellow][PRIV][/]"
    else:
        prefix = "[dim][TASK][/]"

    line = f"{prefix} {task_name} [dim]→[/] {run_as}"

    if command:
        # Truncate long commands
        if len(command) > 60:
            command = command[:57] + "..."
        line += f"\n        [dim]{command}[/]"

    return line


# =============================================================================
# Output Section Panels
# =============================================================================

def print_backup_section(backup_dir: str):
    """Print backup directory info in a styled panel."""
    console.print()
    console.print(
        Panel(
            f"[green][+][/] Raw XML files saved to: [bold]{backup_dir}[/]",
            title="[bold]XML BACKUP[/]",
            border_style="dim",
        )
    )


def print_audit_report_section(report_path: str):
    """Print audit report section in a styled panel."""
    console.print()
    console.print(
        Panel(
            f"[green][+][/] Audit report generated: [bold]{report_path}[/]\n"
            f"[dim][*] Open in a browser to view the report[/]",
            title="[bold]AUDIT REPORT[/]",
            border_style="cyan",
        )
    )


def print_opengraph_section(json_path: str, uploaded: bool = False, node_count: int = 0, edge_count: int = 0):
    """Print OpenGraph output section in a styled panel."""
    console.print()

    if uploaded:
        content = (
            f"[green][+][/] Generated {node_count} nodes, {edge_count} edges\n"
            f"[green][+][/] Uploaded to BloodHound successfully\n"
            f"[dim][*] JSON saved to: {json_path}[/]"
        )
        border_style = "green"
    else:
        content = f"[green][+][/] JSON saved to: [bold]{json_path}[/]"
        border_style = "dim"

    console.print(
        Panel(
            content,
            title="[bold]BLOODHOUND OPENGRAPH[/]",
            border_style=border_style,
        )
    )
