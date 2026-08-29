# LAPS Helper Functions

from ..utils.logging import warn
from .exceptions import LAPS_ERRORS
from .models import LAPSCache, LAPSCredential, LAPSFailure

# =============================================================================
# Helper Functions
# =============================================================================


def get_laps_credential_for_host(
    cache: LAPSCache, hostname: str
) -> tuple[LAPSCredential | None, LAPSFailure | None]:
    """
    Lookup LAPS credential for a hostname with failure tracking.

    Args:
        cache: LAPSCache to search
        hostname: Target hostname (short name, FQDN, or resolved from IP)

    Returns:
        Tuple of (credential, failure) - one will be None
    """
    cred = cache.get(hostname)

    if cred is None:
        failure = LAPSFailure(
            hostname=hostname,
            failure_type="not_found",
            message=LAPS_ERRORS["host_not_found"].format(hostname=hostname),
        )
        return None, failure

    if cred.encrypted:
        failure = LAPSFailure(
            hostname=hostname,
            failure_type="encrypted",
            message=LAPS_ERRORS["encrypted"].format(hostname=hostname),
            laps_type_tried=cred.laps_type,
        )
        return None, failure

    if cred.is_expired():
        warn(f"LAPS: Password for {hostname} may be expired (expiration: {cred.expiration})", verbose_only=True)
        # Still return the credential - it might work if rotation hasn't happened yet

    return cred, None


def print_laps_summary(
    cache: LAPSCache,
    successes: int,
    failures: list[LAPSFailure],
) -> None:
    """
    Print LAPS authentication summary.

    Args:
        cache: LAPSCache that was used
        successes: Number of successful LAPS authentications
        failures: List of LAPS failures
    """
    from rich.console import Console
    from rich.panel import Panel

    console = Console(highlight=False)
    stats = cache.get_statistics()

    # Build statistics content
    lines = [f"Total LAPS entries loaded : [bold]{stats['total']}[/]"]
    if stats["mslaps"] > 0:
        lines.append(f"  - Windows LAPS          : {stats['mslaps']}")
    if stats["legacy"] > 0:
        lines.append(f"  - Legacy LAPS           : {stats['legacy']}")
    if stats["encrypted"] > 0:
        lines.append(f"  - Encrypted (skipped)   : {stats['encrypted']}")

    lines.append("")
    lines.append("[bold]LAPS Auth Results:[/]")
    lines.append(f"  [green][+][/] Successful            : [bold]{successes}[/]")

    # Group failures by type
    failure_counts: dict[str, int] = {}
    for f in failures:
        failure_counts[f.failure_type] = failure_counts.get(f.failure_type, 0) + 1

    failure_labels = {
        "not_found": "No password in cache",
        "auth_failed": "Auth failed",
        "remote_uac": "Remote UAC blocked",
        "encrypted": "Encrypted (unsupported)",
    }

    for ftype, count in failure_counts.items():
        label = failure_labels.get(ftype, ftype)
        lines.append(f"  [red][-][/] {label:21} : [bold]{count}[/]")

    console.print()
    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]LAPS STATISTICS[/]",
            border_style="cyan",
        )
    )
