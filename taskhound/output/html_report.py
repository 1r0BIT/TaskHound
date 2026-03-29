"""
TaskHound HTML Security Audit Report Generator.

Generates comprehensive HTML security audit reports from scheduled task scan results.
Provides severity scoring, risk assessment, and actionable recommendations.
"""

import html
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class SeverityScore:
    """Severity assessment for a scheduled task finding."""

    level: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    score: int  # 0-100 numeric score
    factors: list[str]  # Contributing risk factors

    @property
    def css_class(self) -> str:
        """Return CSS class for this severity level."""
        return f"severity-{self.level.lower()}"

    @property
    def badge_color(self) -> str:
        """Return badge color for this severity level."""
        colors = {
            "CRITICAL": "#dc2626",  # Red
            "HIGH": "#ea580c",  # Orange
            "MEDIUM": "#ca8a04",  # Yellow
            "LOW": "#2563eb",  # Blue
            "INFO": "#6b7280",  # Gray
        }
        return colors.get(self.level, "#6b7280")


def _get_row_value(row: Any, key: str, default: Any = "") -> Any:
    """Get a value from a row, supporting both dicts and objects with attributes."""
    if isinstance(row, dict):
        return row.get(key, default)
    return getattr(row, key, default)


# Module-level domain context for username normalization.
# Set by generate_html_report() before any processing.
_report_netbios_domain: str | None = None


def _extract_sam_from_any_format(username: str) -> str:
    """Extract bare samaccountname from any format.

    Handles: DOMAIN\\user, user@domain.fqdn, bare user, SIDs.
    Returns lowercase bare sam (or the original if SID/empty).
    """
    if not username:
        return ""
    u = username.strip()
    if u.upper().startswith("S-1-"):
        return u
    if "\\" in u:
        return u.rsplit("\\", 1)[1].lower()
    if "@" in u:
        return u.split("@", 1)[0].lower()
    return u.lower()


def _normalize_username(username: str) -> str:
    """Normalize a username to NETBIOS\\sam format for deduplication.

    Uses _report_netbios_domain (set from scan domain) when available.
    All of DOMAIN\\user, user@domain.fqdn, and bare user normalize to
    the same key: NETBIOS\\sam (lowercase).
    """
    if not username:
        return ""
    u = username.strip()
    if u.upper().startswith("S-1-"):
        return u

    sam = _extract_sam_from_any_format(u)
    if not sam:
        return u.lower()

    # If the original had a domain qualifier, or we have a known netbios domain,
    # normalize to netbios\\sam
    has_domain = "\\" in u or "@" in u
    if has_domain or _report_netbios_domain:
        # Extract domain from the username itself if present
        if "\\" in u:
            domain_part = u.split("\\", 1)[0].upper()
        elif "@" in u:
            # UPN — derive netbios from FQDN domain part (first component)
            fqdn_domain = u.split("@", 1)[1]
            domain_part = fqdn_domain.split(".")[0].upper() if "." in fqdn_domain else fqdn_domain.upper()
        elif _report_netbios_domain:
            domain_part = _report_netbios_domain.upper()
        else:
            return sam
        return f"{domain_part}\\{sam}"

    return sam


def _get_canonical_username(username: str, seen_usernames: dict[str, str]) -> str:
    """Get the canonical display form (NETBIOS\\Username), deduplicating variations.

    All variations of the same account (DOMAIN\\user, user@domain, bare user)
    resolve to a single NETBIOS\\Username entry.
    """
    if not username:
        return ""

    normalized = _normalize_username(username)
    if not normalized or normalized.upper().startswith("S-1-"):
        return username

    if normalized in seen_usernames:
        return seen_usernames[normalized]

    # Check if we've seen the same sam under a different domain key
    sam = _extract_sam_from_any_format(username)
    for seen_norm, seen_display in seen_usernames.items():
        if _extract_sam_from_any_format(seen_norm) == sam:
            # Same user — prefer the version with domain prefix
            if "\\" in normalized and "\\" not in seen_norm:
                # New one has domain, old didn't — upgrade
                del seen_usernames[seen_norm]
                break
            else:
                return seen_display

    # Build display form: NETBIOS\Username (preserve original sam casing)
    original_sam = _extract_sam_from_any_format(username)
    # Restore original casing by finding sam in the raw username
    u = username.strip()
    if "\\" in u:
        original_sam = u.rsplit("\\", 1)[1]
    elif "@" in u:
        original_sam = u.split("@", 1)[0]
    else:
        original_sam = u

    if "\\" in normalized:
        domain_part = normalized.split("\\", 1)[0].upper()
        display = f"{domain_part}\\{original_sam}"
    else:
        display = username

    seen_usernames[normalized] = display
    return display


def _normalize_account_display(account: str) -> str:
    """Normalize an account name to NETBIOS\\Sam for display.

    Standalone version (no dedup dict needed). Uses _report_netbios_domain
    context. Strips SID suffixes like '(S-1-5-...)' and collapses all
    formats (UPN, downlevel, bare) to NETBIOS\\Sam.
    """
    if not account:
        return account

    # Strip trailing SID suffix like " (S-1-5-21-...)"
    clean = account.strip()
    if " (S-1-5-" in clean:
        clean = clean[:clean.index(" (S-1-5-")].strip()

    if clean.upper().startswith("S-1-"):
        return clean

    # Extract original-cased sam
    if "\\" in clean:
        original_sam = clean.rsplit("\\", 1)[1]
    elif "@" in clean:
        original_sam = clean.split("@", 1)[0]
    else:
        original_sam = clean

    # Build NETBIOS\Sam
    normalized = _normalize_username(clean)
    if "\\" in normalized:
        domain_part = normalized.split("\\", 1)[0].upper()
        return f"{domain_part}\\{original_sam}"

    return clean


def calculate_severity(row: Any) -> SeverityScore:
    """
    Determine severity level for a scheduled task finding using categorical rules.

    Severity Matrix:
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │ Account Type │ Stored Creds │ Credential Status      │ Severity            │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │ TIER-0       │ Yes          │ Valid                  │ CRITICAL            │
    │ TIER-0       │ Yes          │ Outdated/Unconfirmed   │ HIGH                │
    │ TIER-0       │ Yes          │ Credential Guard       │ HIGH                │
    │ TIER-0       │ No           │ -                      │ MEDIUM              │
    │ PRIV         │ Yes          │ Valid                  │ HIGH                │
    │ PRIV         │ Yes          │ Outdated/Unconfirmed   │ MEDIUM              │
    │ PRIV         │ Yes          │ Credential Guard       │ MEDIUM              │
    │ PRIV         │ No           │ -                      │ LOW                 │
    │ TASK         │ Yes          │ Any                    │ LOW                 │
    │ TASK         │ No           │ -                      │ INFO                │
    │ FAILURE      │ -            │ -                      │ INFO                │
    └─────────────────────────────────────────────────────────────────────────────┘
    """
    factors = []

    # Get task type
    task_type = str(_get_row_value(row, "type", "")).upper()

    # Handle connection failures immediately
    if task_type == "FAILURE":
        return SeverityScore(level="INFO", score=0, factors=["Connection failed"])

    # Detect service rows (service_name only exists on ServiceRow)
    is_service = bool(_get_row_value(row, "service_name", ""))

    # Check for stored credentials
    if is_service:
        # Services always store credentials as LSA secrets
        has_stored_creds = True
    else:
        creds_hint = str(_get_row_value(row, "credentials_hint", "")).lower()
        has_stored_creds = "stored" in creds_hint or "password" in creds_hint

    # Check credential status
    cred_valid = _get_row_value(row, "cred_password_valid", None)
    cred_status = str(_get_row_value(row, "cred_status", "")).lower()
    cred_guard = _get_row_value(row, "credential_guard", None)

    # For services, use decrypted_password presence as proxy for credential validation
    if is_service and cred_valid is None:
        decrypted_pw = _get_row_value(row, "decrypted_password", "")
        if decrypted_pw and decrypted_pw not in ("N/A", "", "-"):
            cred_valid = True

    # Check if account is disabled (indicated in reason field)
    reason = str(_get_row_value(row, "reason", ""))
    account_disabled = "[ACCOUNT DISABLED]" in reason
    # Also check is_disabled_account flag (ServiceRow)
    if _get_row_value(row, "is_disabled_account", False):
        account_disabled = True

    # Determine credential state
    is_valid = cred_valid is True
    is_outdated = cred_status == "invalid" or cred_valid is False
    is_protected = cred_guard is True

    # Build factors list
    if task_type == "TIER-0":
        factors.append("Tier-0 privileged account")
    elif task_type == "PRIV":
        factors.append("Privileged account")
    elif task_type == "SERVICE":
        factors.append("Standard service")
    elif task_type == "TASK":
        factors.append("Standard task")

    # Add account disabled indicator (before credential factors)
    if account_disabled:
        factors.append("Account currently disabled in AD")

    if has_stored_creds:
        if is_service:
            factors.append("LSA secret stored")
        else:
            factors.append("Credentials stored (DPAPI)")
    if is_valid:
        factors.append("Password confirmed valid")
    if is_outdated:
        factors.append("Password outdated/invalid")
    if is_protected:
        factors.append("Credential Guard enabled")

    # Apply severity matrix
    if task_type == "TIER-0":
        if has_stored_creds:
            if is_valid:
                level = "CRITICAL"
            elif is_protected:
                level = "HIGH"
            else:  # Outdated or unconfirmed
                level = "HIGH"
        else:
            level = "MEDIUM"

    elif task_type == "PRIV":
        if has_stored_creds:
            if is_valid:
                level = "HIGH"
            elif is_protected:
                level = "MEDIUM"
            else:  # Outdated or unconfirmed
                level = "MEDIUM"
        else:
            level = "LOW"

    elif task_type in ("TASK", "SERVICE"):
        level = "LOW" if has_stored_creds else "INFO"

    else:
        # Unknown task type
        level = "INFO"

    return SeverityScore(level=level, score=0, factors=factors)


@dataclass
class AuditStatistics:
    """Aggregated statistics for the security audit report."""

    total_hosts: int = 0
    total_tasks: int = 0
    hosts_with_findings: int = 0

    # Severity counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Task type counts
    tier0_count: int = 0
    priv_count: int = 0
    task_count: int = 0

    # Service counts
    total_services: int = 0
    service_tier0_count: int = 0
    service_priv_count: int = 0

    # Credential counts
    stored_creds_count: int = 0
    decrypted_count: int = 0
    valid_creds_count: int = 0

    # Account tracking
    unique_accounts: int = 0
    tier0_accounts: list = field(default_factory=list)

    # Failure tracking
    failures: list = field(default_factory=list)

    @property
    def overall_risk(self) -> str:
        """Determine overall risk level based on findings."""
        if self.critical_count > 0 or self.decrypted_count > 0:
            return "CRITICAL"
        elif self.high_count > 0 or self.tier0_count > 0:
            return "HIGH"
        elif self.medium_count > 0:
            return "MEDIUM"
        elif self.low_count > 0:
            return "LOW"
        else:
            return "INFO"

    @property
    def failure_count(self) -> int:
        """Return count of connection failures."""
        return len(self.failures)


def calculate_statistics(rows: list[Any], service_rows: list[Any] | None = None) -> AuditStatistics:
    """
    Calculate aggregated statistics from scan results.

    Args:
        rows: List of task dictionaries or TaskRow objects from scan results
        service_rows: Optional list of ServiceRow objects for service findings

    Returns:
        AuditStatistics with calculated values
    """
    hosts_seen = set()
    hosts_with_findings = set()
    unique_accounts_seen: dict[str, str] = {}  # normalized -> canonical display form
    tier0_accounts_seen: dict[str, str] = {}   # normalized -> canonical display form
    failures = []

    # Counters
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0
    tier0_count = 0
    priv_count = 0
    task_count = 0
    stored_creds_count = 0
    decrypted_count = 0
    valid_creds_count = 0

    # Service counters
    total_services = 0
    service_tier0_count = 0
    service_priv_count = 0

    for row in rows:
        host = _get_row_value(row, "host", "")
        task_type = str(_get_row_value(row, "type", "")).upper()

        # Handle FAILURE rows separately
        if task_type == "FAILURE":
            reason = _get_row_value(row, "reason", "Connection failed")
            failures.append({"host": host, "error": str(reason)})
            continue

        # Track hosts
        if host:
            hosts_seen.add(host)

        # Track accounts - prefer resolved name over SID, deduplicate variations
        runas_raw = _get_row_value(row, "runas", "")
        resolved_runas = _get_row_value(row, "resolved_runas", "")
        runas = resolved_runas if resolved_runas else runas_raw
        if runas and not runas.startswith("S-1-"):
            _get_canonical_username(runas, unique_accounts_seen)

        # Task type counts
        if task_type == "TIER-0":
            tier0_count += 1
            if runas and not runas.startswith("S-1-"):
                _get_canonical_username(runas, tier0_accounts_seen)
        elif task_type == "PRIV":
            priv_count += 1
        else:
            task_count += 1

        # Stored credentials
        creds_hint = str(_get_row_value(row, "credentials_hint", "")).lower()
        if "stored" in creds_hint:
            stored_creds_count += 1
            if host:
                hosts_with_findings.add(host)

        # Decrypted passwords
        decrypted = _get_row_value(row, "decrypted_password", "")
        if decrypted and decrypted not in ("N/A", "", "-"):
            decrypted_count += 1

        # Valid credentials
        cred_valid = _get_row_value(row, "cred_password_valid", None)
        if cred_valid is True:
            valid_creds_count += 1

        # Calculate severity and count
        severity = calculate_severity(row)
        if severity.level == "CRITICAL":
            critical_count += 1
        elif severity.level == "HIGH":
            high_count += 1
        elif severity.level == "MEDIUM":
            medium_count += 1
        elif severity.level == "LOW":
            low_count += 1
        else:
            info_count += 1

    # Process service rows
    for svc_row in service_rows or []:
        svc_type = str(_get_row_value(svc_row, "type", "")).upper()

        if svc_type in ("FAILURE", "SKIPPED"):
            continue

        total_services += 1

        host = _get_row_value(svc_row, "host", "")
        if host:
            hosts_seen.add(host)
            hosts_with_findings.add(host)

        # Track service accounts — use start_name (ServiceRow) or runas
        runas_raw = _get_row_value(svc_row, "start_name", "") or _get_row_value(svc_row, "runas", "")
        resolved_runas = _get_row_value(svc_row, "resolved_runas", "")
        runas = resolved_runas if resolved_runas else runas_raw
        if runas and not runas.startswith("S-1-"):
            _get_canonical_username(runas, unique_accounts_seen)

        # Service type counts
        if svc_type == "TIER-0":
            service_tier0_count += 1
            if runas and not runas.startswith("S-1-"):
                _get_canonical_username(runas, tier0_accounts_seen)
        elif svc_type == "PRIV":
            service_priv_count += 1

        # Services always have stored credentials (LSA secrets)
        stored_creds_count += 1

        # Decrypted passwords
        decrypted = _get_row_value(svc_row, "decrypted_password", "")
        if decrypted and decrypted not in ("N/A", "", "-"):
            decrypted_count += 1

        # Calculate severity and count
        severity = calculate_severity(svc_row)
        if severity.level == "CRITICAL":
            critical_count += 1
        elif severity.level == "HIGH":
            high_count += 1
        elif severity.level == "MEDIUM":
            medium_count += 1
        elif severity.level == "LOW":
            low_count += 1
        else:
            info_count += 1

    total_tasks = tier0_count + priv_count + task_count

    return AuditStatistics(
        total_hosts=len(hosts_seen),
        total_tasks=total_tasks,
        hosts_with_findings=len(hosts_with_findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        tier0_count=tier0_count,
        priv_count=priv_count,
        task_count=task_count,
        total_services=total_services,
        service_tier0_count=service_tier0_count,
        service_priv_count=service_priv_count,
        stored_creds_count=stored_creds_count,
        decrypted_count=decrypted_count,
        valid_creds_count=valid_creds_count,
        unique_accounts=len(unique_accounts_seen),
        tier0_accounts=list(tier0_accounts_seen.values()),
        failures=failures,
    )


def generate_audit_summary(
    rows: list[Any],
    service_rows: list[Any] | None = None,
) -> tuple[AuditStatistics, list[tuple[SeverityScore, Any, str]]]:
    """
    Generate audit summary with statistics and sorted findings.

    Args:
        rows: List of task dictionaries or TaskRow objects
        service_rows: Optional list of ServiceRow objects for service findings

    Returns:
        Tuple of (AuditStatistics, list of (SeverityScore, row, kind) tuples sorted by severity)
        where kind is "task" or "service"
    """
    stats = calculate_statistics(rows, service_rows=service_rows)

    # Calculate severity for each non-failure row and sort
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    findings: list[tuple[SeverityScore, Any, str]] = []

    for row in rows:
        task_type = str(_get_row_value(row, "type", "")).upper()
        if task_type == "FAILURE":
            continue
        severity = calculate_severity(row)
        findings.append((severity, row, "task"))

    for svc_row in service_rows or []:
        svc_type = str(_get_row_value(svc_row, "type", "")).upper()
        if svc_type in ("FAILURE", "SKIPPED"):
            continue
        severity = calculate_severity(svc_row)
        findings.append((severity, svc_row, "service"))

    # Sort by severity level descending
    findings.sort(key=lambda x: -severity_order.get(x[0].level, 0))

    return stats, findings


# HTML Template - Professional dark theme with muted colors
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TaskHound Security Audit Report</title>
    <style>
        :root {
            --bg-primary: #111827;
            --bg-secondary: #1f2937;
            --bg-card: #374151;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --accent: #6366f1;
            --accent-light: #818cf8;
            --severity-critical: #991b1b;
            --severity-critical-bg: rgba(153, 27, 27, 0.15);
            --severity-high: #9a3412;
            --severity-high-bg: rgba(154, 52, 18, 0.15);
            --severity-medium: #854d0e;
            --severity-medium-bg: rgba(133, 77, 14, 0.15);
            --severity-low: #1e40af;
            --severity-low-bg: rgba(30, 64, 175, 0.15);
            --severity-info: #4b5563;
            --success: #166534;
            --success-light: #22c55e;
            --failure: #991b1b;
            --failure-light: #ef4444;
            --border: #374151;
            --border-light: #4b5563;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.65;
            font-weight: 300;
            font-feature-settings: 'tnum';
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2.5rem;
        }

        /* Header */
        .header {
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: var(--bg-secondary);
            border-radius: 10px;
            border: 1px solid var(--border);
        }

        .header h1 {
            font-size: 2rem;
            color: var(--text-primary);
            margin-bottom: 0.25rem;
            font-weight: 600;
        }

        .header .subtitle {
            color: var(--text-muted);
            font-size: 0.95rem;
        }

        .header .meta {
            margin-top: 1rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .header .meta-grid {
            display: flex;
            justify-content: center;
            gap: 3rem;
            flex-wrap: wrap;
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }

        .header .meta-item {
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .header .meta-value {
            font-size: 1.75rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .header .meta-value.success { color: var(--success-light); }
        .header .meta-value.failure { color: var(--failure-light); }

        .header .meta-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Summary */
        .executive-summary {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }

        .executive-summary h2 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1.1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .risk-banner {
            padding: 1.25rem;
            border-radius: 6px;
            margin-bottom: 1.25rem;
            text-align: center;
        }

        .risk-banner.severity-critical {
            background: transparent;
        }

        .risk-banner.severity-high {
            background: transparent;
        }

        .risk-banner.severity-medium {
            background: transparent;
        }

        .risk-banner.severity-low {
            background: transparent;
        }

        .risk-banner.severity-info {
            background: transparent;
        }

        .risk-banner h3 {
            font-size: 1.25rem;
            margin-bottom: 0.25rem;
            font-weight: 600;
        }

        .risk-banner p {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }

        .stat-card {
            background: var(--bg-card);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
            border: 1px solid var(--border);
        }

        .stat-card:hover {
            border-color: var(--border-light);
        }

        .stat-card .value {
            font-size: 1.75rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .stat-card .label {
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            margin-top: 0.5rem;
        }

        .stat-card.critical .value { color: var(--failure-light); }
        .stat-card.high .value { color: var(--failure-light); }
        .stat-card.medium .value { color: var(--text-secondary); }
        .stat-card.low .value { color: var(--text-secondary); }
        .stat-card.success .value { color: var(--success-light); }

        /* Severity Breakdown - Table Layout */
        .severity-breakdown {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 0.75rem;
            margin-bottom: 1.25rem;
        }

        .severity-badge {
            padding: 1rem;
            border-radius: 6px;
            font-weight: 500;
            font-size: 0.85rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 0.35rem;
            border: 1px solid;
            text-align: center;
        }

        .severity-badge .count {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .severity-badge .label {
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            opacity: 0.85;
        }

        .severity-badge.severity-critical {
            background: var(--severity-critical-bg);
            border-color: var(--severity-critical);
            color: #fca5a5;
        }
        .severity-badge.severity-high {
            background: var(--severity-high-bg);
            border-color: var(--severity-high);
            color: #fdba74;
        }
        .severity-badge.severity-medium {
            background: var(--severity-medium-bg);
            border-color: var(--severity-medium);
            color: #fcd34d;
        }
        .severity-badge.severity-low {
            background: var(--severity-low-bg);
            border-color: var(--severity-low);
            color: #93c5fd;
        }
        .severity-badge.severity-info {
            background: rgba(75, 85, 99, 0.15);
            border-color: var(--severity-info);
            color: var(--text-secondary);
        }

        /* Disclaimer Box */
        .disclaimer {
            background: rgba(99, 102, 241, 0.08);
            border: 1px solid rgba(99, 102, 241, 0.25);
            border-radius: 6px;
            padding: 1rem 1.25rem;
            margin-bottom: 1.5rem;
        }

        .disclaimer-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }

        .disclaimer-header .icon {
            font-size: 1rem;
        }

        .disclaimer-header .title {
            color: var(--accent-light);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }

        .disclaimer p {
            color: var(--text-secondary);
            font-size: 0.85rem;
            line-height: 1.6;
            margin: 0;
        }

        .disclaimer p + p {
            margin-top: 0.5rem;
        }

        /* Classification Reference Section */
        .classification-reference {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }

        .classification-reference h2 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1.1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .classification-reference h3 {
            color: var(--text-primary);
            margin: 1.25rem 0 0.75rem 0;
            font-size: 0.95rem;
            font-weight: 600;
        }

        .classification-reference h3:first-of-type {
            margin-top: 0;
        }

        .classification-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
            font-size: 0.85rem;
        }

        .classification-table th {
            background: var(--bg-card);
            padding: 0.6rem 0.75rem;
            text-align: left;
            font-weight: 500;
            color: var(--text-muted);
            border: 1px solid var(--border);
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.04em;
        }

        .classification-table td {
            padding: 0.6rem 0.75rem;
            border: 1px solid var(--border);
            vertical-align: top;
            color: var(--text-secondary);
        }

        .classification-table tr:hover {
            background: rgba(99, 102, 241, 0.03);
        }

        .impact-list {
            list-style: none;
            margin: 0;
            padding: 0;
        }

        .impact-list li {
            padding: 0.6rem 0.75rem;
            background: var(--bg-card);
            border-radius: 4px;
            margin-bottom: 0.4rem;
            border-left: 3px solid var(--border-light);
            font-size: 0.85rem;
        }

        .impact-list li strong {
            color: var(--text-primary);
            display: block;
            margin-bottom: 0.2rem;
            font-weight: 500;
        }

        .impact-list li p {
            color: var(--text-muted);
            margin: 0;
            font-size: 0.8rem;
        }

        .impact-list li.tier0 { border-left-color: var(--severity-critical); }
        .impact-list li.tier0 strong { color: #fca5a5; }
        .impact-list li.priv { border-left-color: var(--severity-high); }
        .impact-list li.priv strong { color: #fdba74; }
        .impact-list li.stored { border-left-color: var(--severity-medium); }
        .impact-list li.stored strong { color: #fcd34d; }

        /* Tier-0 Warning Box */
        .tier0-warning {
            margin-top: 1.25rem;
            padding: 1rem 1.25rem;
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.25);
            border-radius: 6px;
        }

        .tier0-warning-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.75rem;
        }

        .tier0-warning-header .icon {
            font-size: 1rem;
        }

        .tier0-warning-header .title {
            color: #fca5a5;
            font-weight: 600;
            font-size: 0.9rem;
            letter-spacing: 0.02em;
        }

        .tier0-warning strong {
            color: var(--text-primary);
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.85rem;
        }

        .tier0-accounts-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .tier0-accounts-list li {
            font-family: 'Consolas', 'Monaco', monospace;
            color: var(--text-secondary);
            padding: 0.2rem 0.5rem;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 3px;
            font-size: 0.85rem;
        }

        /* Failures Section - Subtle collapsed style */
        .failures-section {
            margin-top: 1rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
        }

        .failures-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem 1rem;
            cursor: pointer;
            user-select: none;
        }

        .failures-header:hover {
            background: var(--bg-card);
        }

        .failures-header .title {
            color: var(--text-muted);
            font-size: 0.8rem;
            font-weight: 500;
        }

        .failures-header .toggle {
            color: var(--text-muted);
            font-size: 0.75rem;
            transition: transform 0.2s;
        }

        .failures-section.expanded .failures-header .toggle {
            transform: rotate(180deg);
        }

        .failures-content {
            display: none;
            padding: 0 1rem 0.75rem;
            border-top: 1px solid var(--border);
        }

        .failures-section.expanded .failures-content {
            display: block;
        }

        .failure-item {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.35rem 0;
            font-size: 0.8rem;
        }

        .failure-item .host {
            font-family: 'Consolas', 'Monaco', monospace;
            color: var(--text-secondary);
            min-width: 180px;
        }

        .failure-item .error {
            color: var(--text-muted);
        }

        /* Sections */
        .section {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
        }

        .section h2 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1.1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Findings Table */
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }

        .findings-table th {
            background: var(--bg-card);
            padding: 0.75rem 1rem;
            text-align: left;
            font-weight: 500;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.05em;
        }

        .findings-table td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }

        .findings-table tr:hover {
            background: rgba(99, 102, 241, 0.05);
        }

        .findings-table .severity-cell {
            width: 90px;
        }

        .findings-table .severity-pill {
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
            display: inline-block;
            letter-spacing: 0.03em;
            text-align: center;
            min-width: 60px;
        }

        .severity-pill.severity-critical {
            background: var(--severity-critical-bg);
            color: #fca5a5;
            border: 1px solid var(--severity-critical);
        }
        .severity-pill.severity-high {
            background: var(--severity-high-bg);
            color: #fdba74;
            border: 1px solid var(--severity-high);
        }
        .severity-pill.severity-medium {
            background: var(--severity-medium-bg);
            color: #fcd34d;
            border: 1px solid var(--severity-medium);
        }
        .severity-pill.severity-low {
            background: var(--severity-low-bg);
            color: #93c5fd;
            border: 1px solid var(--severity-low);
        }
        .severity-pill.severity-info {
            background: rgba(75, 85, 99, 0.15);
            color: var(--text-secondary);
            border: 1px solid var(--severity-info);
        }

        .task-path {
            font-family: 'Consolas', 'Monaco', monospace;
            color: var(--text-muted);
            font-size: 0.75rem;
            word-break: break-all;
        }

        .runas-account {
            font-weight: 500;
            font-size: 0.85rem;
        }

        .runas-account.tier0 { color: #fca5a5; }
        .runas-account.priv { color: #fdba74; }

        .password-reveal {
            font-family: 'Consolas', 'Monaco', monospace;
            background: rgba(22, 101, 52, 0.2);
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            color: var(--success-light);
            font-size: 0.8rem;
        }

        .factors-list {
            list-style: none;
            margin-top: 0.25rem;
        }

        .factors-list li {
            font-size: 0.75rem;
            color: var(--text-muted);
            padding: 0.1rem 0;
        }

        .factors-list li::before {
            content: "· ";
            color: var(--text-muted);
        }

        /* Recommendations */
        .recommendations {
            list-style: none;
        }

        .recommendations li {
            padding: 0.75rem 1rem;
            background: var(--bg-card);
            border-radius: 4px;
            margin-bottom: 0.5rem;
            border-left: 3px solid var(--border-light);
        }

        .recommendations li.critical { border-left-color: var(--severity-critical); }
        .recommendations li.critical strong { color: #fca5a5; }
        .recommendations li.high { border-left-color: var(--severity-high); }
        .recommendations li.high strong { color: #fdba74; }
        .recommendations li.medium { border-left-color: var(--severity-medium); }
        .recommendations li.medium strong { color: #fcd34d; }

        .recommendations li strong {
            color: var(--text-primary);
            display: block;
            margin-bottom: 0.25rem;
            font-size: 0.9rem;
            font-weight: 500;
        }

        .recommendations li p {
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        /* Host Findings - Collapsible */
        .host-findings-container {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .host-block {
            background: var(--bg-card);
            border-radius: 10px;
            border: 1px solid var(--border);
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
        }

        .host-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem 1rem;
            cursor: pointer;
            user-select: none;
        }

        .host-header:hover {
            background: rgba(99, 102, 241, 0.05);
        }

        .host-header-left {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .host-header h4 {
            font-family: 'Consolas', 'Monaco', monospace;
            color: var(--text-primary);
            font-size: 0.9rem;
            margin: 0;
            font-weight: 500;
        }

        .host-header .host-badges {
            display: flex;
            gap: 0.35rem;
        }

        .host-badge {
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            font-size: 0.65rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }

        .host-badge.tier0 { background: var(--severity-critical-bg); color: #fca5a5; border: 1px solid var(--severity-critical); }
        .host-badge.stored { background: var(--severity-medium-bg); color: #fcd34d; border: 1px solid var(--severity-medium); }
        .host-badge.decrypted { background: rgba(22, 101, 52, 0.2); color: var(--success-light); border: 1px solid var(--success); }
        .host-badge.tasks { background: rgba(99, 102, 241, 0.15); color: var(--accent-light); border: 1px solid var(--accent); }

        .host-header .expand-icon {
            font-size: 0.8rem;
            color: var(--text-muted);
            transition: transform 0.2s;
        }

        .host-block.expanded .host-header .expand-icon {
            transform: rotate(180deg);
        }

        .host-tasks {
            display: none;
            border-top: 1px solid var(--border);
            background: var(--bg-secondary);
        }

        .host-block.expanded .host-tasks {
            display: block;
        }

        .host-task-row {
            display: grid;
            grid-template-columns: 80px 1fr 200px 1fr;
            gap: 1rem;
            padding: 0.6rem 1rem;
            border-bottom: 1px solid var(--border);
            align-items: start;
            font-size: 0.85rem;
        }

        .host-task-row .severity-pill {
            text-align: center;
            min-width: 60px;
        }

        .host-task-row:last-child {
            border-bottom: none;
        }

        .host-task-row:hover {
            background: rgba(99, 102, 241, 0.03);
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 1.5rem;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--border);
            margin-top: 1rem;
        }

        .footer a {
            color: var(--accent-light);
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }

            .header h1 {
                font-size: 1.5rem;
            }

            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .host-task-row {
                grid-template-columns: 1fr;
                gap: 0.5rem;
            }
        }

        /* Finding rows - unified findings */
        .finding-row {
            display: grid;
            grid-template-columns: 80px 65px 1fr 200px 1fr 30px;
            gap: 0.75rem;
            padding: 0.6rem 1rem;
            border-bottom: 1px solid var(--border);
            align-items: center;
            font-size: 0.85rem;
            cursor: pointer;
            user-select: none;
        }

        .finding-row:last-child {
            border-bottom: none;
        }

        .finding-row:hover {
            background: rgba(99, 102, 241, 0.05);
        }

        .finding-row .severity-pill {
            text-align: center;
            min-width: 60px;
        }

        .finding-name {
            font-family: 'Consolas', 'Monaco', monospace;
            color: var(--text-muted);
            font-size: 0.8rem;
            word-break: break-all;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .finding-account {
            font-weight: 500;
            font-size: 0.85rem;
        }

        .finding-account.tier0 { color: #fca5a5; }
        .finding-account.priv { color: #fdba74; }

        .finding-factors {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .expand-icon {
            font-size: 0.8rem;
            color: var(--text-muted);
            transition: transform 0.2s;
            text-align: center;
        }

        .finding-row.expanded .expand-icon {
            transform: rotate(180deg);
        }

        .kind-badge {
            padding: 0.15rem 0.35rem;
            border-radius: 3px;
            font-size: 0.6rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            text-align: center;
            display: inline-block;
        }

        .kind-badge.kind-task {
            background: rgba(99, 102, 241, 0.15);
            color: var(--accent-light);
            border: 1px solid var(--accent);
        }

        .kind-badge.kind-service {
            background: rgba(20, 184, 166, 0.15);
            color: #5eead4;
            border: 1px solid #0d9488;
        }

        .host-badge.services {
            background: rgba(20, 184, 166, 0.15);
            color: #5eead4;
            border: 1px solid #0d9488;
        }

        /* Finding detail panel */
        .finding-detail {
            display: none;
            padding: 0.75rem 1rem 0.75rem 1.5rem;
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border);
        }

        .finding-detail.visible {
            display: block;
        }

        .finding-detail-grid {
            display: grid;
            grid-template-columns: 160px 1fr;
            gap: 0.3rem 1rem;
            font-size: 0.82rem;
        }

        .finding-detail-grid .detail-key {
            color: var(--text-muted);
            font-weight: 500;
            text-align: right;
            padding: 0.15rem 0;
        }

        .finding-detail-grid .detail-value {
            color: var(--text-secondary);
            padding: 0.15rem 0;
            word-break: break-all;
        }

        .password-inline {
            font-family: 'Consolas', 'Monaco', monospace;
            background: rgba(22, 101, 52, 0.2);
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            color: var(--success-light);
            font-size: 0.82rem;
        }

        .tag-gmsa {
            color: var(--accent-light);
            font-size: 0.75rem;
            font-weight: 500;
        }

        .tag-disabled {
            color: var(--failure-light);
            font-size: 0.75rem;
            font-weight: 500;
        }

        /* Attack Path Summary */
        .attack-path {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
            border-left: 4px solid var(--severity-info);
        }

        .attack-path.risk-critical { border-left-color: var(--severity-critical); }
        .attack-path.risk-high { border-left-color: var(--severity-high); }
        .attack-path.risk-medium { border-left-color: var(--severity-medium); }
        .attack-path.risk-low { border-left-color: var(--severity-low); }
        .attack-path.risk-info { border-left-color: var(--severity-info); }

        .attack-path h2 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1.1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .attack-path p {
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.7;
            margin-bottom: 0.75rem;
        }

        .attack-path p:last-child {
            margin-bottom: 0;
        }

        /* Credential Summary Table */
        .credential-summary {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }

        .credential-summary h2 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1.1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .credential-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.82rem;
        }

        .credential-table th {
            background: var(--bg-card);
            padding: 0.6rem 0.75rem;
            text-align: left;
            font-weight: 500;
            color: var(--text-muted);
            border: 1px solid var(--border);
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.04em;
        }

        .credential-table td {
            padding: 0.6rem 0.75rem;
            border: 1px solid var(--border);
            vertical-align: top;
            color: var(--text-secondary);
        }

        .credential-table tr:hover {
            background: rgba(99, 102, 241, 0.03);
        }

        .credential-table .password-cell {
            font-family: 'Consolas', 'Monaco', monospace;
            color: var(--success-light);
            background: rgba(22, 101, 52, 0.1);
            word-break: break-all;
        }

        .credential-table .no-creds {
            color: var(--text-muted);
            font-style: italic;
            padding: 1.5rem;
            text-align: center;
        }

        /* Account Risk Matrix */
        .risk-matrix-section {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
            overflow-x: auto;
        }

        .risk-matrix-section h2 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 1.1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .risk-matrix {
            border-collapse: collapse;
            font-size: 0.8rem;
            min-width: 100%;
        }

        .risk-matrix th {
            background: var(--bg-card);
            padding: 0.5rem 0.75rem;
            text-align: center;
            font-weight: 500;
            color: var(--text-muted);
            border: 1px solid var(--border);
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            white-space: nowrap;
        }

        .risk-matrix th:first-child {
            text-align: left;
            position: sticky;
            left: 0;
            z-index: 1;
            background: var(--bg-card);
        }

        .risk-matrix td {
            padding: 0.4rem 0.6rem;
            border: 1px solid var(--border);
            text-align: center;
            vertical-align: middle;
        }

        .risk-matrix td:first-child {
            text-align: left;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.8rem;
            color: var(--text-secondary);
            white-space: nowrap;
            position: sticky;
            left: 0;
            z-index: 1;
            background: var(--bg-secondary);
        }

        .risk-cell {
            display: inline-block;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-size: 0.7rem;
            font-weight: 600;
            letter-spacing: 0.03em;
            min-width: 24px;
        }

        .risk-cell.severity-critical {
            background: var(--severity-critical-bg);
            color: #fca5a5;
            border: 1px solid var(--severity-critical);
        }
        .risk-cell.severity-high {
            background: var(--severity-high-bg);
            color: #fdba74;
            border: 1px solid var(--severity-high);
        }
        .risk-cell.severity-medium {
            background: var(--severity-medium-bg);
            color: #fcd34d;
            border: 1px solid var(--severity-medium);
        }
        .risk-cell.severity-low {
            background: var(--severity-low-bg);
            color: #93c5fd;
            border: 1px solid var(--severity-low);
        }
        .risk-cell.severity-info {
            background: rgba(75, 85, 99, 0.15);
            color: var(--text-secondary);
            border: 1px solid var(--severity-info);
        }

        .risk-matrix .multi-host {
            font-weight: 600;
        }

        /* Print styles */
        @media print {
            body, .container, .section, .host-block, .finding-row, .finding-detail {
                background: white !important;
                color: #1a1a1a !important;
            }

            .executive-summary, .header, .attack-path, .credential-summary,
            .risk-matrix-section, .classification-reference, .disclaimer,
            .failures-section {
                background: white !important;
                color: #1a1a1a !important;
            }

            .section, .host-block, .executive-summary, .header, .attack-path,
            .credential-summary, .risk-matrix-section, .classification-reference,
            .disclaimer, .failures-section, .stat-card, .severity-badge,
            .finding-detail, .finding-row {
                border-color: #ddd !important;
            }

            .stat-card {
                background: #f5f5f5 !important;
            }

            .stat-card .value, .stat-card.critical .value, .stat-card.high .value,
            .stat-card.medium .value, .stat-card.low .value, .stat-card.success .value {
                color: #1a1a1a !important;
            }

            .host-tasks, .host-block .host-tasks,
            .finding-detail, .failures-content {
                display: block !important;
            }

            .expand-icon {
                display: none !important;
            }

            .host-block {
                page-break-inside: avoid;
            }

            .finding-detail {
                page-break-inside: avoid;
            }

            .password-inline {
                background: transparent !important;
                border: 1px solid #999 !important;
                color: #1a1a1a !important;
                padding: 0.1rem 0.3rem;
            }

            .password-cell {
                background: transparent !important;
                color: #1a1a1a !important;
            }

            .bg-card, .host-tasks {
                background: #fafafa !important;
            }

            .text-primary, .text-secondary, .text-muted,
            .finding-name, .finding-factors, .finding-account,
            .host-header h4, .detail-key, .detail-value,
            .tier0-warning strong, .tier0-accounts-list li,
            .failure-item .host, .failure-item .error,
            .disclaimer p, .attack-path p,
            .meta-label, .meta-value, .header .subtitle, .header .meta {
                color: #1a1a1a !important;
            }

            .section, .host-block, .executive-summary {
                box-shadow: none !important;
            }

            .container {
                padding: 0.5rem !important;
            }

            .footer a {
                color: #1a1a1a !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        {{HEADER}}
        {{DISCLAIMER}}
        {{EXECUTIVE_SUMMARY}}
        {{ATTACK_PATH_SUMMARY}}
        {{CREDENTIAL_SUMMARY}}
        {{CLASSIFICATION_REFERENCE}}
        {{UNIFIED_FINDINGS}}
        {{FAILURES}}
        {{FOOTER}}
    </div>

    <script>
        function toggleHost(hostId) {
            const hostBlock = document.getElementById(hostId);
            hostBlock.classList.toggle('expanded');
        }
        function toggleFinding(findingId) {
            const row = document.getElementById('row-' + findingId);
            const detail = document.getElementById('detail-' + findingId);
            if (row && detail) {
                row.classList.toggle('expanded');
                detail.classList.toggle('visible');
            }
        }
    </script>
</body>
</html>"""


def _generate_header(stats: AuditStatistics, timestamp: str) -> str:
    """Generate the header section HTML."""
    subtitle = "Scheduled Task &amp; Service Privilege Analysis" if stats.total_services > 0 else "Scheduled Task Privilege Analysis"

    services_item = ""
    if stats.total_services > 0:
        services_item = f"""
                <div class="meta-item">
                    <span class="meta-value">{stats.total_services}</span>
                    <span class="meta-label">Services Found</span>
                </div>"""

    credentials_item = ""
    if stats.decrypted_count > 0:
        credentials_item = f"""
                <div class="meta-item">
                    <span class="meta-value failure">{stats.decrypted_count}</span>
                    <span class="meta-label">Credentials Extracted</span>
                </div>"""

    # Overall risk badge color
    risk_level = stats.overall_risk
    risk_colors = {
        "CRITICAL": "var(--failure-light)",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "var(--accent-light)",
        "INFO": "var(--text-muted)",
    }
    risk_color = risk_colors.get(risk_level, "var(--text-muted)")

    return f"""
        <div class="header">
            <h1>TaskHound Security Audit Report</h1>
            <p class="subtitle">{subtitle}</p>
            <p class="meta" style="margin-bottom: 1rem;">Generated: {html.escape(timestamp)}</p>
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="meta-value success">{stats.total_hosts}</span>
                    <span class="meta-label">Hosts Scanned</span>
                </div>
                <div class="meta-item">
                    <span class="meta-value">{stats.total_tasks}</span>
                    <span class="meta-label">Tasks Found</span>
                </div>{services_item}{credentials_item}
                <div class="meta-item">
                    <span class="meta-value" style="color: {risk_color};">{risk_level}</span>
                    <span class="meta-label">Overall Risk</span>
                </div>
            </div>
        </div>
    """


def _generate_executive_summary(stats: AuditStatistics) -> str:
    """Generate the executive summary section HTML."""

    summary_html = """
        <div class="executive-summary">
            <h2>Summary</h2>
            <div class="severity-breakdown">
    """

    # Add all severity badges as table cells
    severity_counts = [
        ("CRITICAL", stats.critical_count),
        ("HIGH", stats.high_count),
        ("MEDIUM", stats.medium_count),
        ("LOW", stats.low_count),
        ("INFO", stats.info_count),
    ]

    for level, count in severity_counts:
        summary_html += f'''<div class="severity-badge severity-{level.lower()}"><span class="count">{count}</span><span class="label">{level}</span></div>'''

    summary_html += "</div>"

    # Add Tier-0 warning if applicable
    if stats.tier0_accounts:
        summary_html += """
            <div class="tier0-warning">
                <div class="tier0-warning-header">
                    <span class="title">Tier-0 Accounts at Risk</span>
                </div>
                <ul class="tier0-accounts-list">
        """
        for account in sorted(stats.tier0_accounts):
            summary_html += f"<li>{html.escape(account)}</li>"
        summary_html += """
                </ul>
            </div>
        """

    summary_html += "</div>"

    return summary_html


def _generate_disclaimer() -> str:
    """Generate the disclaimer note section HTML."""
    return """
        <div class="disclaimer">
            <div class="disclaimer-header">
                <span class="icon">ℹ️</span>
                <span class="title">Important Notice</span>
            </div>
            <p>
                This report represents a <strong>point-in-time snapshot</strong> of the scheduled task configuration
                across the scanned environment. Active Directory changes, task modifications, or credential updates
                occurring after the scan time are not reflected in these findings.
            </p>
            <p>
                Severity classifications are determined through automated heuristic analysis based on account
                privilege levels, credential storage indicators, and validation results. These assessments should
                be considered as <strong>indicative guidance</strong> rather than definitive security verdicts.
                Manual verification and contextual evaluation by qualified security personnel is recommended
                before taking remediation actions.
            </p>
        </div>
    """


def _generate_classification_reference() -> str:
    """Generate the classification and impact reference section HTML."""
    return """
        <div class="classification-reference">
            <h2>Classification &amp; Impact Reference</h2>

            <h3>Severity Classification Matrix</h3>
            <table class="classification-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Criteria</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="severity-pill severity-critical">CRITICAL</span></td>
                        <td>Tier-0 account + Stored credentials + Valid password</td>
                        <td>Domain Admin or equivalent credentials confirmed valid. Immediate compromise risk.</td>
                    </tr>
                    <tr>
                        <td><span class="severity-pill severity-high">HIGH</span></td>
                        <td>Tier-0 + Stored creds (outdated/protected)<br>—or— Privileged account + Valid password</td>
                        <td>High-value credentials at risk. May enable privilege escalation or lateral movement.</td>
                    </tr>
                    <tr>
                        <td><span class="severity-pill severity-medium">MEDIUM</span></td>
                        <td>Tier-0 without stored creds<br>—or— Privileged account + Stored creds (not validated)</td>
                        <td>Elevated account exposure. Potential attack path if credentials are obtained elsewhere.</td>
                    </tr>
                    <tr>
                        <td><span class="severity-pill severity-low">LOW</span></td>
                        <td>Privileged account without stored creds<br>—or— Standard task with stored credentials</td>
                        <td>Limited direct risk. Monitor for privilege changes or credential additions.</td>
                    </tr>
                    <tr>
                        <td><span class="severity-pill severity-info">INFO</span></td>
                        <td>Standard task without stored credentials</td>
                        <td>Informational finding. No immediate security concern identified.</td>
                    </tr>
                </tbody>
            </table>

            <!-- Impact descriptions moved to Attack Path Summary -->
        </div>
    """


def _get_finding_display_name(row: Any, kind: str) -> str:
    """Get display name for a finding (task path or service name)."""
    if kind == "service":
        name = _get_row_value(row, "service_name", "") or ""
        display = _get_row_value(row, "display_name", "") or ""
        if display and name:
            return name
        return name or display or "Unknown"
    return _get_row_value(row, "path", "Unknown") or "Unknown"


def _get_finding_account(row: Any, kind: str) -> str:
    """Get the display account for a finding, normalized to NETBIOS\\Sam."""
    if kind == "service":
        runas_raw = _get_row_value(row, "start_name", "") or _get_row_value(row, "runas", "") or ""
    else:
        runas_raw = _get_row_value(row, "runas", "") or ""
    resolved_runas = _get_row_value(row, "resolved_runas", "") or ""

    # Prefer resolved name, fall back to raw
    account = resolved_runas or runas_raw or "N/A"

    # Normalize to NETBIOS\Sam (strips SID suffixes, normalizes UPN/downlevel)
    return _normalize_account_display(account)


def _generate_finding_detail(row: Any, kind: str, finding_id: str) -> str:
    """Generate the expandable detail panel for a finding."""
    detail_html = f'<div class="finding-detail" id="detail-{finding_id}">'
    detail_html += '<div class="finding-detail-grid">'

    def _kv(key: str, value: str) -> str:
        if not value or value in ("N/A", "-", "None"):
            return ""
        return f'<span class="detail-key">{html.escape(key)}</span><span class="detail-value">{value}</span>'

    if kind == "task":
        # Task-specific details
        command = _get_row_value(row, "command", "") or ""
        trigger = _get_row_value(row, "triggers", "") or _get_row_value(row, "trigger", "") or ""
        author = _get_row_value(row, "author", "") or ""
        date = _get_row_value(row, "date", "") or ""
        last_run = _get_row_value(row, "last_run", "") or ""
        return_code = _get_row_value(row, "return_code", "") or ""
        cred_status = _get_row_value(row, "cred_status", "") or ""
        cred_valid = _get_row_value(row, "cred_password_valid", None)
        reason = _get_row_value(row, "reason", "") or ""

        if command:
            detail_html += _kv("Command", html.escape(str(command)))
        if trigger:
            detail_html += _kv("Trigger", html.escape(str(trigger)))
        if author:
            detail_html += _kv("Author", html.escape(str(author)))
        if date:
            detail_html += _kv("Date", html.escape(str(date)))
        if last_run:
            detail_html += _kv("Last Run", html.escape(str(last_run)))
        if return_code:
            detail_html += _kv("Return Code", html.escape(str(return_code)))
        if cred_valid is True:
            detail_html += _kv("Cred Validation", '<span style="color: var(--success-light);">Valid</span>')
        elif cred_valid is False:
            detail_html += _kv("Cred Validation", '<span style="color: var(--failure-light);">Invalid</span>')
        elif cred_status:
            detail_html += _kv("Cred Validation", html.escape(str(cred_status)))
        if reason:
            detail_html += _kv("Reason", html.escape(str(reason)))

    else:
        # Service-specific details
        display_name = _get_row_value(row, "display_name", "") or ""
        binary_path = _get_row_value(row, "binary_path", "") or ""
        start_type = _get_row_value(row, "start_type", "") or ""
        state = _get_row_value(row, "state", "") or ""
        lsa_secret = _get_row_value(row, "lsa_secret_name", "") or ""
        reason = _get_row_value(row, "reason", "") or ""

        if display_name:
            detail_html += _kv("Display Name", html.escape(str(display_name)))
        if binary_path:
            detail_html += _kv("Binary Path", html.escape(str(binary_path)))
        if start_type:
            detail_html += _kv("Start Type", html.escape(str(start_type)))
        if state:
            detail_html += _kv("State", html.escape(str(state)))
        if lsa_secret:
            detail_html += _kv("LSA Secret", html.escape(str(lsa_secret)))
        if reason:
            detail_html += _kv("Reason", html.escape(str(reason)))

    # Common fields for both kinds
    decrypted = _get_row_value(row, "decrypted_password", "") or ""
    is_gmsa = _get_row_value(row, "is_gmsa", False)
    is_disabled = _get_row_value(row, "is_disabled_account", False)
    cred_guard = _get_row_value(row, "credential_guard", None)

    if decrypted and decrypted not in ("N/A", "", "-"):
        detail_html += f'<span class="detail-key">Password</span><span class="detail-value"><span class="password-inline">{html.escape(decrypted)}</span></span>'
    if is_gmsa:
        detail_html += '<span class="detail-key">gMSA</span><span class="detail-value"><span class="tag-gmsa">[gMSA]</span></span>'
    if is_disabled:
        detail_html += '<span class="detail-key">Account</span><span class="detail-value"><span class="tag-disabled">[DISABLED]</span></span>'
    if cred_guard is True:
        detail_html += '<span class="detail-key">Credential Guard</span><span class="detail-value"><span style="color: var(--accent-light);">Enabled</span></span>'

    detail_html += "</div></div>"
    return detail_html


def _generate_unified_findings(findings: list[tuple[SeverityScore, Any, str]]) -> str:
    """Generate unified findings section with collapsible host blocks containing tasks and services."""
    if not findings:
        return """
        <div class="section">
            <h2>Detailed Findings</h2>
            <p style="color: var(--text-muted);">No findings to display.</p>
        </div>
        """

    # Group findings by host
    from collections import defaultdict

    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    hosts_data: dict[str, dict] = defaultdict(
        lambda: {
            "findings": [],
            "tier0_count": 0,
            "task_count": 0,
            "service_count": 0,
            "decrypted_count": 0,
            "max_severity": 0,
        }
    )

    for severity, row, kind in findings:
        host = _get_row_value(row, "host", "Unknown")
        hosts_data[host]["findings"].append({"row": row, "severity": severity, "kind": kind})

        task_type = str(_get_row_value(row, "type", "")).upper()
        if task_type == "TIER-0":
            hosts_data[host]["tier0_count"] += 1

        if kind == "task":
            hosts_data[host]["task_count"] += 1
        else:
            hosts_data[host]["service_count"] += 1

        decrypted = _get_row_value(row, "decrypted_password", "")
        if decrypted and decrypted not in ("N/A", "", "-"):
            hosts_data[host]["decrypted_count"] += 1

        sev_val = severity_order.get(severity.level, 0)
        if sev_val > hosts_data[host]["max_severity"]:
            hosts_data[host]["max_severity"] = sev_val

    # Sort hosts by highest severity first, then alphabetically
    sorted_hosts = sorted(
        hosts_data.items(),
        key=lambda item: (-item[1]["max_severity"], item[0].lower()),
    )

    html_output = """
        <div class="section">
            <h2>Detailed Findings</h2>
            <p style="color: var(--text-muted); margin-bottom: 1rem; font-size: 0.85rem;">Click on a host to expand, then click a finding for full details.</p>
            <div class="host-findings-container">
    """

    finding_counter = 0

    for _i, (host, data) in enumerate(sorted_hosts):
        host_id = f"host-{re.sub(r'[^a-zA-Z0-9]', '-', host.lower())}"

        # Generate badges
        badges_html = ""
        if data["tier0_count"] > 0:
            badges_html += f'<span class="host-badge tier0">{data["tier0_count"]} Tier-0</span>'
        if data["task_count"] > 0:
            badges_html += f'<span class="host-badge tasks">{data["task_count"]} Tasks</span>'
        if data["service_count"] > 0:
            badges_html += f'<span class="host-badge services">{data["service_count"]} Services</span>'
        if data["decrypted_count"] > 0:
            badges_html += f'<span class="host-badge decrypted">{data["decrypted_count"]} Decrypted</span>'

        html_output += f"""
                <div class="host-block" id="{host_id}">
                    <div class="host-header" onclick="toggleHost('{host_id}')">
                        <div class="host-header-left">
                            <h4>{html.escape(host)}</h4>
                            <div class="host-badges">
                                {badges_html}
                            </div>
                        </div>
                        <span class="expand-icon">▼</span>
                    </div>
                    <div class="host-tasks">
        """

        # Sort findings within host by severity descending
        sorted_findings = sorted(
            data["findings"],
            key=lambda f: -severity_order.get(f["severity"].level, 0),
        )

        for finding_data in sorted_findings:
            row = finding_data["row"]
            severity = finding_data["severity"]
            kind = finding_data["kind"]
            finding_id = f"finding-{finding_counter}"
            finding_counter += 1

            name = _get_finding_display_name(row, kind)
            account = _get_finding_account(row, kind)
            task_type = str(_get_row_value(row, "type", "") or "").upper()

            # Account styling
            account_class = ""
            if task_type == "TIER-0":
                account_class = " tier0"
            elif task_type == "PRIV":
                account_class = " priv"

            # Factors inline
            factors_text = ", ".join(severity.factors) if severity.factors else ""

            # Kind badge
            kind_label = "Task" if kind == "task" else "Service"

            # Finding row
            html_output += f"""
                        <div class="finding-row" id="row-{finding_id}" onclick="toggleFinding('{finding_id}')">
                            <span class="severity-pill {severity.css_class}">{severity.level}</span>
                            <span class="kind-badge kind-{kind}">{kind_label}</span>
                            <span class="finding-name">{html.escape(name)}</span>
                            <span class="finding-account{account_class}">{html.escape(account)}</span>
                            <span class="finding-factors">{html.escape(factors_text)}</span>
                            <span class="expand-icon">&#9660;</span>
                        </div>
            """

            # Detail panel
            html_output += _generate_finding_detail(row, kind, finding_id)

        html_output += """
                    </div>
                </div>
        """

    html_output += """
            </div>
        </div>
    """

    return html_output


def _generate_failures(stats: AuditStatistics) -> str:
    """Generate the failures section HTML (collapsible)."""
    if not stats.failures:
        return ""

    failures_html = f"""
        <div class="failures-section" onclick="this.classList.toggle('expanded')">
            <div class="failures-header">
                <span class="title">Connection Failures ({stats.failure_count})</span>
                <span class="toggle">▼</span>
            </div>
            <div class="failures-content">
    """

    for failure in stats.failures:
        host = html.escape(failure.get("host") or "Unknown")
        error = html.escape(failure.get("error") or "Unknown error")
        failures_html += f"""
                <div class="failure-item">
                    <span class="host">{host}</span>
                    <span class="error">{error}</span>
                </div>
        """

    failures_html += """
            </div>
        </div>
    """

    return failures_html


def _generate_footer() -> str:
    """Generate the footer section HTML."""
    return """
        <div class="footer">
            <p>
                Generated by <strong>TaskHound</strong> - Windows Scheduled Task Security Analysis Tool<br>
                <a href="https://github.com/1r0BIT/TaskHound" target="_blank">https://github.com/1r0BIT/TaskHound</a>
            </p>
        </div>
    """




def _generate_attack_path_summary(
    stats: AuditStatistics,
    findings: list[tuple[SeverityScore, Any, str]],
    service_rows: list[Any] | None = None,
) -> str:
    """Generate a data-driven attack path narrative section."""
    total_findings = len(findings)
    if total_findings == 0:
        return ""

    risk_class = f"risk-{stats.overall_risk.lower()}"
    paragraphs: list[str] = []

    # --- Opening paragraph (always) ---
    cred_sentence = ""
    if stats.decrypted_count > 0:
        cred_sentence = (
            f" {stats.decrypted_count} plaintext credential{'s were' if stats.decrypted_count != 1 else ' was'}"
            " successfully extracted."
        )
    else:
        cred_sentence = " No plaintext credentials were successfully extracted."

    opening = (
        f"The assessment identified {total_findings} finding{'s' if total_findings != 1 else ''}"
        f" across {stats.total_hosts} host{'s' if stats.total_hosts != 1 else ''}"
    )
    severity_parts: list[str] = []
    if stats.critical_count > 0:
        severity_parts.append(f"{stats.critical_count} critical")
    if stats.high_count > 0:
        severity_parts.append(f"{stats.high_count} high-severity")
    if severity_parts:
        opening += f", including {' and '.join(severity_parts)} issue{'s' if (stats.critical_count + stats.high_count) != 1 else ''}"
    opening += f".{cred_sentence}"
    paragraphs.append(opening)

    # --- Tier-0 paragraph (Domain Takeover risk) ---
    if stats.tier0_count > 0 or stats.service_tier0_count > 0:
        tier0_accounts: set[str] = set()
        tier0_has_decrypted = False
        for _severity, row, kind in findings:
            if str(_get_row_value(row, "type", "")).upper() == "TIER-0":
                tier0_accounts.add(_normalize_account_display(_get_finding_account(row, kind)))
                decrypted = _get_row_value(row, "decrypted_password", "")
                if decrypted and decrypted not in ("N/A", "", "-"):
                    tier0_has_decrypted = True

        names = ", ".join(html.escape(a) for a in sorted(tier0_accounts))
        tier0_text = (
            f"<strong>Domain Takeover:</strong> Tier-0 account{'s' if len(tier0_accounts) != 1 else ''}"
            f" ({names}) {'were' if len(tier0_accounts) != 1 else 'was'} found running"
            " tasks or services with stored credentials."
        )
        if tier0_has_decrypted:
            tier0_text += " Plaintext credentials were successfully recovered during the assessment."
        paragraphs.append(tier0_text)

    # --- Lateral Movement / Privilege Escalation paragraph ---
    # Covers both PRIV accounts and TIER-0 accounts spanning multiple hosts
    privileged_account_hosts: dict[str, set[str]] = {}
    priv_only_accounts: set[str] = set()
    for _severity, row, kind in findings:
        task_type = str(_get_row_value(row, "type", "")).upper()
        if task_type in ("TIER-0", "PRIV"):
            account = _normalize_account_display(_get_finding_account(row, kind))
            host = str(_get_row_value(row, "host", "Unknown"))
            privileged_account_hosts.setdefault(account, set()).add(host)
            if task_type == "PRIV":
                priv_only_accounts.add(account)

    multi_host_accounts = {a for a, h in privileged_account_hosts.items() if len(h) > 1}

    # Show PRIV-specific text if any PRIV accounts exist
    if priv_only_accounts:
        names = ", ".join(html.escape(a) for a in sorted(priv_only_accounts))
        priv_text = (
            f"<strong>Lateral Movement &amp; Privilege Escalation:</strong>"
            f" Privileged account{'s' if len(priv_only_accounts) != 1 else ''}"
            f" ({names}) {'were' if len(priv_only_accounts) != 1 else 'was'} found with stored credentials."
            " Compromise could enable privilege escalation toward full domain takeover."
        )
        paragraphs.append(priv_text)

    # Show lateral movement note if ANY privileged accounts span multiple hosts
    if multi_host_accounts:
        paragraphs.append(
            f"<strong>Lateral Movement:</strong>"
            f" {len(multi_host_accounts)} privileged account{'s' if len(multi_host_accounts) != 1 else ''}"
            f" {'span' if len(multi_host_accounts) != 1 else 'spans'} multiple hosts,"
            " enabling lateral movement via credential reuse."
            " Extracting stored credentials from any single host grants access to the others."
        )

    # --- Credential Guard note ---
    cred_guard_hosts = len({
        str(_get_row_value(row, "host", ""))
        for _s, row, _k in findings
        if _get_row_value(row, "credential_guard", None) is True
    })
    if cred_guard_hosts:
        paragraphs.append(
            f"<strong>Note:</strong> Credential Guard was detected on {cred_guard_hosts}"
            f" host{'s' if cred_guard_hosts != 1 else ''}, providing protection against"
            " DPAPI-based credential extraction for scheduled tasks."
            " LSA secrets (service credentials) may still be extractable."
        )

    para_html = "".join(f"<p>{p}</p>" for p in paragraphs)

    return f"""
        <div class="attack-path {risk_class}">
            <h2>Attack Path Summary</h2>
            {para_html}
        </div>
    """


def _generate_credential_summary(
    findings: list[tuple[SeverityScore, Any, str]],
    service_rows: list[Any] | None = None,
) -> str:
    """Generate a table of all extracted credentials (passwords and hashes)."""
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    cred_rows: list[dict[str, str]] = []

    for severity, row, kind in findings:
        decrypted = _get_row_value(row, "decrypted_password", "")
        if not decrypted or decrypted in ("N/A", "", "-"):
            continue

        account = _normalize_account_display(_get_finding_account(row, kind))
        host = str(_get_row_value(row, "host", "Unknown"))
        name = _get_finding_display_name(row, kind)
        task_type = str(_get_row_value(row, "type", "")).upper()
        cred_guard = _get_row_value(row, "credential_guard", None)
        source = "Task" if kind == "task" else "Service"

        cred_rows.append({
            "account": account,
            "password": str(decrypted),
            "source": source,
            "host": host,
            "name": name,
            "classification": task_type,
            "cred_guard": "Yes" if cred_guard is True else "No" if cred_guard is False else "-",
            "severity_rank": str(severity_order.get(severity.level, 0)),
            "class_rank": str({"TIER-0": 3, "PRIV": 2}.get(task_type, 1)),
        })

    # Sort by host first (for grouping), then by classification severity
    cred_rows.sort(key=lambda r: (r["host"], -int(r["class_rank"]), -int(r["severity_rank"])))

    summary_html = f"""
        <div class="credential-summary">
            <h2>Credential Summary ({len(cred_rows)})</h2>
    """

    if not cred_rows:
        summary_html += '<p class="credential-table no-creds">No credentials were successfully extracted during this assessment.</p>'
        summary_html += "</div>"
        return summary_html

    # Group credentials by host
    from collections import OrderedDict
    hosts_creds: OrderedDict[str, list[dict]] = OrderedDict()
    for cr in cred_rows:
        hosts_creds.setdefault(cr["host"], []).append(cr)

    for host_idx, (host_name, host_creds) in enumerate(hosts_creds.items()):
        cred_host_id = f"cred-host-{host_idx}"
        summary_html += f"""
            <div class="host-block" id="{cred_host_id}" style="margin-bottom: 0.75rem;">
                <div class="host-header" onclick="toggleHost('{cred_host_id}')" style="cursor: pointer; padding: 0.6rem 1rem;">
                    <div class="host-header-left">
                        <h4 style="margin: 0; font-size: 0.9rem;">{html.escape(host_name)}</h4>
                        <span class="host-badge stored">{len(host_creds)} credential{'s' if len(host_creds) != 1 else ''}</span>
                    </div>
                    <span class="expand-icon">&#9660;</span>
                </div>
                <div class="host-tasks">
                    <table class="credential-table" style="margin: 0;">
                        <thead>
                            <tr>
                                <th>Account</th>
                                <th>Password / Hash</th>
                                <th>Source</th>
                                <th>Task / Service</th>
                                <th>Classification</th>
                            </tr>
                        </thead>
                        <tbody>
        """

        for cr in host_creds:
            account_class = ""
            if cr["classification"] == "TIER-0":
                account_class = " tier0"
            elif cr["classification"] == "PRIV":
                account_class = " priv"

            summary_html += f"""
                            <tr>
                                <td><span class="finding-account{account_class}">{html.escape(cr['account'])}</span></td>
                                <td class="password-cell">{html.escape(cr['password'])}</td>
                                <td>{html.escape(cr['source'])}</td>
                                <td style="font-family: 'Consolas', 'Monaco', monospace; font-size: 0.8rem;">{html.escape(cr['name'])}</td>
                                <td>{html.escape(cr['classification'])}</td>
                            </tr>
            """

        summary_html += """
                        </tbody>
                    </table>
                </div>
            </div>
        """

    summary_html += "</div>"
    return summary_html


def _generate_account_risk_matrix(
    findings: list[tuple[SeverityScore, Any, str]],
    service_rows: list[Any] | None = None,
) -> str:
    """Generate an account-vs-host risk matrix for privileged accounts."""
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    # Collect data: account -> host -> {kinds, max_severity_level}
    matrix_data: dict[str, dict[str, dict[str, Any]]] = {}

    for severity, row, kind in findings:
        task_type = str(_get_row_value(row, "type", "")).upper()
        if task_type not in ("TIER-0", "PRIV"):
            continue

        account = _normalize_account_display(_get_finding_account(row, kind))
        host = str(_get_row_value(row, "host", "Unknown"))

        if account not in matrix_data:
            matrix_data[account] = {}
        if host not in matrix_data[account]:
            matrix_data[account][host] = {"kinds": set(), "max_severity": "INFO"}

        cell = matrix_data[account][host]
        cell["kinds"].add(kind)

        if severity_order.get(severity.level, 0) > severity_order.get(cell["max_severity"], 0):
            cell["max_severity"] = severity.level

    if not matrix_data:
        return ""

    # Determine unique hosts across all privileged accounts
    all_hosts: list[str] = sorted({h for acct_data in matrix_data.values() for h in acct_data})
    # Sort accounts: by highest severity across all hosts, then name
    def account_sort_key(acct: str) -> tuple[int, str]:
        max_sev = 0
        for host_data in matrix_data[acct].values():
            sev_val = severity_order.get(host_data["max_severity"], 0)
            if sev_val > max_sev:
                max_sev = sev_val
        return (-max_sev, acct.lower())

    sorted_accounts = sorted(matrix_data.keys(), key=account_sort_key)

    # Check which accounts span multiple hosts (lateral movement)
    multi_host_accounts = {acct for acct in matrix_data if len(matrix_data[acct]) > 1}

    matrix_html = """
        <div class="risk-matrix-section">
            <h2>Account Risk Matrix</h2>
            <table class="risk-matrix">
                <thead>
                    <tr>
                        <th>Account</th>
    """

    for host in all_hosts:
        matrix_html += f"<th>{html.escape(host)}</th>"

    matrix_html += """
                    </tr>
                </thead>
                <tbody>
    """

    for account in sorted_accounts:
        multi_class = ' class="multi-host"' if account in multi_host_accounts else ""
        matrix_html += f"<tr><td{multi_class}>{html.escape(account)}</td>"

        for host in all_hosts:
            cell_data = matrix_data[account].get(host)
            if cell_data is None:
                matrix_html += "<td></td>"
            else:
                kinds = cell_data["kinds"]
                sev_level = cell_data["max_severity"]
                sev_class = f"severity-{sev_level.lower()}"

                label_parts: list[str] = []
                if "task" in kinds:
                    label_parts.append("T")
                if "service" in kinds:
                    label_parts.append("S")
                label = " ".join(label_parts)

                matrix_html += f'<td><span class="risk-cell {sev_class}">{label}</span></td>'

        matrix_html += "</tr>"

    matrix_html += """
                </tbody>
            </table>
        </div>
    """

    return matrix_html


def generate_html_report(
    rows: list[Any],
    output_path: str,
    scan_time: str | None = None,
    service_rows: list[Any] | None = None,
    domain: str | None = None,
) -> str:
    """
    Generate a comprehensive HTML security audit report.

    Args:
        rows: List of task dictionaries or TaskRow objects from scan results
        output_path: Path to write the HTML file
        scan_time: Optional timestamp string (defaults to current time)
        service_rows: Optional list of ServiceRow objects for service findings
        domain: Domain FQDN from scan (e.g., 'ludus.domain') — used for
                normalizing account names to NETBIOS\\sam format

    Returns:
        The output path where the report was written
    """
    # Set module-level netbios domain for username normalization
    global _report_netbios_domain
    if domain:
        _report_netbios_domain = domain.split(".")[0].upper() if "." in domain else domain.upper()
    else:
        _report_netbios_domain = None

    if scan_time is None:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Calculate statistics and findings (unified tasks + services)
    stats, findings = generate_audit_summary(rows, service_rows=service_rows)

    # Generate sections
    header = _generate_header(stats, scan_time)
    disclaimer = _generate_disclaimer()
    executive_summary = _generate_executive_summary(stats)
    attack_path_summary = _generate_attack_path_summary(stats, findings, service_rows)
    credential_summary = _generate_credential_summary(findings, service_rows)
    classification_reference = _generate_classification_reference()
    unified_findings = _generate_unified_findings(findings)
    failures = _generate_failures(stats)
    footer = _generate_footer()

    # Build final HTML using replace chain (avoids {} conflicts with CSS)
    html_content = (
        HTML_TEMPLATE.replace("{{HEADER}}", header)
        .replace("{{DISCLAIMER}}", disclaimer)
        .replace("{{EXECUTIVE_SUMMARY}}", executive_summary)
        .replace("{{ATTACK_PATH_SUMMARY}}", attack_path_summary)
        .replace("{{CREDENTIAL_SUMMARY}}", credential_summary)
        .replace("{{CLASSIFICATION_REFERENCE}}", classification_reference)
        .replace("{{UNIFIED_FINDINGS}}", unified_findings)
        .replace("{{FAILURES}}", failures)
        .replace("{{FOOTER}}", footer)
    )

    # Write to file
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path
