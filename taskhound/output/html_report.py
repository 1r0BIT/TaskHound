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


def _normalize_username(username: str) -> str:
    """
    Normalize a username for deduplication.

    Handles:
    - Case insensitivity (DOMAIN\\User -> domain\\user)
    - Domain prefix variations (DOMAIN\\user vs user)

    Returns the normalized form: lowercase, with domain if present.
    """
    if not username:
        return ""

    username = username.strip().lower()

    # Skip SIDs
    if username.startswith("s-1-"):
        return username

    return username


def _get_canonical_username(username: str, seen_usernames: dict[str, str]) -> str:
    """
    Get the canonical (display) form of a username, deduplicating variations.

    Args:
        username: The username to canonicalize
        seen_usernames: Dict mapping normalized usernames to their canonical display form

    Returns:
        The canonical display form (preserves first-seen casing and domain prefix)
    """
    if not username:
        return ""

    normalized = _normalize_username(username)
    if not normalized or normalized.startswith("s-1-"):
        return username

    # Extract just the username part (without domain) for matching
    if "\\" in normalized:
        _, name_part = normalized.rsplit("\\", 1)
    else:
        name_part = normalized

    # Check if we've seen this username before (with or without domain)
    # Prefer the version WITH domain prefix if available
    for seen_norm, seen_canonical in seen_usernames.items():
        if "\\" in seen_norm:
            _, seen_name = seen_norm.rsplit("\\", 1)
        else:
            seen_name = seen_norm

        if name_part == seen_name:
            # If new one has domain and old one doesn't, update canonical
            if "\\" in normalized and "\\" not in seen_norm:
                seen_usernames[normalized] = username
                # Remove the old entry without domain
                if seen_norm in seen_usernames:
                    del seen_usernames[seen_norm]
                return username
            # Otherwise use existing canonical form
            return seen_canonical

    # First time seeing this username
    seen_usernames[normalized] = username
    return username


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

    # Check for stored credentials
    creds_hint = str(_get_row_value(row, "credentials_hint", "")).lower()
    has_stored_creds = "stored" in creds_hint or "password" in creds_hint

    # Check credential status
    cred_valid = _get_row_value(row, "cred_password_valid", None)
    cred_status = str(_get_row_value(row, "cred_status", "")).lower()
    cred_guard = _get_row_value(row, "credential_guard", None)

    # Check if account is disabled (indicated in reason field)
    reason = str(_get_row_value(row, "reason", ""))
    account_disabled = "[ACCOUNT DISABLED]" in reason

    # Determine credential state
    is_valid = cred_valid is True
    is_outdated = cred_status == "invalid" or cred_valid is False
    is_protected = cred_guard is True

    # Build factors list
    if task_type == "TIER-0":
        factors.append("Tier-0 privileged account")
    elif task_type == "PRIV":
        factors.append("Privileged account")
    elif task_type == "TASK":
        factors.append("Standard task")

    # Add account disabled indicator (before credential factors)
    if account_disabled:
        factors.append("Account currently disabled in AD")

    if has_stored_creds:
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

    elif task_type == "TASK":
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


def calculate_statistics(rows: list[Any]) -> AuditStatistics:
    """
    Calculate aggregated statistics from scan results.

    Args:
        rows: List of task dictionaries or TaskRow objects from scan results

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
        stored_creds_count=stored_creds_count,
        decrypted_count=decrypted_count,
        valid_creds_count=valid_creds_count,
        unique_accounts=len(unique_accounts_seen),
        tier0_accounts=list(tier0_accounts_seen.values()),
        failures=failures,
    )


def generate_audit_summary(rows: list[Any]) -> tuple[AuditStatistics, list[tuple[SeverityScore, Any]]]:
    """
    Generate audit summary with statistics and sorted findings.

    Args:
        rows: List of task dictionaries or TaskRow objects

    Returns:
        Tuple of (AuditStatistics, list of (SeverityScore, row) tuples sorted by severity)
    """
    stats = calculate_statistics(rows)

    # Calculate severity for each non-failure row and sort
    findings = []
    for row in rows:
        task_type = str(_get_row_value(row, "type", "")).upper()
        if task_type == "FAILURE":
            continue
        severity = calculate_severity(row)
        findings.append((severity, row))

    # Sort by severity score descending
    findings.sort(key=lambda x: x[0].score, reverse=True)

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
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Header */
        .header {
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: var(--bg-secondary);
            border-radius: 8px;
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
            border-radius: 8px;
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
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
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
            border-radius: 6px;
            border: 1px solid var(--border);
            overflow: hidden;
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

        /* Print styles */
        @media print {
            body {
                background: white;
                color: black;
            }

            .section, .executive-summary, .header {
                background: white;
                border: 1px solid #ddd;
            }

            .stat-card {
                background: #f5f5f5;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        {{HEADER}}
        {{DISCLAIMER}}
        {{EXECUTIVE_SUMMARY}}
        {{CLASSIFICATION_REFERENCE}}
        {{DETAILED_FINDINGS}}
        {{FAILURES}}
        {{FOOTER}}
    </div>

    <script>
        function toggleHost(hostId) {
            const hostBlock = document.getElementById(hostId);
            hostBlock.classList.toggle('expanded');
        }
    </script>
</body>
</html>"""


def _generate_header(stats: AuditStatistics, timestamp: str) -> str:
    """Generate the header section HTML."""
    return f"""
        <div class="header">
            <h1>TaskHound Security Audit Report</h1>
            <p class="subtitle">Scheduled Task Privilege Analysis</p>
            <p class="meta" style="margin-bottom: 1rem;">Generated: {html.escape(timestamp)}</p>
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="meta-value success">{stats.total_hosts}</span>
                    <span class="meta-label">Hosts Scanned</span>
                </div>
                <div class="meta-item">
                    <span class="meta-value failure">{stats.failure_count}</span>
                    <span class="meta-label">Hosts Failed</span>
                </div>
                <div class="meta-item">
                    <span class="meta-value">{stats.total_tasks}</span>
                    <span class="meta-label">Tasks Found</span>
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

            <h3>Potential Impact When Abused</h3>
            <ul class="impact-list">
                <li class="tier0">
                    <strong>Tier-0 Credential Compromise</strong>
                    <p>Attackers obtaining Domain Admin or equivalent credentials can achieve full domain control,
                    including the ability to create persistence mechanisms, access all domain resources,
                    modify security policies, and potentially compromise connected forests or cloud tenants.</p>
                </li>
                <li class="priv">
                    <strong>Privileged Account Abuse</strong>
                    <p>Compromised privileged accounts (local admin, service accounts with elevated rights)
                    enable lateral movement across systems, access to sensitive data, deployment of malware,
                    and potential escalation paths toward Tier-0 assets.</p>
                </li>
                <li class="stored">
                    <strong>Stored Credential Extraction</strong>
                    <p>Credentials stored via DPAPI can be extracted by attackers with local administrator
                    access to the host. Successful decryption yields plaintext passwords that may be reused
                    across systems or services, enabling credential stuffing and password spraying attacks.</p>
                </li>
            </ul>
        </div>
    """


def _generate_detailed_findings(rows: list[Any], findings: list[tuple[SeverityScore, Any]]) -> str:
    """Generate the detailed findings section with collapsible host blocks."""
    if not findings:
        return """
        <div class="section">
            <h2>Detailed Findings</h2>
            <p style="color: var(--text-muted);">No findings to display.</p>
        </div>
        """

    # Group tasks by host
    from collections import defaultdict

    hosts_data: dict[str, dict] = defaultdict(
        lambda: {"tasks": [], "tier0_count": 0, "stored_count": 0, "decrypted_count": 0}
    )

    for severity, row in findings:
        host = _get_row_value(row, "host", "Unknown")
        hosts_data[host]["tasks"].append({"row": row, "severity": severity})

        task_type = str(_get_row_value(row, "type", "")).upper()
        if task_type == "TIER-0":
            hosts_data[host]["tier0_count"] += 1

        creds_hint = str(_get_row_value(row, "credentials_hint", "")).lower()
        if "stored" in creds_hint:
            hosts_data[host]["stored_count"] += 1

        decrypted = _get_row_value(row, "decrypted_password", "")
        if decrypted and decrypted not in ("N/A", "", "-"):
            hosts_data[host]["decrypted_count"] += 1

    # Sort hosts by highest severity first
    def host_sort_key(item):
        host, data = item
        max_score = max((t["severity"].score for t in data["tasks"]), default=0)
        return (-max_score, host.lower())

    sorted_hosts = sorted(hosts_data.items(), key=host_sort_key)

    html_output = """
        <div class="section">
            <h2>Detailed Findings</h2>
            <p style="color: var(--text-muted); margin-bottom: 1rem; font-size: 0.85rem;">Click on a host to expand and view task details.</p>
            <div class="host-findings-container">
    """

    for i, (host, data) in enumerate(sorted_hosts):
        # Create safe ID for HTML
        host_id = f"host-{re.sub(r'[^a-zA-Z0-9]', '-', host.lower())}"

        # First host expanded by default
        expanded_class = " expanded" if i == 0 else ""

        # Generate badges
        badges_html = ""
        if data["tier0_count"] > 0:
            badges_html += f'<span class="host-badge tier0">{data["tier0_count"]} Tier-0</span>'
        if data["stored_count"] > 0:
            badges_html += f'<span class="host-badge stored">{data["stored_count"]} Stored</span>'
        if data["decrypted_count"] > 0:
            badges_html += f'<span class="host-badge decrypted">{data["decrypted_count"]} Decrypted</span>'
        if not badges_html and len(data["tasks"]) > 0:
            badges_html = f'<span class="host-badge tasks">{len(data["tasks"])} Tasks</span>'

        html_output += f"""
                <div class="host-block{expanded_class}" id="{host_id}">
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

        # Sort tasks by severity
        sorted_tasks = sorted(data["tasks"], key=lambda t: -t["severity"].score)

        for task_data in sorted_tasks:
            row = task_data["row"]
            severity = task_data["severity"]

            task_path = _get_row_value(row, "path", "Unknown") or "Unknown"
            # Prefer resolved username, show "username (SID)" when available
            runas_raw = _get_row_value(row, "runas", "") or ""
            resolved_runas = _get_row_value(row, "resolved_runas", "") or ""
            if resolved_runas and runas_raw.startswith("S-1-"):
                runas = f"{resolved_runas} ({runas_raw})"
            elif resolved_runas:
                runas = resolved_runas
            else:
                runas = runas_raw or "N/A"
            task_type = str(_get_row_value(row, "type", "") or "").upper()
            decrypted = _get_row_value(row, "decrypted_password", "") or ""

            # RunAs styling
            runas_class = ""
            if task_type == "TIER-0":
                runas_class = " tier0"
            elif task_type == "PRIV":
                runas_class = " priv"

            # Factors list
            factors_html = "<ul class='factors-list'>"
            for factor in severity.factors:
                factors_html += f"<li>{html.escape(factor)}</li>"
            factors_html += "</ul>"

            # Add decrypted password if present
            password_html = ""
            if decrypted and decrypted not in ("N/A", "", "-"):
                password_html = f'<span class="password-reveal">{html.escape(decrypted)}</span>'

            html_output += f"""
                        <div class="host-task-row">
                            <span class="severity-pill {severity.css_class}">{severity.level}</span>
                            <div>
                                <div class="task-path">{html.escape(task_path)}</div>
                                {password_html}
                            </div>
                            <span class="runas-account{runas_class}">{html.escape(runas)}</span>
                            <div>
                                {factors_html}
                            </div>
                        </div>
            """

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


def generate_html_report(
    rows: list[Any],
    output_path: str,
    scan_time: str | None = None,
) -> str:
    """
    Generate a comprehensive HTML security audit report.

    Args:
        rows: List of task dictionaries or TaskRow objects from scan results
        output_path: Path to write the HTML file
        scan_time: Optional timestamp string (defaults to current time)

    Returns:
        The output path where the report was written
    """
    if scan_time is None:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Calculate statistics and findings
    stats, findings = generate_audit_summary(rows)

    # Generate sections
    header = _generate_header(stats, scan_time)
    disclaimer = _generate_disclaimer()
    executive_summary = _generate_executive_summary(stats)
    classification_reference = _generate_classification_reference()
    detailed_findings = _generate_detailed_findings(rows, findings)
    failures = _generate_failures(stats)
    footer = _generate_footer()

    # Build final HTML using replace chain (avoids {} conflicts with CSS)
    html_content = (
        HTML_TEMPLATE.replace("{{HEADER}}", header)
        .replace("{{DISCLAIMER}}", disclaimer)
        .replace("{{EXECUTIVE_SUMMARY}}", executive_summary)
        .replace("{{CLASSIFICATION_REFERENCE}}", classification_reference)
        .replace("{{DETAILED_FINDINGS}}", detailed_findings)
        .replace("{{FAILURES}}", failures)
        .replace("{{FOOTER}}", footer)
    )

    # Write to file
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path
