"""Output module for TaskHound results."""

# Shared color scheme for task output
COLORS = {
    "tier0_header": "bold red",
    "tier0_border": "red",
    "priv_header": "bold yellow",
    "priv_border": "yellow",
    "task_header": "bold green",
    "task_border": "green",
    "service_header": "bold cyan",
    "service_border": "cyan",
    "label": "dim",
    "value": "white",
    "password": "bold green",
    "warning": "yellow",
    "error": "red",
    "success": "green",
}


def cred_status_display(
    cred_status: str | None,
    cred_valid: bool | None,
    cred_hijackable: bool | None,
    cred_code: str | None,
    password_analysis: str | None,
) -> str:
    """Human-readable credential-validation status (shared by printer + writer)."""
    if cred_status == "unknown":
        if password_analysis and "GOOD" in password_analysis.upper():
            return "LIKELY VALID (password newer than pwdLastSet)"
        if password_analysis and "BAD" in password_analysis.upper():
            return "LIKELY INVALID (password older than pwdLastSet)"
        return "UNKNOWN"
    if cred_valid is True:
        return "VALID" if cred_hijackable else f"VALID (restricted: {cred_status})"
    if cred_status == "invalid":
        return "INVALID (wrong password)"
    if cred_status == "blocked":
        return "BLOCKED (account disabled/expired)"
    return f"{cred_status} ({cred_code})"
