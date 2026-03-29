# Built-in Windows service account filtering.
#
# Determines whether a service's start_name (lpServiceStartName) is a
# built-in/virtual account or a domain account worth reporting. Used by
# both online (SVCCTL) and offline (registry hive) enumeration paths.

from typing import Any

# Accounts that are built-in to Windows and never represent stored
# domain credentials. Comparison is case-insensitive.
_BUILTIN_ACCOUNTS = {
    # LocalSystem variants
    "localsystem",
    "nt authority\\system",
    "nt authority\\localsystem",
    ".\\localsystem",
    "system",
    # LocalService variants
    "localservice",
    "nt authority\\localservice",
    "nt authority\\local service",
    ".\\localservice",
    "local service",
    # NetworkService variants
    "networkservice",
    "nt authority\\networkservice",
    "nt authority\\network service",
    ".\\networkservice",
    "network service",
}

# Prefixes that indicate virtual service accounts (NT SERVICE\*, etc.)
_BUILTIN_PREFIXES = (
    "nt service\\",
    "nt authority\\",
)


def is_builtin_account(account: str) -> bool:
    """Check if a service account is a built-in/virtual Windows account.

    These accounts do not store domain credentials and are not
    interesting for credential enumeration.

    Args:
        account: The lpServiceStartName value from SVCCTL or registry

    Returns:
        True if the account is built-in (should be filtered out)
    """
    if not account or not account.strip():
        # Empty/null start_name defaults to LocalSystem
        return True

    normalized = account.strip().lower()

    # Exact match against known built-in accounts
    if normalized in _BUILTIN_ACCOUNTS:
        return True

    # Prefix match for virtual service accounts (NT SERVICE\*, NT AUTHORITY\*)
    return any(normalized.startswith(prefix) for prefix in _BUILTIN_PREFIXES)


def is_domain_account(account: str) -> bool:
    """Check if a service account looks like a domain account.

    Domain accounts come in three formats:
      - DOMAIN\\username
      - username@domain.fqdn (UPN)
      - bare username (ambiguous — could be local, treated as potential domain)

    Args:
        account: The service start_name

    Returns:
        True if the account appears to be a domain account
    """
    if not account or not account.strip():
        return False

    account = account.strip()

    # Already confirmed not built-in by caller, so:
    # DOMAIN\user or user@domain.fqdn are clearly domain
    if "\\" in account or "@" in account:
        return True

    # Bare username — could be local or domain. Since we already
    # filtered built-ins, and local_users enumeration (SAMR) will
    # later exclude known local accounts, we treat bare names as
    # potentially interesting and include them.
    return True


def filter_domain_services(
    services: list[dict[str, Any]],
    local_accounts: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter a list of services to only those running as domain accounts.

    Args:
        services: Raw service dicts from enumerate_services()
        local_accounts: Optional set of known local account names
                       (lowercase) from SAMR enumeration. Used to
                       exclude bare-name matches that are local.

    Returns:
        Filtered list of service dicts with domain accounts only
    """
    local_accounts = local_accounts or set()
    result = []

    for svc in services:
        account = (svc.get("account") or "").strip()

        # Skip built-in accounts
        if is_builtin_account(account):
            continue

        # Skip known local accounts (from SAMR)
        if local_accounts:
            bare = account.split("\\")[-1].lower() if "\\" in account else account.lower()
            # Only filter if it's a bare name or .\username (local prefix)
            if account.lower().startswith(".\\") or ("\\" not in account and "@" not in account):
                if bare in local_accounts:
                    continue

        # Remaining accounts are domain (or ambiguous — include them)
        if is_domain_account(account):
            result.append(svc)

    return result
