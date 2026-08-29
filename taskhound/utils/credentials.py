# Credential matching utilities for TaskHound
#
# This module provides shared credential matching utilities used across
# TaskHound modules (printer, online engine, etc.)


from ..dpapi.decryptor import ScheduledTaskCredential


def match_username(username1: str, username2: str) -> bool:
    """
    Match usernames accounting for DOMAIN\\user format variations.

    Handles cases where one username has a domain prefix and the other doesn't,
    or both have different domain prefixes but the same username part.

    Args:
        username1: First username to compare (may be "user" or "DOMAIN\\user")
        username2: Second username to compare (may be "user" or "DOMAIN\\user")

    Returns:
        True if the usernames match (exact or by username part), False otherwise

    Examples:
        >>> match_username("jdoe", "jdoe")
        True
        >>> match_username("CORP\\jdoe", "jdoe")
        True
        >>> match_username("jdoe", "CORP\\jdoe")
        True
        >>> match_username("CORP\\jdoe", "OTHERDOMAIN\\jdoe")
        True
        >>> match_username("jdoe", "admin")
        False
    """
    u1, u2 = username1.lower(), username2.lower()

    # Exact match
    if u1 == u2:
        return True

    # Extract username portions:
    #   DOMAIN\user -> user
    #   user@domain.local -> user
    #   user -> user
    def _extract_name(u: str) -> str:
        if "\\" in u:
            return u.split("\\")[-1]
        if "@" in u:
            return u.split("@")[0]
        return u

    return _extract_name(u1) == _extract_name(u2)


def find_password_for_user(
    username: str,
    decrypted_creds: list[ScheduledTaskCredential],
    resolved_username: str | None = None,
) -> str | None:
    """
    Find password for a username from list of decrypted credentials.

    Tries to match the username against all credentials, accounting for
    DOMAIN\\user format variations. Optionally also tries a resolved username
    (e.g., SID resolved to sAMAccountName).

    Args:
        username: Primary username to match (e.g., "jdoe" or "CORP\\jdoe")
        decrypted_creds: List of decrypted DPAPI credentials
        resolved_username: Optional resolved username (e.g., from SID resolution)

    Returns:
        The password if a matching credential is found, None otherwise
    """
    if not decrypted_creds:
        return None

    # Build list of usernames to try
    usernames_to_try = [username.lower()]
    if resolved_username and resolved_username.lower() != username.lower():
        usernames_to_try.append(resolved_username.lower())

    # Also try without SID suffix if present (e.g., "jdoe (S-1-5-21-...)")
    for u in list(usernames_to_try):
        if " (s-1-5-" in u:
            usernames_to_try.append(u.split(" (s-1-5-")[0].strip())

    for cred in decrypted_creds:
        if not cred.username:
            continue

        for try_username in usernames_to_try:
            if match_username(cred.username, try_username):
                return cred.password

    return None
