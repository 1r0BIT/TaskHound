# LAPS Exceptions and Error Messages

# =============================================================================
# Exceptions
# =============================================================================


class LAPSError(Exception):
    """Base exception for LAPS operations"""

    pass


class LAPSConnectionError(LAPSError):
    """Failed to connect to domain controller via LDAP"""

    pass


class LAPSEmptyCacheError(LAPSError):
    """No LAPS passwords found in Active Directory"""

    pass


class LAPSParseError(LAPSError):
    """Failed to parse LAPS attribute data"""

    pass


# =============================================================================
# Error Messages
# =============================================================================

LAPS_ERRORS = {
    "host_not_found": "{hostname}: No LAPS password found in cache",
    "auth_failed": (
        "{hostname}: LAPS authentication failed\n"
        "Password may have rotated since LDAP query"
    ),
    "encrypted": (
        "{hostname}: LAPS password is encrypted (Windows LAPS)\n"
        "Decryption requires MS-GKDI access on domain controller"
    ),
    "remote_uac": (
        "{hostname}: LAPS authentication succeeded but admin access denied\n"
        "Likely cause: Remote UAC (LocalAccountTokenFilterPolicy=0)\n"
        "\n"
        "This is a Windows security feature that filters local admin tokens\n"
        "for remote connections. The LAPS password is correct, but the\n"
        "resulting session lacks administrative privileges.\n"
        "\n"
        "Solutions:\n"
        "  1. GPO: Set LocalAccountTokenFilterPolicy=1 (DWORD) at\n"
        "     HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n"
        "  2. Use domain credentials with local admin rights instead\n"
        "  3. Servers typically have this disabled by default (workstations don't)"
    ),
    "remote_uac_short": "{hostname}: Remote UAC blocking LAPS admin access",
}
