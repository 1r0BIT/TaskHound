# Constants and utility functions for SID resolution
#
# Contains well-known SIDs, RIDs, patterns, and simple utility functions
# that don't require network access.

import re
import struct
from functools import lru_cache

from ..utils.logging import debug

# =============================================================================
# Well-Known SIDs
# =============================================================================
# Reference: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
# NOTE: Only includes SIDs commonly found in Scheduled Task RunAs fields

WELL_KNOWN_SIDS = {
    # NT AUTHORITY - Service accounts (common in scheduled tasks)
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
    # NT AUTHORITY - Other (occasionally seen)
    "S-1-5-7": "NT AUTHORITY\\ANONYMOUS LOGON",
    "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
    # BUILTIN domain (S-1-5-32-*) - Groups that might run tasks
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
    # Universal SIDs
    "S-1-1-0": "Everyone",
    "S-1-5-80-0": "NT SERVICE\\ALL SERVICES",
}


# =============================================================================
# Well-Known Local Account RIDs
# =============================================================================
# Common RIDs that we can map to names even without SAM access

WELL_KNOWN_LOCAL_RIDS = {
    # User account RIDs
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    # Group RIDs - common privileged groups
    512: "Domain Admins",
    513: "Domain Users",
    518: "Schema Admins",
    519: "Enterprise Admins",
    # Local user RIDs start at 1000+
}


# =============================================================================
# SID Pattern Detection
# =============================================================================

_SID_PATTERN = re.compile(r"^S-1-\d+(-\d+)+$")


@lru_cache(maxsize=2048)
def is_sid(value: str) -> bool:
    """Check if a string looks like a Windows SID (cached for performance)."""
    if not value:
        return False
    # SID pattern: S-1-<revision>-<authority>-<sub-authorities>
    return bool(_SID_PATTERN.match(value.strip()))


def get_domain_sid_prefix(sid: str) -> str | None:
    """
    Extract domain SID prefix from a full SID.

    Domain SIDs have the format: S-1-5-21-{domain1}-{domain2}-{domain3}-{RID}
    The domain prefix is S-1-5-21-{domain1}-{domain2}-{domain3} (without RID).

    Args:
        sid: Full SID string (e.g., "S-1-5-21-123-456-789-1001")

    Returns:
        Domain prefix (e.g., "S-1-5-21-123-456-789") or None if not a domain SID
    """
    if not sid or not sid.startswith("S-1-5-21-"):
        return None

    parts = sid.split("-")
    # Domain SID: S-1-5-21-{d1}-{d2}-{d3}-{RID} = 8 parts minimum
    if len(parts) < 8:
        return None

    # Return everything except the RID (last part)
    return "-".join(parts[:-1])


def resolve_special_sid_pattern(sid: str) -> str | None:
    """
    Resolve special SID patterns that can't be enumerated statically.

    Handles dynamically-generated SIDs like:
    - Service SIDs (S-1-5-80-*) - NT SERVICE\\<ServiceName>
    - IIS AppPool SIDs (S-1-5-82-*)

    Args:
        sid: SID to check for special patterns

    Returns:
        Descriptive name if special pattern matched, None otherwise
    """
    if not sid:
        return None

    # Service SIDs: S-1-5-80-{hash of service name}
    if sid.startswith("S-1-5-80-"):
        if sid == "S-1-5-80-0":
            return None  # Let WELL_KNOWN_SIDS handle it
        return f"NT SERVICE\\<service> ({sid})"

    # IIS AppPool virtual accounts: S-1-5-82-*
    if sid.startswith("S-1-5-82-"):
        return f"IIS APPPOOL\\<AppPool> ({sid})"

    return None


# =============================================================================
# SID Binary Conversion
# =============================================================================

def sid_to_binary(sid_string: str) -> bytes | None:
    """
    Convert a SID string (S-1-5-21-...) to binary format for LDAP queries.

    Args:
        sid_string: String representation of SID

    Returns:
        Binary representation of SID for LDAP queries, None if invalid
    """
    try:
        if not sid_string.startswith("S-"):
            return None

        parts = sid_string[2:].split("-")
        if len(parts) < 3:
            return None

        revision = int(parts[0])
        authority = int(parts[1])
        subauthorities = [int(x) for x in parts[2:]]

        # Pack the SID according to Windows SID binary format
        # Revision (1 byte) + SubAuthorityCount (1 byte) + Authority (6 bytes) + SubAuthorities (4 bytes each)
        binary_sid = struct.pack("B", revision)  # Revision
        binary_sid += struct.pack("B", len(subauthorities))  # SubAuthorityCount
        binary_sid += struct.pack(">Q", authority)[2:]  # Authority (6 bytes, big-endian)

        for subauth in subauthorities:
            binary_sid += struct.pack("<I", subauth)  # SubAuthorities (little-endian)

        return binary_sid

    except (ValueError, struct.error) as e:
        debug(f"Error converting SID {sid_string} to binary: {e}")
        return None


def binary_to_sid(binary_sid: bytes) -> str | None:
    """
    Convert a binary SID (from LDAP objectSid attribute) to string format.

    Args:
        binary_sid: Binary representation of SID from LDAP

    Returns:
        String representation like "S-1-5-21-...", None if invalid
    """
    try:
        if not binary_sid or len(binary_sid) < 8:
            return None

        # Unpack the SID binary format
        revision = struct.unpack("B", binary_sid[0:1])[0]
        subauth_count = struct.unpack("B", binary_sid[1:2])[0]

        # Authority is 6 bytes, big-endian (bytes 2-8)
        authority = struct.unpack(">Q", b"\x00\x00" + binary_sid[2:8])[0]

        # Build the SID string
        sid_parts = [f"S-{revision}-{authority}"]

        # Extract sub-authorities (4 bytes each, little-endian)
        offset = 8
        for _ in range(subauth_count):
            if offset + 4 > len(binary_sid):
                debug("Binary SID too short for claimed sub-authority count")
                return None
            subauth = struct.unpack("<I", binary_sid[offset : offset + 4])[0]
            sid_parts.append(str(subauth))
            offset += 4

        return "-".join(sid_parts)

    except (ValueError, struct.error) as e:
        debug(f"Error converting binary SID to string: {e}")
        return None


# =============================================================================
# Domain User Detection
# =============================================================================

# Known local domains / authority names (English + common misspellings/localized variants).
LOCAL_DOMAIN_MARKERS = ("nt authority", "nt_autority", "nt_autoritat", "nt_autorität", "localhost")

# Known local users / built-in / service accounts (English + German variants). Bare names
# matching these are almost certainly local accounts, not domain accounts.
LOCAL_USER_NAMES = {
    "system",
    "netzwerkdienst",
    "networkservice",
    "lokaler dienst",
    "localservice",
    "administrator",
    "guest",
    "gast",
    "wdagutilityaccount",
    "defaultaccount",
}


def looks_like_domain_user(runas: str) -> bool:
    r"""
    Return True when `runas` appears to represent a domain account.

    The function returns False for well-known local/system principals
    (including common German translations seen in German-language
    Windows installations). It treats values with a backslash (NETBIOS\user)
    or values containing a dot (user@domain-like or UPN) as domain-like.
    It also recognizes domain SIDs (S-1-5-21-*-*-*-RID) as domain accounts.
    """
    if not runas:
        return False

    val = runas.strip()

    # Check if this is a SID format
    if val.upper().startswith("S-1-"):
        # Exclude well-known local SIDs (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
        up = val.upper()
        if up.startswith("S-1-5-18") or up.startswith("S-1-5-19") or up.startswith("S-1-5-20"):
            return False

        # Domain SIDs have pattern S-1-5-21-domain-domain-domain-rid
        return up.startswith("S-1-5-21-")

    # If username contains a backslash (DOMAIN\user), check for local/system principals
    if "\\" in val:
        domain, user = val.split("\\", 1)
        domain = domain.strip().lower()
        user = user.strip().lower()

        # Known local domains / authority names (English + some common misspellings/variants)
        if any(ld in domain for ld in LOCAL_DOMAIN_MARKERS):
            return False

        # Known local users / service accounts (English + German variants)
        if user in LOCAL_USER_NAMES:
            return False

        # If domain is the computer name (often represented as dot), it's local
        return domain != "."

    # If username contains @ (UPN format), it's likely a domain user
    return "@" in val


def is_bare_name(value: str) -> bool:
    r"""Return True when `value` is a bare account name with no qualifier.

    A bare name is not a SID and has neither a NETBIOS domain prefix (``DOMAIN\user``)
    nor a UPN suffix (``user@domain``). These are the values that scheduled-task
    ``<UserId>`` fields sometimes carry instead of a fully-qualified principal.
    """
    if not value:
        return False
    val = value.strip()
    if not val or is_sid(val):
        return False
    return "\\" not in val and "@" not in val


def is_probably_local_bare_name(value: str) -> bool:
    """Return True when a bare name matches a well-known local/built-in account.

    Used to avoid resolving or matching bare names (e.g. ``Administrator``, ``Guest``,
    localized service accounts) that are almost certainly local accounts rather than
    domain accounts. Returns False for any value that is not a bare name.
    """
    if not is_bare_name(value):
        return False
    return value.strip().lower() in LOCAL_USER_NAMES
