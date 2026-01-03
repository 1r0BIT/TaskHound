# Constants and utility functions for SID resolution
#
# Contains well-known SIDs, RIDs, patterns, and simple utility functions
# that don't require network access.

import re
import struct
from functools import lru_cache
from typing import Any, Optional

from ..utils.logging import debug

# =============================================================================
# Trust Attribute Flags
# =============================================================================
# Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646c877eb42

TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x1
TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x2
TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x4  # SID filtering enabled
TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x8  # Cross-forest trust
TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10
TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20  # Intra-forest trust (parent-child, tree-root)
TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x40
TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 0x80


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


def get_domain_sid_prefix(sid: str) -> Optional[str]:
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


def resolve_special_sid_pattern(sid: str) -> Optional[str]:
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


def resolve_rid_to_name(sid: str, domain_prefix: Optional[str] = None) -> Optional[str]:
    """
    Resolve a SID to a name using well-known RIDs.

    Consolidated function that handles both:
    - Unknown domain SIDs → "UNKNOWN\\<name>"
    - Known trust SIDs → "<domain>\\<name>" or "<name>@<domain>"

    Args:
        sid: SID to resolve (e.g., "S-1-5-21-xxx-xxx-xxx-500")
        domain_prefix: Optional domain identifier (FQDN or "UNKNOWN")
                      If None, uses "UNKNOWN"

    Returns:
        Resolved name or None if RID not recognized
    """
    if not sid or not sid.startswith("S-1-5-21-"):
        return None

    try:
        parts = sid.split("-")
        if len(parts) < 8:
            return None

        rid = int(parts[-1])
        prefix = domain_prefix or "UNKNOWN"

        # Check well-known RIDs
        if rid in WELL_KNOWN_LOCAL_RIDS:
            name = WELL_KNOWN_LOCAL_RIDS[rid]
            # Use UPN format for FQDNs (contains dot), backslash for NETBIOS/UNKNOWN
            if "." in prefix:
                return f"{name}@{prefix}"
            return f"{prefix}\\{name}"

        # For unknown RIDs >= 1000, show as User-<RID>
        if rid >= 1000:
            if "." in prefix:
                return f"{prefix}\\User-{rid}"
            return f"{prefix}\\User-{rid}"

        return None

    except (ValueError, IndexError):
        return None


# =============================================================================
# SID Binary Conversion
# =============================================================================

def sid_to_binary(sid_string: str) -> Optional[bytes]:
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


def binary_to_sid(binary_sid: bytes) -> Optional[str]:
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
        local_domain_markers = ("nt authority", "nt_autority", "nt_autoritat", "nt_autorität", "localhost")
        if any(ld in domain for ld in local_domain_markers):
            return False

        # Known local users / service accounts (English + German variants)
        local_user_names = {
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
        if user in local_user_names:
            return False

        # If domain is the computer name (often represented as dot), it's local
        return domain != "."

    # If username contains @ (UPN format), it's likely a domain user
    return "@" in val


def extract_domain_sid_from_hv(hv_loader: Optional[Any]) -> Optional[str]:
    """
    Extract domain SID from BloodHound data. Returns Admin SID (RID 500) for testing.

    Searches through all available SID sources in the HighValueLoader and returns
    the first valid domain SID with RID 500 appended (well-known Administrator).

    Args:
        hv_loader: HighValueLoader instance with BloodHound data

    Returns:
        Domain SID with RID 500 (e.g., "S-1-5-21-XXX-XXX-XXX-500") or None if not found
    """
    if not hv_loader or not getattr(hv_loader, "loaded", False):
        return None

    # Try hv_sids first (keys are SIDs, values are metadata)
    hv_sids = getattr(hv_loader, "hv_sids", {})
    for sid in hv_sids:
        if sid and sid.startswith("S-1-5-21-"):
            parts = sid.split("-")
            if len(parts) >= 7:
                domain_sid = "-".join(parts[:-1])
                return f"{domain_sid}-500"

    # Try other sources (values contain 'objectid' or 'sid' fields)
    sid_sources = [
        getattr(hv_loader, "hv_users", {}),
        getattr(hv_loader, "tier_zero_users", {}),
        getattr(hv_loader, "high_value_users", {}),
    ]

    for source in sid_sources:
        for item in source.values():
            sid = item.get("objectid") or item.get("sid")
            if sid and sid.startswith("S-1-5-21-"):
                parts = sid.split("-")
                if len(parts) >= 7:
                    domain_sid = "-".join(parts[:-1])
                    return f"{domain_sid}-500"

    return None
