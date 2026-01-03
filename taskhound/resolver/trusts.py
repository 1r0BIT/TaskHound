# Trust Detection and Handling
#
# Functions for working with Active Directory trusts, determining
# if SIDs are from foreign domains, and classifying trust types.

from dataclasses import dataclass
from typing import Dict, Optional, Set, Union

from impacket.ldap import ldapasn1 as ldapasn1_impacket

from ..utils.logging import debug, info
from .constants import WELL_KNOWN_LOCAL_RIDS, binary_to_sid, get_domain_sid_prefix

# Trust attribute flags from Active Directory
# Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646c877eb42
TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x1
TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x2
TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x4  # SID filtering enabled
TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x8  # Cross-forest trust
TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10
TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20  # Intra-forest trust (parent-child, tree-root)
TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x40
TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 0x80


@dataclass
class TrustInfo:
    """
    Information about a trusted domain for SID resolution.

    Used to determine whether GC lookup is viable (intra-forest) or
    we should use trust FQDN directly (external/cross-forest).
    """
    fqdn: str  # Fully qualified domain name (e.g., "TRUSTEDFOREST.LOCAL")
    is_intra_forest: bool  # True if trust is within the same forest (GC will work)
    trust_attributes: int = 0  # Raw trustAttributes value from AD
    netbios_name: Optional[str] = None  # NETBIOS domain name (e.g., "YOURCOMPANY")

    def __str__(self) -> str:
        trust_type = "intra-forest" if self.is_intra_forest else "external"
        return f"{self.fqdn} ({trust_type})"


# Type alias for backwards compatibility - can be either simple str or TrustInfo
TrustData = Union[str, TrustInfo]


# Track domain prefixes known to be external trusts (different forest)
# GC lookups are useless for these - they're not in the same forest
# This is populated at runtime when GC lookups fail for foreign SIDs
_external_trust_prefixes: Set[str] = set()


def mark_as_external_trust(sid_prefix: str) -> None:
    """
    Mark a domain SID prefix as an external trust (different forest).

    Call this when GC lookup fails for a foreign SID - it tells us
    that this domain is not in our forest, so future GC lookups
    for SIDs from this domain are pointless.

    Args:
        sid_prefix: Domain SID prefix (e.g., "S-1-5-21-111-222-333")
    """
    global _external_trust_prefixes
    _external_trust_prefixes.add(sid_prefix)
    debug(f"Marked {sid_prefix} as external trust (GC lookup skipped for future SIDs)")


def is_known_external_trust(sid_prefix: str) -> bool:
    """
    Check if a domain SID prefix is known to be an external trust.

    Args:
        sid_prefix: Domain SID prefix to check

    Returns:
        True if we've previously determined this domain is external
    """
    return sid_prefix in _external_trust_prefixes


def is_foreign_domain_sid(sid: str, local_domain_sid_prefix: Optional[str]) -> bool:
    """
    Check if a SID belongs to a foreign (trusted) domain.

    Args:
        sid: SID to check
        local_domain_sid_prefix: Known local domain prefix (e.g., "S-1-5-21-123-456-789")

    Returns:
        True if SID is from a different domain than local_domain_sid_prefix
    """
    if not local_domain_sid_prefix:
        return False  # Can't determine without local domain info

    sid_prefix = get_domain_sid_prefix(sid)
    if not sid_prefix:
        return False  # Not a domain SID (built-in, well-known, etc.)

    return sid_prefix != local_domain_sid_prefix


def is_unknown_domain_sid(sid: str, known_domain_prefixes: Dict[str, TrustData]) -> bool:
    """
    Check if a SID is from an unknown domain (not in our known set).

    Unknown domain SIDs are likely local machine accounts that cannot be
    resolved via DC queries. They should either be skipped or displayed
    as "UNKNOWN\\<name>" based on well-known RIDs.

    Args:
        sid: SID to check (e.g., "S-1-5-21-XXXXXXXXXX-...-500")
        known_domain_prefixes: Dict mapping domain SID prefixes to TrustInfo or FQDN strings

    Returns:
        True if SID is from an unknown domain (not in known_domain_prefixes)
    """
    if not known_domain_prefixes:
        return False  # No known prefixes means we can't classify

    sid_prefix = get_domain_sid_prefix(sid)
    if not sid_prefix:
        return False  # Not a domain-style SID (built-in, well-known, etc.)

    return sid_prefix not in known_domain_prefixes


def get_trust_fqdn(trust_data: TrustData) -> str:
    """Extract FQDN from TrustInfo or string."""
    if isinstance(trust_data, TrustInfo):
        return trust_data.fqdn
    return trust_data  # Already a string (backwards compatibility)


def is_external_trust(trust_data: TrustData) -> bool:
    """Check if trust is external (cross-forest) vs intra-forest."""
    if isinstance(trust_data, TrustInfo):
        return not trust_data.is_intra_forest
    # String format (backwards compatibility) - assume external to be safe
    # GC lookup will succeed if it's actually intra-forest
    return False


def resolve_unknown_sid_to_local_name(sid: str) -> Optional[str]:
    """
    Attempt to resolve an unknown domain SID to a local account name.

    For SIDs from unknown domains (likely local machine accounts), we can
    infer the account name from well-known RIDs like 500 (Administrator).

    Args:
        sid: SID to resolve (e.g., "S-1-5-21-XXXXXXXXXX-...-500")

    Returns:
        "UNKNOWN\\<name>" if RID is well-known, None otherwise
    """
    if not sid or not sid.startswith("S-1-5-21-"):
        return None

    try:
        # Extract RID (last component)
        parts = sid.split("-")
        if len(parts) < 8:
            return None

        rid = int(parts[-1])

        # Check if it's a well-known RID
        if rid in WELL_KNOWN_LOCAL_RIDS:
            name = WELL_KNOWN_LOCAL_RIDS[rid]
            return f"UNKNOWN\\{name}"

        # For unknown RIDs >= 1000, these are typically custom local user accounts
        # We can't know the actual name, so just show the RID number as a fallback
        if rid >= 1000:
            return f"UNKNOWN\\User-{rid}"

        return None

    except (ValueError, IndexError):
        return None


def resolve_trust_sid_to_name(sid: str, trust_fqdn: str) -> Optional[str]:
    """
    Resolve a SID from a known trust domain to a displayable name.

    For SIDs from cross-forest trusts where GC lookup isn't possible,
    we use the known trust FQDN to create a UPN-style display for
    well-known RIDs (like Administrator), or show the FQDN + SID for
    unknown accounts.

    Args:
        sid: SID to resolve (e.g., "S-1-5-21-111111111-222222222-333333333-500")
        trust_fqdn: The FQDN of the trusted domain (e.g., "TRUSTEDFOREST.LOCAL")

    Returns:
        For well-known RIDs: "Administrator@TRUSTEDFOREST.LOCAL"
        For unknown RIDs: "TRUSTEDFOREST.LOCAL\\User-1234" or None if unparseable
    """
    if not sid or not sid.startswith("S-1-5-21-") or not trust_fqdn:
        return None

    try:
        # Extract RID (last component)
        parts = sid.split("-")
        if len(parts) < 8:
            return None

        rid = int(parts[-1])

        # Check if it's a well-known RID - use UPN format
        if rid in WELL_KNOWN_LOCAL_RIDS:
            name = WELL_KNOWN_LOCAL_RIDS[rid]
            return f"{name}@{trust_fqdn}"

        # For unknown RIDs >= 1000, show domain with user indicator
        if rid >= 1000:
            return f"{trust_fqdn}\\User-{rid}"

        return None

    except (ValueError, IndexError):
        return None


def fetch_known_domain_sids_via_ldap(
    domain: str,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Dict[str, TrustInfo]:
    """
    Fetch known domain SID prefixes from LDAP (own domain + trusts).

    Queries the domain's own SID and all trusted domain SIDs via LDAP,
    including trust attributes to determine if GC lookup is viable.

    Args:
        domain: Domain name (e.g., "corp.local")
        dc_ip: Domain controller IP
        username: LDAP authentication username
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash
        kerberos: Use Kerberos authentication

    Returns:
        Dict mapping domain SID prefix -> TrustInfo (with FQDN and trust type)
    """
    result: Dict[str, TrustInfo] = {}

    # Validate domain
    if not domain or "." not in domain:
        debug(f"Invalid domain '{domain}' for LDAP domain SID query")
        return result

    if not username or not (password or hashes or kerberos):
        debug("No valid credentials for LDAP domain SID query")
        return result

    try:
        from ..utils.ldap import get_ldap_connection

        conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
        )

        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

        # Query 1: Get own domain's SID from the domain object
        # Own domain is always intra-forest (it's our forest!)
        domain_filter = "(objectClass=domain)"
        try:
            search_results = conn.search(
                searchBase=base_dn,
                searchFilter=domain_filter,
                attributes=["objectSid", "name"],
                searchControls=None,
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        for attribute in entry["attributes"]:
                            attr_name = str(attribute["type"])
                            if attr_name.lower() == "objectsid":
                                binary_sid_val = bytes(attribute["vals"][0])
                                sid_str = binary_to_sid(binary_sid_val)
                                if sid_str:
                                    # Own domain is always intra-forest
                                    result[sid_str] = TrustInfo(
                                        fqdn=domain.upper(),
                                        is_intra_forest=True,
                                        trust_attributes=0,
                                    )
                                    debug(f"Own domain SID: {sid_str} -> {domain} (intra-forest)")
        except Exception as e:
            debug(f"Error querying own domain SID: {e}")

        # Query 2: Get trusted domain SIDs with trustAttributes
        trust_filter = "(objectClass=trustedDomain)"
        try:
            search_results = conn.search(
                searchBase=f"CN=System,{base_dn}",
                searchFilter=trust_filter,
                attributes=["securityIdentifier", "trustPartner", "name", "trustAttributes"],
                searchControls=None,
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        trust_name = None
                        trust_sid = None
                        trust_attrs = 0

                        for attribute in entry["attributes"]:
                            attr_name = str(attribute["type"])
                            if attr_name.lower() == "securityidentifier":
                                binary_sid_val = bytes(attribute["vals"][0])
                                trust_sid = binary_to_sid(binary_sid_val)
                            elif attr_name.lower() in ("trustpartner", "name"):
                                trust_name = str(attribute["vals"][0])
                            elif attr_name.lower() == "trustattributes":
                                try:
                                    trust_attrs = int(attribute["vals"][0])
                                except (ValueError, TypeError):
                                    trust_attrs = 0

                        if trust_sid and trust_name:
                            # Determine if intra-forest based on trustAttributes
                            # TRUST_ATTRIBUTE_WITHIN_FOREST (0x20) = parent-child or tree-root trust
                            is_intra = bool(trust_attrs & TRUST_ATTRIBUTE_WITHIN_FOREST)
                            trust_type = "intra-forest" if is_intra else "external"
                            result[trust_sid] = TrustInfo(
                                fqdn=trust_name.upper(),
                                is_intra_forest=is_intra,
                                trust_attributes=trust_attrs,
                            )
                            debug(f"Trust SID: {trust_sid} -> {trust_name} ({trust_type}, attrs=0x{trust_attrs:x})")

        except Exception as e:
            debug(f"Error querying trust SIDs: {e}")

        if result:
            intra_count = sum(1 for t in result.values() if t.is_intra_forest)
            external_count = len(result) - intra_count
            info(f"Loaded {len(result)} domain SID prefixes via LDAP ({intra_count} intra-forest, {external_count} external)")

    except Exception as e:
        debug(f"Error fetching domain SIDs via LDAP: {e}")

    return result


def reset_external_trust_cache() -> None:
    """Reset the external trust tracking set (for testing)."""
    global _external_trust_prefixes
    _external_trust_prefixes = set()
