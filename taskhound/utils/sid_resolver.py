# SID Resolution utilities for TaskHound
#
# This module handles resolving Windows SIDs to human-readable usernames
# using BloodHound data first, then falling back to LDAP queries when available.
# REFACTORED: Now uses Impacket LDAP with NTLM hash support

import re
import socket
import struct
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from impacket.ldap import ldapasn1 as ldapasn1_impacket

from ..parsers.highvalue import HighValueLoader
from ..utils.cache_manager import get_cache
from ..utils.ldap import LDAPConnectionError, get_ldap_connection
from ..utils.logging import debug, info, status, warn

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

# Cached Global Catalog server discovered via DNS
# This is populated on first GC lookup attempt to avoid repeated DNS queries
_discovered_gc_server: Optional[str] = None
_gc_discovery_attempted: bool = False

# Lazy-loaded NETBIOS → FQDN mapping cache
# Populated on first lookup from LDAP (crossRef + trustedDomain objects)
_netbios_to_fqdn_cache: Dict[str, str] = {}
_netbios_cache_loaded: bool = False
_netbios_cache_ldap_creds: Optional[Dict[str, Any]] = None  # Stored for lazy loading


def set_netbios_ldap_credentials(
    domain: str,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> None:
    """
    Store LDAP credentials for lazy NETBIOS resolution.

    Call this at startup with LDAP credentials. The actual LDAP query
    will only happen on first NETBIOS lookup (lazy loading).

    Args:
        domain: Domain FQDN (e.g., "corp.local")
        dc_ip: Domain controller IP
        username: LDAP username
        password: LDAP password
        hashes: NTLM hashes
        kerberos: Use Kerberos auth
    """
    global _netbios_cache_ldap_creds
    _netbios_cache_ldap_creds = {
        "domain": domain,
        "dc_ip": dc_ip,
        "username": username,
        "password": password,
        "hashes": hashes,
        "kerberos": kerberos,
    }


def resolve_netbios_to_fqdn(netbios_name: str) -> Optional[str]:
    """
    Resolve a NETBIOS domain name to its FQDN.

    Uses lazy loading: first lookup triggers LDAP query for all NETBIOS mappings
    from both crossRef (own forest) and trustedDomain (external trusts) objects.

    Args:
        netbios_name: NETBIOS domain name (e.g., "YOURCOMPANY", "TRUSTEDDOM")

    Returns:
        FQDN (e.g., "corp.example.com") or None if not found
    """
    global _netbios_to_fqdn_cache, _netbios_cache_loaded

    netbios_upper = netbios_name.upper()

    # Check cache first
    if netbios_upper in _netbios_to_fqdn_cache:
        return _netbios_to_fqdn_cache[netbios_upper]

    # If cache already loaded and not found, return None
    if _netbios_cache_loaded:
        return None

    # Lazy load: query LDAP for all NETBIOS mappings
    if _netbios_cache_ldap_creds:
        _load_netbios_cache_from_ldap()
        # Check again after loading
        return _netbios_to_fqdn_cache.get(netbios_upper)

    # No credentials stored - can't query LDAP
    debug("NETBIOS resolution unavailable - no LDAP credentials stored")
    return None


def add_netbios_mapping(netbios_name: str, fqdn: str) -> None:
    """
    Manually add a NETBIOS → FQDN mapping to the cache.

    Use this to populate the cache from BloodHound or other sources.

    Args:
        netbios_name: NETBIOS domain name (e.g., "YOURCOMPANY")
        fqdn: Fully qualified domain name (e.g., "corp.example.com")
    """
    global _netbios_to_fqdn_cache
    _netbios_to_fqdn_cache[netbios_name.upper()] = fqdn.upper()


def get_netbios_cache() -> Dict[str, str]:
    """
    Get the current NETBIOS → FQDN cache.

    Useful for OpenGraph and other consumers that need all mappings.

    Returns:
        Dict mapping NETBIOS names to FQDNs
    """
    global _netbios_to_fqdn_cache, _netbios_cache_loaded

    # Trigger lazy load if not yet loaded
    if not _netbios_cache_loaded and _netbios_cache_ldap_creds:
        _load_netbios_cache_from_ldap()

    return _netbios_to_fqdn_cache.copy()


def _load_netbios_cache_from_ldap() -> None:
    """
    Load NETBIOS mappings from LDAP (internal helper).

    Queries two sources:
    1. crossRef objects in Configuration partition (own forest domains)
    2. trustedDomain objects in System container (external trusts)
    """
    global _netbios_to_fqdn_cache, _netbios_cache_loaded

    if _netbios_cache_loaded:
        return

    _netbios_cache_loaded = True  # Mark as loaded even if query fails (avoid retry loops)

    if not _netbios_cache_ldap_creds:
        return

    creds = _netbios_cache_ldap_creds
    domain = creds["domain"]
    dc_ip = creds["dc_ip"]
    username = creds["username"]
    password = creds["password"]
    hashes = creds["hashes"]
    kerberos = creds["kerberos"]

    if not domain or "." not in domain:
        debug("NETBIOS cache: Invalid domain, skipping LDAP query")
        return

    debug("NETBIOS cache: Loading mappings from LDAP (lazy load triggered)")

    try:
        from impacket.ldap.ldapasn1 import SearchResultEntry

        from ..utils.ldap import LDAPConnectionError, get_ldap_connection

        conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
        )

        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

        # Query 1: crossRef objects (own forest domains)
        config_dn = f"CN=Partitions,CN=Configuration,{base_dn}"
        crossref_filter = "(&(objectClass=crossRef)(nETBIOSName=*)(dnsRoot=*))"

        try:
            results = conn.search(
                searchBase=config_dn,
                searchFilter=crossref_filter,
                attributes=["nETBIOSName", "dnsRoot"],
            )

            for result in results:
                if not isinstance(result, SearchResultEntry):
                    continue

                netbios = None
                fqdn = None

                for attr in result["attributes"]:
                    attr_type = str(attr["type"]).lower()
                    if attr_type == "netbiosname" and attr["vals"]:
                        netbios = str(attr["vals"][0]).upper()
                    elif attr_type == "dnsroot" and attr["vals"]:
                        fqdn = str(attr["vals"][0]).upper()

                if netbios and fqdn:
                    _netbios_to_fqdn_cache[netbios] = fqdn
                    debug(f"NETBIOS cache: {netbios} -> {fqdn} (crossRef)")

        except Exception as e:
            debug(f"NETBIOS cache: crossRef query failed: {e}")

        # Query 2: trustedDomain objects (external trusts)
        system_dn = f"CN=System,{base_dn}"
        trust_filter = "(objectClass=trustedDomain)"

        try:
            results = conn.search(
                searchBase=system_dn,
                searchFilter=trust_filter,
                attributes=["flatName", "trustPartner"],
            )

            for result in results:
                if not isinstance(result, SearchResultEntry):
                    continue

                netbios = None
                fqdn = None

                for attr in result["attributes"]:
                    attr_type = str(attr["type"]).lower()
                    if attr_type == "flatname" and attr["vals"]:
                        netbios = str(attr["vals"][0]).upper()
                    elif attr_type == "trustpartner" and attr["vals"]:
                        fqdn = str(attr["vals"][0]).upper()

                if netbios and fqdn:
                    _netbios_to_fqdn_cache[netbios] = fqdn
                    debug(f"NETBIOS cache: {netbios} -> {fqdn} (trustedDomain)")

        except Exception as e:
            debug(f"NETBIOS cache: trustedDomain query failed: {e}")

        conn.close()

        if _netbios_to_fqdn_cache:
            debug(f"NETBIOS cache: Loaded {len(_netbios_to_fqdn_cache)} mappings from LDAP")
        else:
            debug("NETBIOS cache: No mappings found in LDAP")

    except LDAPConnectionError as e:
        debug(f"NETBIOS cache: LDAP connection failed: {e}")
    except Exception as e:
        debug(f"NETBIOS cache: Unexpected error: {e}")


def get_discovered_gc_server(domain: str) -> Optional[str]:
    """
    Get a Global Catalog server for the domain, discovering via DNS if needed.

    Results are cached module-wide to avoid repeated DNS lookups.
    Call this during warmup/init or on first GC lookup attempt.

    Args:
        domain: Forest root domain name (e.g., "corp.local")

    Returns:
        GC server hostname/IP if discovered, None otherwise
    """
    global _discovered_gc_server, _gc_discovery_attempted

    # Return cached result if we've already attempted discovery
    if _gc_discovery_attempted:
        return _discovered_gc_server

    _gc_discovery_attempted = True

    if not domain or "." not in domain:
        debug(f"Invalid domain '{domain}' for GC discovery")
        return None

    try:
        from ..utils.dns import discover_global_catalog_servers

        gc_servers = discover_global_catalog_servers(domain)
        if gc_servers:
            _discovered_gc_server = gc_servers[0]  # Use first (highest priority)
            debug(f"Cached discovered GC server: {_discovered_gc_server}")
            return _discovered_gc_server
        else:
            debug(f"No GC servers discovered via DNS for domain {domain}")
    except Exception as e:
        debug(f"GC discovery failed: {e}")

    return None


def resolve_sid_via_smb(sid: str, smb_connection) -> Optional[str]:
    """
    Resolve SID to username using LSARPC over an existing SMB connection.

    This is useful when we have a valid SMB session (e.g. via Kerberos CIFS ticket)
    but cannot authenticate to the DC via LDAP (e.g. missing TGT/LDAP ticket).

    Args:
        sid: Windows SID to resolve
        smb_connection: Active impacket.smbconnection.SMBConnection

    Returns:
        Resolved username (DOMAIN\\User) or None
    """
    if not smb_connection:
        return None

    try:
        from impacket.dcerpc.v5 import lsad, lsat, transport
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        debug(f"Attempting SMB/LSARPC resolution for SID: {sid}")

        # Connect to LSARPC pipe
        # We reuse the existing SMB connection
        rpctransport = transport.SMBTransport(
            smb_connection.getRemoteName(),
            smb_connection.getRemoteHost(),
            filename=r"\lsarpc",
            smb_connection=smb_connection,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)

        # Open policy using lsad module (hLsarOpenPolicy2 is in lsad, not lsat)
        # We need POLICY_LOOKUP_NAMES to resolve SIDs
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp["PolicyHandle"]

        # Lookup SID
        try:
            resp = lsat.hLsarLookupSids(dce, policyHandle, [sid], lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            names = resp["TranslatedNames"]["Names"]
            domains = resp["ReferencedDomains"]["Domains"]

            if names:
                name_entry = names[0]
                domain_idx = name_entry["DomainIndex"]
                name = name_entry["Name"]

                # If we have a domain index, try to resolve domain name too
                domain_name = ""
                if domain_idx >= 0 and domain_idx < len(domains):
                    domain_name = domains[domain_idx]["Name"]

                full_name = f"{domain_name}\\{name}" if domain_name else name
                info(f"Resolved SID {sid} to {full_name} via SMB/LSARPC")
                return full_name

        except DCERPCException as e:
            debug(f"LSARPC lookup failed for {sid}: {e}")
        finally:
            # Always try to close the handle if we opened it, though dce.disconnect handles cleanup usually
            pass

        dce.disconnect()

    except Exception as e:
        debug(f"SMB SID resolution failed: {e}")

    return None


def resolve_sid_via_dc_lsarpc(
    sid: str,
    dc_ip: str,
    domain: str,
    username: str,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
) -> Optional[str]:
    """
    Resolve SID to username using LSARPC directly to the Domain Controller.

    Unlike resolve_sid_via_smb() which queries the TARGET machine, this function
    queries the DC directly. The DC can resolve SIDs from trusted domains by
    following the trust path - making this ideal for cross-domain/cross-forest
    SID resolution.

    Args:
        sid: Windows SID to resolve
        dc_ip: Domain Controller IP address
        domain: Domain name for authentication
        username: Username for authentication
        password: Password (plaintext or LM:NT hash format)
        hashes: NTLM hashes in LM:NT format (alternative to password)
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos authentication

    Returns:
        Resolved username (DOMAIN\\User) or None
    """
    if not dc_ip or not username:
        return None

    try:
        from impacket.dcerpc.v5 import lsad, lsat, transport
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        debug(f"Attempting DC LSARPC resolution for SID: {sid} via {dc_ip}")

        # Parse hashes if provided
        lmhash = ""
        nthash = ""
        pwd = password or ""

        if hashes:
            if ":" in hashes:
                lmhash, nthash = hashes.split(":", 1)
            else:
                nthash = hashes
            pwd = ""  # Don't use password when hashes provided
        elif password and ":" in password and len(password) == 65:
            # Password might be in hash format
            lmhash, nthash = password.split(":", 1)
            pwd = ""

        # Create RPC transport to DC's LSARPC pipe
        # Use named pipe over SMB (ncacn_np)
        string_binding = f"ncacn_np:{dc_ip}[\\pipe\\lsarpc]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        # Set credentials
        rpc_transport.set_credentials(
            username=username,
            password=pwd,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=aes_key or "",
        )

        if kerberos:
            rpc_transport.set_kerberos(True, kdcHost=dc_ip)

        # Connect and bind
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)

        # Open policy handle
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policy_handle = resp["PolicyHandle"]

        # Lookup SID - use LsapLookupWksta level which follows trusts
        try:
            resp = lsat.hLsarLookupSids(dce, policy_handle, [sid], lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            names = resp["TranslatedNames"]["Names"]
            domains = resp["ReferencedDomains"]["Domains"]

            if names:
                name_entry = names[0]
                domain_idx = name_entry["DomainIndex"]
                name = name_entry["Name"]

                # Build full name with domain prefix
                domain_name = ""
                if domain_idx >= 0 and domain_idx < len(domains):
                    domain_name = domains[domain_idx]["Name"]

                full_name = f"{domain_name}\\{name}" if domain_name else name
                info(f"Resolved SID {sid} to {full_name} via DC LSARPC ({dc_ip})")

                # Clean up
                try:
                    lsad.hLsarClose(dce, policy_handle)
                except Exception:
                    pass
                dce.disconnect()

                return full_name

        except DCERPCException as e:
            # STATUS_NONE_MAPPED means DC couldn't resolve it either
            # This is expected for truly external/unknown SIDs
            if "STATUS_NONE_MAPPED" in str(e):
                debug(f"DC LSARPC: SID {sid} not found (STATUS_NONE_MAPPED)")
            else:
                debug(f"DC LSARPC lookup failed for {sid}: {e}")

        # Clean up
        try:
            lsad.hLsarClose(dce, policy_handle)
        except Exception:
            pass
        dce.disconnect()

    except Exception as e:
        debug(f"DC LSARPC resolution failed for {sid}: {e}")

    return None


# Precompiled SID pattern for performance
_SID_PATTERN = re.compile(r"^S-1-\d+(-\d+)+$")


@lru_cache(maxsize=2048)
def is_sid(value: str) -> bool:
    """Check if a string looks like a Windows SID (cached for performance)."""
    if not value:
        return False
    # SID pattern: S-1-<revision>-<authority>-<sub-authorities>
    # Must have at least revision and authority, sub-authorities are optional but common
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


# Well-known local account RIDs for resolving unknown domain SIDs
# These are common RIDs that we can map to names even without SAM access
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

# Well-known SIDs that can be resolved instantly without any network calls
# Chain 0 in the Multi-Chain SID Resolution architecture
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
    # These are per-service virtual accounts - common in scheduled tasks
    if sid.startswith("S-1-5-80-"):
        if sid == "S-1-5-80-0":
            return None  # Let WELL_KNOWN_SIDS handle it
        return f"NT SERVICE\\<service> ({sid})"

    # IIS AppPool virtual accounts: S-1-5-82-*
    if sid.startswith("S-1-5-82-"):
        return f"IIS APPPOOL\\<AppPool> ({sid})"

    return None


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
        from ..utils.ldap import LDAPConnectionError, get_ldap_connection

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
                                binary_sid = bytes(attribute["vals"][0])
                                sid_str = binary_to_sid(binary_sid)
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
                                binary_sid = bytes(attribute["vals"][0])
                                trust_sid = binary_to_sid(binary_sid)
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

    except LDAPConnectionError as e:
        debug(f"LDAP connection failed for domain SID query: {e}")
    except Exception as e:
        debug(f"Error fetching domain SIDs via LDAP: {e}")

    return result


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
        # We need to pad it to 8 bytes for unpacking as Q
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


def resolve_sid_from_bloodhound(sid: str, hv_loader: Optional[HighValueLoader]) -> Optional[str]:
    """
    Resolve SID to username using BloodHound data.

    Args:
        sid: Windows SID to resolve
        hv_loader: Loaded BloodHound data (can be None)

    Returns:
        Username if found in BloodHound data, None otherwise
    """
    if not hv_loader or not hv_loader.loaded:
        return None

    # Check if SID exists in BloodHound data
    user_data = hv_loader.hv_sids.get(sid)
    if user_data:
        # Try to get samaccountname or name
        username = user_data.get("samaccountname") or user_data.get("name")
        if username:
            info(f"Resolved SID {sid} to {username} via BloodHound data")
            return username.strip().strip('"')

    return None


def resolve_sid_via_bloodhound_api(sid: str, bh_connector) -> Optional[str]:
    """
    Resolve SID to username using live BloodHound API queries.

    This extends offline BloodHound data by querying the live database for SIDs
    that may exist in BloodHound but weren't in the offline export.

    **Roadmap Feature:** Enhanced SID Resolution fallback chain
    Combines BloodHound offline data, live API queries, and LDAP for comprehensive SID lookups.

    Args:
        sid: Windows SID to resolve
        bh_connector: BloodHoundConnector instance with active connection

    Returns:
        Username if found via BloodHound API, None otherwise
    """
    if not bh_connector:
        return None

    try:
        # Build Cypher query to find user or computer by objectId (SID)
        query = f'MATCH (n) WHERE n.objectid = "{sid}" RETURN n.name AS name LIMIT 1'

        data = bh_connector.run_cypher_query(query)

        if data:
            # Extract name from Cypher query result
            if "data" in data and "data" in data["data"] and len(data["data"]["data"]) > 0:
                result = data["data"]["data"][0]
                if result and "name" in result:
                    username = result["name"]
                    info(f"Resolved SID {sid} to {username} via BloodHound API")
                    return username
        else:
            debug("BloodHound API SID query returned no data")

    except Exception as e:
        debug(f"BloodHound API SID resolution failed: {e}")

    return None


def resolve_sid_via_ldap(
    sid: str,
    domain: str,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional[str]:
    """
    Resolve a SID to a username using LDAP queries to a domain controller.

    This function attempts to query Active Directory via LDAP to resolve a SID to a username.
    It uses the provided credentials for authentication and supports both NTLM and Kerberos.
    NOW SUPPORTS NTLM HASH AUTHENTICATION via Impacket LDAP!

    Args:
        sid: The Windows SID to resolve (e.g., "S-1-5-21-...")
        domain: The domain name (e.g., "corp.local")
        dc_ip: Domain controller IP address (optional, will try to resolve from domain if not provided)
        username: LDAP authentication username (can be different from the SID being resolved)
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash (format: lm:nt or just nt)
        kerberos: Use Kerberos authentication

    Returns:
        The resolved username (sAMAccountName), None if resolution fails
    """
    try:
        debug(f"Attempting LDAP resolution for SID: {sid}")

        if not username or not (password or hashes or kerberos):
            debug("No valid credentials provided for LDAP SID resolution")
            return None

        # Validate domain - must be non-empty and contain at least one dot for LDAP DN construction
        if not domain or "." not in domain:
            debug(f"Invalid domain '{domain}' for LDAP SID resolution - must be FQDN")
            return None

        # Convert SID to binary format for LDAP search
        binary_sid = sid_to_binary(sid)
        if not binary_sid:
            warn(f"Could not convert SID {sid} to binary format")
            return None

        # Get LDAP connection using shared utility (handles DC discovery if dc_ip is None)
        try:
            conn = get_ldap_connection(
                dc_ip=dc_ip,
                domain=domain,
                username=username,
                password=password,
                hashes=hashes,
                kerberos=kerberos,
            )
        except LDAPConnectionError as e:
            warn(f"Failed to connect to LDAP server {dc_ip} for SID resolution: {e}")
            return None

        # Build search base DN from domain
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
        debug(f"Using LDAP base DN: {base_dn}")

        # Create search filter using binary SID
        # Impacket expects hex-escaped binary format
        binary_sid_escaped = "".join([f"\\{b:02x}" for b in binary_sid])
        search_filter = f"(objectSid={binary_sid_escaped})"
        debug(f"LDAP search filter: {search_filter}")

        # Perform the search
        try:
            search_results = conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=["sAMAccountName", "name", "displayName", "objectClass"],
                searchControls=None,
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        attributes = {}
                        for attribute in entry["attributes"]:
                            attr_name = str(attribute["type"])
                            attr_vals = [str(val) for val in attribute["vals"]]
                            attributes[attr_name] = attr_vals[0] if len(attr_vals) == 1 else attr_vals

                        # Try different name attributes in order of preference
                        sam_account_name = attributes.get("sAMAccountName")
                        display_name = attributes.get("displayName")
                        name = attributes.get("name")

                        username_resolved = sam_account_name or display_name or name

                        if username_resolved:
                            info(f"Resolved SID {sid} to {username_resolved} via LDAP")
                            return username_resolved.strip()
                        else:
                            debug(f"No usable name attribute found in LDAP entry for SID {sid}")
            else:
                debug(f"No LDAP entries found for SID {sid}")

        except Exception as e:
            warn(f"LDAP search error during SID resolution: {e}")
            return None

        return None

    except Exception as e:
        warn(f"Unexpected error during LDAP SID resolution: {e}")
        debug(f"Full traceback: {e}", exc_info=True)
        return None


def resolve_sid_via_global_catalog(
    sid: str,
    domain: str,
    gc_server: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    nameserver: Optional[str] = None,
    use_tcp: bool = False,
) -> Optional[str]:
    """
    Resolve a SID from a foreign domain within the same AD forest via Global Catalog.

    Global Catalog (ports 3268/3269) contains a partial replica of ALL objects in the
    forest. Use this for resolving SIDs from other domains in the same forest where
    local LDAP (port 389) cannot find them.

    Chain 2 in the Multi-Chain SID Resolution architecture:
    - Skips: LSARPC (STATUS_NONE_MAPPED for foreign SIDs)
    - Skips: Local LDAP (wrong partition - foreign SIDs aren't there)
    - Uses: Global Catalog (forest-wide partial replica)

    Args:
        sid: The Windows SID to resolve
        domain: Forest root domain name (for GC discovery)
        gc_server: Global Catalog server IP (optional, auto-discovers if not provided)
        username: Authentication username
        password: Authentication password
        hashes: NTLM hashes (format: lm:nt or just nt)
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos
        nameserver: DNS server for GC discovery
        use_tcp: Force DNS over TCP (for SOCKS proxies)

    Returns:
        The resolved username (sAMAccountName), None if resolution fails
    """
    from ..utils.ldap import LDAPConnectionError, get_global_catalog_connection

    try:
        debug(f"Attempting Global Catalog resolution for foreign SID: {sid}")

        if not username or not (password or hashes or kerberos):
            debug("No valid credentials provided for GC SID resolution")
            return None

        if not domain or "." not in domain:
            debug(f"Invalid domain '{domain}' for GC SID resolution")
            return None

        # Convert SID to binary format for LDAP search
        binary_sid = sid_to_binary(sid)
        if not binary_sid:
            warn(f"Could not convert SID {sid} to binary format for GC lookup")
            return None

        # Get Global Catalog connection
        try:
            gc_conn = get_global_catalog_connection(
                gc_server=gc_server,
                domain=domain,
                username=username,
                password=password,
                hashes=hashes,
                kerberos=kerberos,
                aes_key=aes_key,
                nameserver=nameserver,
                use_tcp=use_tcp,
            )
        except LDAPConnectionError as e:
            debug(f"Failed to connect to Global Catalog: {e}")
            return None

        # Global Catalog searches use empty base DN for forest-wide search
        # or the forest root DN (we'll use forest root for consistency)
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
        debug(f"Using GC search base: {base_dn}")

        # Create search filter using binary SID
        binary_sid_escaped = "".join([f"\\{b:02x}" for b in binary_sid])
        search_filter = f"(objectSid={binary_sid_escaped})"
        debug(f"GC search filter: {search_filter}")

        # Perform the search
        # GC partial replica includes sAMAccountName and objectSid
        try:
            search_results = gc_conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=["sAMAccountName", "name", "displayName"],
                searchControls=None,
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        attributes = {}
                        for attribute in entry["attributes"]:
                            attr_name = str(attribute["type"])
                            attr_vals = [str(val) for val in attribute["vals"]]
                            attributes[attr_name] = attr_vals[0] if len(attr_vals) == 1 else attr_vals

                        sam_account_name = attributes.get("sAMAccountName")
                        display_name = attributes.get("displayName")
                        name = attributes.get("name")

                        username_resolved = sam_account_name or display_name or name

                        if username_resolved:
                            # Sanity check: ensure we didn't somehow get the SID back as the "name"
                            resolved_str = username_resolved.strip()
                            if resolved_str.startswith("S-1-") or resolved_str == sid:
                                debug(f"GC returned SID as name attribute for {sid} - treating as not found. Raw attributes: {attributes}")
                            else:
                                info(f"Resolved foreign SID {sid} to {resolved_str} via Global Catalog")
                                return resolved_str
                        else:
                            # GC found the object but no name attributes - this shouldn't happen
                            # for normal user/computer objects. Log all attributes for debugging.
                            debug(f"GC entry for SID {sid} has no sAMAccountName/displayName/name. Raw attributes: {attributes}")
            else:
                debug(f"No GC entries found for SID {sid}")

        except Exception as e:
            warn(f"GC search error during SID resolution: {e}")
            return None

        return None

    except Exception as e:
        warn(f"Unexpected error during GC SID resolution: {e}")
        debug(f"Full traceback: {e}", exc_info=True)
        return None


def resolve_name_to_sid_via_ldap(
    name: str,
    domain: str,
    is_computer: bool = False,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional[str]:
    """
    Resolve a computer name or username to its SID using LDAP.
    Results are cached persistently to avoid redundant LDAP queries.
    NOW SUPPORTS NTLM HASH AUTHENTICATION via Impacket LDAP!

    Args:
        name: Computer name (without domain) or username (USER@DOMAIN.TLD format or just USER)
        domain: Domain name (e.g., "corp.local")
        is_computer: True if resolving a computer account, False for user
        dc_ip: Domain controller IP address (optional, will try to resolve if not provided)
        username: LDAP authentication username (can be different from the name being resolved)
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash (format: lm:nt or just nt)
        kerberos: Use Kerberos authentication

    Returns:
        SID string (e.g., "S-1-5-21-..."), None if resolution fails
    """
    # Check cache first (before any processing)
    from ..utils.cache_manager import get_cache
    cache = get_cache()

    if cache and is_computer:
        # Normalize for cache key: strip $ and domain suffix
        cache_name = name.upper()
        if cache_name.endswith("$"):
            cache_name = cache_name[:-1]
        if "." in cache_name:
            cache_name = cache_name.split(".")[0]
        cache_key = f"name:{cache_name}:{domain.upper()}"

        cached_sid = cache.get("computers", cache_key)
        if cached_sid:
            debug(f"Cache hit for computer {name}: {cached_sid}")
            return cached_sid
    else:
        cache_key = None  # Only cache computers for now

    # Validate domain - must be non-empty and contain at least one dot for LDAP DN construction
    if not domain or "." not in domain:
        debug(f"Invalid domain '{domain}' for LDAP resolution - must be FQDN (e.g., 'corp.local')")
        return None

    try:
        # Extract just the name part if it's in USER@DOMAIN format
        search_name = name
        if "@" in name and not is_computer:
            search_name = name.split("@")[0]

        # For computers, strip the trailing $ if present
        if is_computer and search_name.endswith("$"):
            search_name = search_name[:-1]

        # For computers, also strip the domain suffix (FQDN -> hostname)
        # e.g., "testclient2.badsuccessor.lab" -> "testclient2"
        if is_computer and "." in search_name:
            search_name = search_name.split(".")[0]

        # If no DC IP provided, try to resolve it
        if not dc_ip:
            try:
                dc_ip = socket.gethostbyname(domain)
                debug(f"Resolved domain {domain} to DC IP: {dc_ip}")
            except socket.gaierror:
                warn(f"Could not resolve domain {domain} to IP address")
                return None

        # Get LDAP connection using shared utility (handles DC discovery if dc_ip is None)
        try:
            conn = get_ldap_connection(
                dc_ip=dc_ip,
                domain=domain,
                username=username,
                password=password,
                hashes=hashes,
                kerberos=kerberos,
            )
        except LDAPConnectionError as e:
            warn(f"Failed to connect to LDAP server for name resolution: {e}")
            return None

        debug(f"Successfully bound to LDAP server {dc_ip}")

        # Build search base DN from domain
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
        debug(f"Using LDAP base DN: {base_dn}")

        # Create search filter based on object type
        if is_computer:
            # For computers, search by cn (computer name without $)
            search_filter = f"(&(objectClass=computer)(cn={search_name}))"
        else:
            # For users, try both samAccountName and userPrincipalName
            if "@" in name:
                search_filter = f"(&(objectClass=user)(|(userPrincipalName={name})(samAccountName={search_name})))"
            else:
                search_filter = f"(&(objectClass=user)(samAccountName={search_name}))"

        debug(f"LDAP search filter: {search_filter}")

        # Perform the search
        try:
            search_results = conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=["objectSid", "sAMAccountName", "cn"],
                searchControls=None,
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        attributes = {}
                        for attribute in entry["attributes"]:
                            attr_name = str(attribute["type"])
                            # objectSid is binary, keep as bytes
                            if attr_name.lower() == "objectsid":
                                # Get raw bytes
                                attr_vals = [bytes(val) for val in attribute["vals"]]
                            else:
                                attr_vals = [str(val) for val in attribute["vals"]]
                            attributes[attr_name] = attr_vals[0] if len(attr_vals) == 1 else attr_vals

                        # Extract the binary objectSid
                        binary_sid = attributes.get("objectSid")

                        if binary_sid and isinstance(binary_sid, bytes):
                            # Convert binary SID to string
                            sid_string = binary_to_sid(binary_sid)

                            if sid_string:
                                account_name = attributes.get("sAMAccountName") or attributes.get("cn") or name
                                info(f"Resolved {account_name} to SID {sid_string} via LDAP")
                                # Cache for future lookups (computers only)
                                if cache and cache_key:
                                    cache.set("computers", cache_key, sid_string)
                                return sid_string
                            else:
                                debug(f"Failed to convert binary SID to string for {name}")
                        else:
                            debug(f"No objectSid attribute found in LDAP entry for {name}")
            else:
                debug(f"No LDAP entries found for {name}")

        except Exception as e:
            warn(f"LDAP search error during name→SID resolution: {e}")
            return None

        return None

    except Exception as e:
        warn(f"Unexpected error during LDAP name→SID resolution: {e}")
        debug(f"Full traceback: {e}", exc_info=True)
        return None


def resolve_name_to_sid(
    name: str,
    domain: str,
    is_computer: bool = False,
    hv_loader=None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional[str]:
    """
    Resolve a name (computer or user) to its SID using a multi-tier fallback chain.

    Fallback order:
    1. Cache (fast, persistent)
    2. BloodHound data (if hv_loader provided)
    3. LDAP query (if credentials provided)

    Args:
        name: Computer name (FQDN or hostname) or username
        domain: Domain name (e.g., "corp.local")
        is_computer: True if resolving a computer account, False for user
        hv_loader: HighValueLoader with BloodHound data (optional)
        dc_ip: Domain controller IP address
        username: LDAP authentication username
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash
        kerberos: Use Kerberos authentication

    Returns:
        SID string (e.g., "S-1-5-21-..."), None if resolution fails
    """
    if not name:
        return None

    # Normalize name for lookups
    lookup_name = name.upper()
    if is_computer:
        # Strip trailing $ and domain suffix
        if lookup_name.endswith("$"):
            lookup_name = lookup_name[:-1]
        if "." in lookup_name:
            lookup_name = lookup_name.split(".")[0]

    # Tier 1: Check cache first
    cache = get_cache()
    if cache:
        cache_key = f"name:{lookup_name}:{domain.upper() if domain else 'LOCAL'}"
        cache_type = "computers" if is_computer else "users"
        cached_sid = cache.get(cache_type, cache_key)
        if cached_sid:
            debug(f"Cache hit for {name}: {cached_sid}")
            return cached_sid

    # Tier 2: Try BloodHound data
    if hv_loader and hasattr(hv_loader, "loaded") and hv_loader.loaded:
        if is_computer:
            # Try hv_computers dict (maps hostname → SID)
            hv_computers = getattr(hv_loader, "hv_computers", {})
            if hv_computers:
                sid = hv_computers.get(lookup_name)
                if sid:
                    debug(f"Resolved {name} to {sid} via BloodHound computer data")
                    # Cache for future lookups
                    if cache:
                        cache.set("computers", cache_key, sid)
                    return sid
        else:
            # Try hv_users dict (maps samaccountname → metadata with SID)
            hv_users = getattr(hv_loader, "hv_users", {})
            if hv_users:
                # Try exact match first
                user_data = hv_users.get(lookup_name) or hv_users.get(lookup_name.lower())
                if user_data:
                    sid = user_data.get("sid") or user_data.get("objectid")
                    if sid:
                        debug(f"Resolved {name} to {sid} via BloodHound data")
                        # Cache for future lookups
                        if cache:
                            cache.set("users", cache_key, sid)
                        return sid

    # Tier 3: Try LDAP if credentials available
    if domain and username and (password or hashes):
        sid = resolve_name_to_sid_via_ldap(
            name=name,
            domain=domain,
            is_computer=is_computer,
            dc_ip=dc_ip,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
        )
        if sid:
            # Already cached by resolve_name_to_sid_via_ldap
            return sid

    debug(f"Could not resolve {name} to SID (checked cache, BloodHound, LDAP)")
    return None


def prefetch_computer_sids(
    targets: List[str],
    domain: str,
    hv_loader=None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Dict[str, str]:
    """
    Batch pre-fetch computer SIDs for known targets before scanning begins.

    This function efficiently resolves computer SIDs for all targets upfront,
    using BloodHound data first (instant) and falling back to LDAP only for
    computers not found in BloodHound. Results are cached for the scan.

    Fallback order:
    1. BloodHound data (if hv_loader provided with hv_computers)
    2. Cache (check if already resolved)
    3. Batch LDAP query for remaining computers

    Args:
        targets: List of target hostnames (FQDN or short names)
        domain: Domain name (e.g., "corp.local")
        hv_loader: HighValueLoader with BloodHound data (optional)
        dc_ip: Domain controller IP address
        username: LDAP authentication username
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash
        kerberos: Use Kerberos authentication

    Returns:
        Dict mapping normalized hostname -> SID for all resolved targets
    """
    if not targets:
        return {}

    resolved: Dict[str, str] = {}
    remaining: List[str] = []
    cache = get_cache()

    # Normalize all target names
    normalized_targets = {}
    for target in targets:
        # Strip domain suffix and normalize to uppercase
        hostname = target.upper()
        if "." in hostname:
            hostname = hostname.split(".")[0]
        normalized_targets[hostname] = target

    # Step 1: Check BloodHound data first (instant lookups)
    bh_hits = 0
    if hv_loader and hasattr(hv_loader, "hv_computers") and hv_loader.hv_computers:
        hv_computers = hv_loader.hv_computers
        for hostname, _original in normalized_targets.items():
            sid = hv_computers.get(hostname)
            if sid:
                resolved[hostname] = sid
                bh_hits += 1
                # Cache the result
                if cache:
                    cache_key = f"name:{hostname}:{domain.upper() if domain else 'LOCAL'}"
                    cache.set("computers", cache_key, sid)

        if bh_hits > 0:
            status(f"[SID Prefetch] {bh_hits} computer SIDs from BloodHound")

    # Step 2: Check cache for remaining
    cache_hits = 0
    for hostname in normalized_targets:
        if hostname in resolved:
            continue

        if cache:
            cache_key = f"name:{hostname}:{domain.upper() if domain else 'LOCAL'}"
            cached_sid = cache.get("computers", cache_key)
            if cached_sid:
                resolved[hostname] = cached_sid
                cache_hits += 1
            else:
                remaining.append(hostname)
        else:
            remaining.append(hostname)

    if cache_hits > 0:
        debug(f"Pre-fetch: {cache_hits} computer SIDs from cache")

    # Step 3: Batch LDAP query for remaining (if credentials available)
    if remaining and domain and username and (password or hashes):
        debug(f"Pre-fetch: Querying LDAP for {len(remaining)} remaining computers")
        for hostname in remaining:
            sid = resolve_name_to_sid_via_ldap(
                name=hostname,
                domain=domain,
                is_computer=True,
                dc_ip=dc_ip,
                username=username,
                password=password,
                hashes=hashes,
                kerberos=kerberos,
            )
            if sid:
                resolved[hostname] = sid
                # Already cached by resolve_name_to_sid_via_ldap

        ldap_resolved = len(resolved) - bh_hits - cache_hits
        if ldap_resolved > 0:
            status(f"[SID Prefetch] {ldap_resolved} computer SIDs via LDAP")

    total = len(resolved)
    if total > 0:
        debug(f"Pre-fetch complete: {total} computer SIDs resolved")

    return resolved


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


def extract_domain_sid_from_hv(hv_loader: Optional[HighValueLoader]) -> Optional[str]:
    """
    Extract domain SID from BloodHound data. Returns Admin SID (RID 500) for testing.

    Searches through all available SID sources in the HighValueLoader and returns
    the first valid domain SID with RID 500 appended (well-known Administrator).

    Args:
        hv_loader: HighValueLoader instance with BloodHound data

    Returns:
        Domain SID with RID 500 (e.g., "S-1-5-21-XXX-XXX-XXX-500") or None if not found
    """
    if not hv_loader or not hv_loader.loaded:
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


def resolve_sid(
    sid: str,
    hv_loader: Optional[HighValueLoader] = None,
    bh_connector=None,
    smb_connection=None,
    no_ldap: bool = False,
    no_rpc: bool = False,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
    local_domain_sid_prefix: Optional[str] = None,
    known_domain_prefixes: Optional[Dict[str, TrustData]] = None,
    gc_server: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Comprehensive SID resolution with multi-tier fallback chain.

    Fallback order:
    0. Well-known SIDs (static lookup - instant, no network)
    1. Cache (SQLite)
    2. BloodHound offline data (JSON file from --bloodhound flag)
    3. BloodHound live API (if bh_connector provided and has active connection)
    4. SMB/LSARPC via existing connection (uses target's LSA to resolve SIDs)
       - SKIPPED for foreign domain SIDs (different domain prefix)
       - SKIPPED if no_rpc=True
    5. DC LSARPC (queries DC directly - can resolve trusted domain SIDs)
       - Only for foreign domain SIDs
       - SKIPPED if no_rpc=True
    6. LDAP queries to domain controller (if credentials provided and not disabled)
    7. Global Catalog for foreign/cross-domain SIDs

    For unknown domain SIDs (not matching any known domain prefix), falls back to
    UNKNOWN\\<name> based on well-known RIDs (e.g., 500 -> UNKNOWN\\Administrator).

    For foreign domain SIDs from known trusts:
    - Intra-forest trusts: Try DC LSARPC, then GC lookup
    - External trusts: Try DC LSARPC (follows trust path), then trust FQDN fallback

    Args:
        sid: Windows SID to resolve
        hv_loader: BloodHound data loader (optional)
        bh_connector: BloodHound API connector (optional, for live queries)
        smb_connection: Active SMB connection to target (optional, for LSARPC)
        no_ldap: Disable LDAP/GC resolution
        no_rpc: Disable RPC operations (target LSARPC and DC LSARPC)
        domain: Domain name for LDAP
        dc_ip: Domain controller IP
        username: Authentication username
        password: Authentication password
        hashes: NTLM hashes
        kerberos: Use Kerberos
        aes_key: AES key for Kerberos
        ldap_domain: Separate LDAP domain (for local admin case)
        ldap_user: Separate LDAP username (for local admin case)
        ldap_password: Separate LDAP password (for local admin case - plaintext only)
        ldap_hashes: Separate LDAP NTLM hashes (for local admin case - use instead of ldap_password)
        local_domain_sid_prefix: Known local domain SID prefix for foreign domain detection
        known_domain_prefixes: Dict mapping SID prefixes to TrustInfo (with trust type) or FQDN strings
        gc_server: Global Catalog server IP (optional, auto-discovers if not provided)

    Returns:
        Tuple of (display_name, resolved_username)
        - display_name: What to show in output (SID + username or just SID)
        - resolved_username: Just the resolved username (for internal use)
    """
    if not is_sid(sid):
        # Not a SID, return as-is
        return sid, None

    # Chain 0: Well-known SIDs - instant static lookup (no network, no cache needed)
    # This handles S-1-5-18 (SYSTEM), S-1-5-32-* (BUILTIN), etc.
    if sid in WELL_KNOWN_SIDS:
        resolved = WELL_KNOWN_SIDS[sid]
        debug(f"SID {sid} resolved via well-known SID table: {resolved}")
        return f"{resolved} ({sid})", resolved

    # Chain 0.5: Special SID patterns (service SIDs, capability SIDs, etc.)
    # These are dynamically-generated SIDs that can be identified by pattern
    special = resolve_special_sid_pattern(sid)
    if special:
        debug(f"SID {sid} resolved via special pattern detection: {special}")
        return special, None  # No clean username for display purposes

    # Check cache first
    cache = get_cache()
    if cache:
        cached_username = cache.get("sids", sid)
        if cached_username:
            debug(f"Using cached SID resolution: {sid} → {cached_username}")
            return f"{cached_username} ({sid})", cached_username

        # Check fail count atomically to prevent race conditions
        # increment() returns value > 3 if already at max, allowing us to skip
        fail_count = cache.get("sid_failures", sid) or 0
        if fail_count >= 3:
            debug(f"Skipping resolution for {sid} (failed {fail_count} times previously)")
            return f"{sid} (Unresolvable)", None

    debug(f"Attempting to resolve SID: {sid}")

    # Helper to cache success and clear failures
    def _cache_success(resolved_name):
        if cache:
            cache.set("sids", sid, resolved_name)
            cache.delete("sid_failures", sid)

    # Tier 1: Try BloodHound offline data first
    debug("Tier 1 check")
    resolved = resolve_sid_from_bloodhound(sid, hv_loader)
    if resolved:
        debug(f"SID {sid} resolved via BloodHound offline data: {resolved}")
        _cache_success(resolved)
        return f"{resolved} ({sid})", resolved

    # Tier 2: Try BloodHound live API if connector available
    if bh_connector:
        resolved = resolve_sid_via_bloodhound_api(sid, bh_connector)
        if resolved:
            debug(f"SID {sid} resolved via BloodHound API: {resolved}")
            _cache_success(resolved)
            return f"{resolved} ({sid})", resolved

    # Check for foreign domain SID before attempting LSARPC
    # Foreign SIDs cannot be resolved via local domain's LSARPC (returns STATUS_NONE_MAPPED)
    is_foreign = is_foreign_domain_sid(sid, local_domain_sid_prefix)
    sid_prefix = get_domain_sid_prefix(sid) if is_foreign else None
    trust_data = known_domain_prefixes.get(sid_prefix) if (sid_prefix and known_domain_prefixes) else None

    if is_foreign:
        debug(f"SID {sid} is from foreign domain (prefix mismatch with {local_domain_sid_prefix}), skipping LSARPC")

        # Check if this is a KNOWN trust
        if trust_data:
            trust_fqdn = get_trust_fqdn(trust_data)
            is_external = is_external_trust(trust_data)

            if is_external:
                # EXTERNAL TRUST: GC won't have these objects
                # Strategy: Try well-known RIDs first, then DC LSARPC (DC can follow trust path)
                debug(f"SID {sid} is from EXTERNAL trust {trust_fqdn} - skipping GC (different forest)")

                # First try well-known RID resolution using trust FQDN
                trust_name = resolve_trust_sid_to_name(sid, trust_fqdn)
                if trust_name:
                    debug(f"SID {sid} resolved via external trust to {trust_fqdn}: {trust_name}")
                    _cache_success(trust_name)
                    info(f"[CROSS-TRUST] SID from {trust_fqdn} - for full resolution, collect BloodHound data from trusted domain")
                    return f"[CROSS-TRUST] {trust_name} ({sid})", trust_name

                # Not a well-known RID - try DC LSARPC (DC can resolve cross-trust SIDs)
                if not no_rpc and dc_ip and username:
                    resolved = resolve_sid_via_dc_lsarpc(
                        sid, dc_ip, domain, username, password, hashes, kerberos, aes_key
                    )
                    if resolved:
                        debug(f"SID {sid} resolved via DC LSARPC: {resolved}")
                        _cache_success(resolved)
                        return f"[CROSS-TRUST] {resolved} ({sid})", resolved

                # DC couldn't resolve - show domain context with the trust FQDN we know
                debug(f"SID {sid} from external trust {trust_fqdn} - RID not well-known, DC couldn't resolve")
                display_name = f"{trust_fqdn}\\SID-{sid.split('-')[-1]}"
                _cache_success(display_name)
                info(f"[CROSS-TRUST] Unknown account from {trust_fqdn} - collect BloodHound data from trusted domain for full resolution")
                return f"[CROSS-TRUST] {display_name} ({sid})", display_name
            else:
                # INTRA-FOREST TRUST: GC should have these - continue to GC lookup below
                debug(f"SID {sid} is from INTRA-FOREST trust {trust_fqdn} - will try DC LSARPC then GC lookup")

        # Check if this domain prefix is cached as external trust (failed GC lookup previously)
        elif sid_prefix and sid_prefix in _external_trust_prefixes:
            debug(f"Skipping GC lookup for SID {sid} - domain prefix {sid_prefix} cached as external trust")
            return f"{sid} (SID - external trust, unknown domain)", None

        # UNKNOWN foreign domain - not in BloodHound trust data
        # Try DC LSARPC first (DC can follow trust paths), then fall back to well-known RIDs
        elif sid_prefix and known_domain_prefixes:
            debug(f"SID {sid} is from UNKNOWN domain (prefix {sid_prefix} not in BloodHound)")

            # Try DC LSARPC for unknown foreign domains (DC might still resolve via trust)
            if not no_rpc and dc_ip and username:
                resolved = resolve_sid_via_dc_lsarpc(
                    sid, dc_ip, domain, username, password, hashes, kerberos, aes_key
                )
                if resolved:
                    debug(f"SID {sid} resolved via DC LSARPC: {resolved}")
                    _cache_success(resolved)
                    return f"{resolved} ({sid})", resolved

            # DC couldn't resolve - likely local machine SID
            debug(f"SID {sid} from unknown domain - trying well-known RID fallback")
            local_name = resolve_unknown_sid_to_local_name(sid)
            if local_name:
                debug(f"SID {sid} resolved to {local_name} (unknown domain, likely local machine account)")
                _cache_success(local_name)
                return f"{local_name} ({sid})", local_name
            else:
                # Unknown RID from unknown domain - just return the SID
                debug(f"SID {sid} from unknown domain - cannot resolve (likely local machine account)")
                return f"{sid} (SID - unknown domain, likely local)", None

    # Tier 3: Try SMB/LSARPC if connection available (skip for foreign domain SIDs)
    # This is very useful when using Kerberos CIFS tickets where LDAP auth might fail
    if smb_connection and not is_foreign and not no_rpc:
        resolved = resolve_sid_via_smb(sid, smb_connection)
        if resolved:
            debug(f"SID {sid} resolved via SMB/LSARPC: {resolved}")
            _cache_success(resolved)
            return f"{resolved} ({sid})", resolved

    # Tier 3.5: If target LSARPC failed/skipped and we have DC credentials, try DC LSARPC
    # This catches cases where:
    # - is_foreign is False because we don't have local_domain_sid_prefix (can't detect foreign)
    # - Target LSARPC returned STATUS_NONE_MAPPED (SID is from another domain)
    # - We're operating without BloodHound trust data
    # DC LSARPC can resolve SIDs from ANY trusted domain by following trust paths
    if not no_rpc and dc_ip and username and not is_foreign:
        # Only try this for domain-style SIDs (S-1-5-21-*) that weren't resolved above
        sid_prefix = get_domain_sid_prefix(sid)
        if sid_prefix:
            debug(f"Target LSARPC failed/skipped - trying DC LSARPC as fallback for {sid}")
            resolved = resolve_sid_via_dc_lsarpc(
                sid, dc_ip, domain, username, password, hashes, kerberos, aes_key
            )
            if resolved:
                debug(f"SID {sid} resolved via DC LSARPC (fallback): {resolved}")
                _cache_success(resolved)
                return f"{resolved} ({sid})", resolved

    # Tier 4: Try LDAP if enabled and we have sufficient authentication info
    # Prioritize dedicated LDAP credentials over main auth credentials
    ldap_auth_domain = ldap_domain if ldap_domain else domain
    ldap_auth_user = ldap_user if ldap_user else username
    ldap_auth_password = ldap_password if ldap_password else password
    ldap_auth_hashes = ldap_hashes if ldap_hashes else hashes

    # Only use Kerberos for LDAP if no explicit LDAP credentials provided
    # This prevents using wrong service ticket (CIFS vs LDAP)
    use_kerberos_for_ldap = kerberos and not (ldap_password or ldap_hashes)

    # For foreign domain SIDs, skip local LDAP (it won't have them) and go straight to GC
    if not no_ldap and ldap_auth_domain and ldap_auth_user:
        if not is_foreign:
            # Local domain SID - try local LDAP (port 389/636)
            debug(f"Attempting LDAP resolution for SID {sid}")
            resolved = resolve_sid_via_ldap(
                sid, ldap_auth_domain, dc_ip, ldap_auth_user, ldap_auth_password, ldap_auth_hashes, use_kerberos_for_ldap
            )
            if resolved:
                debug(f"SID {sid} resolved via LDAP: {resolved}")
                _cache_success(resolved)
                return f"{resolved} ({sid})", resolved
        else:
            # Chain 2: Foreign domain SID - try Global Catalog
            # External trusts are already handled above (they skip GC)
            # If we get here, it's either an intra-forest trust or unknown foreign domain
            debug(f"Attempting Global Catalog resolution for foreign SID {sid}")
            # Use explicit gc_server if provided, otherwise discover via DNS
            # Do NOT assume DC is also a GC - that's unreliable
            effective_gc_server = gc_server
            if not effective_gc_server:
                effective_gc_server = get_discovered_gc_server(ldap_auth_domain)
            resolved = resolve_sid_via_global_catalog(
                sid=sid,
                domain=ldap_auth_domain,
                gc_server=effective_gc_server,  # Explicit GC or DNS-discovered, None triggers auto-discovery
                username=ldap_auth_user,
                password=ldap_auth_password,
                hashes=ldap_auth_hashes,
                kerberos=use_kerberos_for_ldap,
            )
            if resolved:
                debug(f"SID {sid} resolved via Global Catalog: {resolved}")
                _cache_success(resolved)
                return f"{resolved} ({sid})", resolved
            else:
                # GC lookup failed - this could be:
                # 1. Intra-forest trust but object not replicated to GC (unusual)
                # 2. External trust (different forest, not in GC)
                # 3. Unknown domain we don't have trust data for
                # Try DC LSARPC as fallback - DC can follow trust paths

                if trust_data and not is_external_trust(trust_data):
                    # Known intra-forest trust but GC failed - try DC LSARPC
                    trust_fqdn = get_trust_fqdn(trust_data)
                    debug(f"GC lookup failed for INTRA-FOREST trust SID {sid} from {trust_fqdn} - trying DC LSARPC")

                    if not no_rpc and dc_ip and username:
                        resolved = resolve_sid_via_dc_lsarpc(
                            sid, dc_ip, domain, username, password, hashes, kerberos, aes_key
                        )
                        if resolved:
                            debug(f"SID {sid} resolved via DC LSARPC: {resolved}")
                            _cache_success(resolved)
                            return f"{resolved} ({sid})", resolved

                    # Fall back to trust FQDN display
                    trust_name = resolve_trust_sid_to_name(sid, trust_fqdn)
                    if trust_name:
                        _cache_success(trust_name)
                        return f"{trust_name} ({sid})", trust_name

                elif sid_prefix:
                    # Unknown foreign domain (no BloodHound trust data)
                    # Try DC LSARPC - might be a trust we just don't know about
                    if not no_rpc and dc_ip and username:
                        debug(f"GC failed for unknown foreign SID {sid} - trying DC LSARPC")
                        resolved = resolve_sid_via_dc_lsarpc(
                            sid, dc_ip, domain, username, password, hashes, kerberos, aes_key
                        )
                        if resolved:
                            debug(f"SID {sid} resolved via DC LSARPC: {resolved}")
                            _cache_success(resolved)
                            return f"{resolved} ({sid})", resolved

                    # DC couldn't resolve either - cache as external trust for future lookups
                    _external_trust_prefixes.add(sid_prefix)
                    debug(f"GC and DC LSARPC failed for foreign SID {sid} - caching domain prefix {sid_prefix} as unreachable trust")
                else:
                    debug(f"GC lookup failed for foreign SID {sid} - may be external trust (different forest)")

    # Check if this is an unknown domain SID (not matching any known domain)
    # This is likely a local machine account that cannot be resolved via DC
    is_unknown_domain = False
    if known_domain_prefixes:
        is_unknown_domain = is_unknown_domain_sid(sid, known_domain_prefixes)
        if is_unknown_domain:
            debug(f"SID {sid} is from unknown domain (not in {len(known_domain_prefixes)} known prefixes)")
            # Try to resolve to UNKNOWN\<name> based on well-known RIDs
            local_name = resolve_unknown_sid_to_local_name(sid)
            if local_name:
                # Determine if this is a well-known RID or a fallback
                try:
                    rid = int(sid.split("-")[-1])
                    if rid in WELL_KNOWN_LOCAL_RIDS:
                        debug(f"SID {sid} resolved to {local_name} (unknown domain, well-known RID {rid})")
                    else:
                        debug(f"SID {sid} resolved to {local_name} (unknown domain, local account RID {rid})")
                except (ValueError, IndexError):
                    debug(f"SID {sid} resolved to {local_name} (unknown domain)")
                _cache_success(local_name)
                return f"{local_name} ({sid})", local_name

    # Could not resolve - return SID with appropriate explanation
    if cache:
        # Atomically increment fail count to prevent race conditions in multi-threaded scenarios
        # Using atomic increment ensures multiple threads don't all pass the check and then all increment
        fail_count = cache.increment("sid_failures", sid, max_value=3)
        if fail_count <= 3:
            debug(f"SID {sid} resolution failed (attempt {fail_count}/3)")
        # If fail_count > 3, we've exceeded max (shouldn't happen with atomic increment)

    if is_unknown_domain:
        debug(f"SID {sid} not resolved: unknown domain SID (possibly local machine account)")
        return f"{sid} (SID - unknown domain)", None
    elif no_ldap:
        debug(f"SID {sid} not resolved: LDAP resolution disabled")
        return f"{sid} (SID - LDAP resolution disabled)", None
    elif not ldap_auth_domain or not ldap_auth_user:
        debug(f"SID {sid} not resolved: insufficient authentication information")
        return f"{sid} (SID - insufficient auth for LDAP resolution)", None
    elif is_foreign:
        debug(f"SID {sid} not resolved: foreign domain SID (cross-trust)")
        return f"{sid} (SID - foreign domain/trust)", None
    else:
        debug(f"SID {sid} not resolved: could not find in BloodHound offline, BloodHound API, SMB, or LDAP")
        return f"{sid} (SID - could not resolve: deleted user or access denied)", None


def batch_get_user_attributes(
    usernames: list[str],
    domain: str,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    attributes: list[str] = None,
) -> dict[str, dict]:
    """
    Batch query LDAP for user attributes (pwdLastSet, etc.).

    Results are cached in both session memory and persistent SQLite cache.
    Uses a single LDAP connection for all queries (efficient batching).

    Args:
        usernames: List of usernames to query (DOMAIN\\user or just user format)
        domain: Domain name (FQDN format, e.g., "domain.local")
        dc_ip: Domain controller IP address
        username: LDAP authentication username
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos authentication (128 or 256 bit)
        attributes: List of attributes to fetch (default: pwdLastSet, lastLogon)

    Returns:
        Dictionary mapping normalized username (lowercase, no domain) to attribute dict
        e.g., {"jsmith": {"pwdLastSet": datetime(...), "lastLogon": datetime(...)}}
    """
    if not usernames:
        return {}

    if attributes is None:
        attributes = ["pwdLastSet", "lastLogon", "sAMAccountName", "objectSid"]

    # Normalize usernames - extract just the username part
    users_to_query = set()
    username_mapping = {}  # original -> normalized
    for user in usernames:
        if not user:
            continue
        # Strip domain prefix if present (DOMAIN\user -> user)
        normalized = user.split("\\")[-1].lower() if "\\" in user else user.lower()
        users_to_query.add(normalized)
        username_mapping[user] = normalized

    if not users_to_query:
        return {}

    # Validate domain - must be non-empty and contain at least one dot for LDAP DN construction
    if not domain or "." not in domain:
        debug(f"Invalid domain '{domain}' for batch user attribute lookup - must be FQDN")
        return {}

    # Check cache first
    cache = get_cache()
    results = {}
    users_needing_query = []

    for norm_user in users_to_query:
        cached = cache.get("user_attrs", norm_user) if cache else None
        if cached:
            results[norm_user] = cached
            debug(f"Cache hit for user attributes: {norm_user}")
        else:
            users_needing_query.append(norm_user)

    if not users_needing_query:
        debug(f"All {len(results)} user attribute lookups satisfied from cache")
        return results

    debug(f"Querying LDAP for {len(users_needing_query)} users (cached: {len(results)})")

    # Query LDAP for remaining users (get_ldap_connection handles DC discovery if dc_ip is None)
    try:
        conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
            aes_key=aes_key,
        )
    except LDAPConnectionError as e:
        warn(f"LDAP connection failed for user attribute lookup: {e}")
        return results

    # Build base DN
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    # Query users in batches using OR filter
    # LDAP has limits on filter size, so batch in groups of 20
    BATCH_SIZE = 20
    for i in range(0, len(users_needing_query), BATCH_SIZE):
        batch = users_needing_query[i:i + BATCH_SIZE]

        # Build OR filter for batch
        if len(batch) == 1:
            search_filter = f"(&(objectClass=user)(sAMAccountName={batch[0]}))"
        else:
            user_filters = "".join([f"(sAMAccountName={u})" for u in batch])
            search_filter = f"(&(objectClass=user)(|{user_filters}))"

        debug(f"LDAP batch query for {len(batch)} users")

        try:
            search_results = conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=attributes,
                searchControls=None,
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        entry_attrs = {}
                        sam_name = None

                        for attribute in entry["attributes"]:
                            attr_name = str(attribute["type"])
                            attr_vals = [str(val) for val in attribute["vals"]]

                            if attr_name.lower() == "samaccountname":
                                sam_name = attr_vals[0].lower() if attr_vals else None
                            elif attr_name.lower() == "pwdlastset":
                                # Convert Windows FILETIME to Unix timestamp then datetime
                                try:
                                    filetime = int(attr_vals[0]) if attr_vals else 0
                                    if filetime > 0:
                                        # Windows FILETIME is 100-nanosecond intervals since 1601
                                        unix_ts = (filetime - 116444736000000000) / 10000000
                                        from datetime import datetime, timezone
                                        # Use UTC timezone for consistency with task date parsing
                                        entry_attrs["pwdLastSet"] = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                                except (ValueError, OSError):
                                    pass
                            elif attr_name.lower() == "lastlogon":
                                try:
                                    filetime = int(attr_vals[0]) if attr_vals else 0
                                    if filetime > 0:
                                        unix_ts = (filetime - 116444736000000000) / 10000000
                                        from datetime import datetime, timezone
                                        # Use UTC timezone for consistency
                                        entry_attrs["lastLogon"] = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                                except (ValueError, OSError):
                                    pass
                            elif attr_name.lower() == "objectsid" and attr_vals:
                                # Binary SID - convert to string
                                try:
                                    binary_sid = attribute["vals"][0].asOctets()
                                    sid_str = binary_to_sid(binary_sid)
                                    if sid_str:
                                        entry_attrs["sid"] = sid_str
                                except (ValueError, TypeError, AttributeError):
                                    pass  # Malformed SID data

                        if sam_name and entry_attrs:
                            results[sam_name] = entry_attrs
                            # Cache the result
                            if cache:
                                # Convert datetime to timestamp for JSON serialization
                                cache_entry = {}
                                for k, v in entry_attrs.items():
                                    if hasattr(v, 'timestamp'):
                                        cache_entry[k] = v.timestamp()
                                    else:
                                        cache_entry[k] = v
                                cache.set("user_attrs", sam_name, cache_entry)
                            debug(f"Got attributes for {sam_name}: pwdLastSet={entry_attrs.get('pwdLastSet')}")

        except Exception as e:
            warn(f"LDAP batch query error: {e}")
            continue

    info(f"Retrieved attributes for {len(results)} users via LDAP")
    return results


def get_user_pwd_last_set(
    username: str,
    domain: str,
    dc_ip: Optional[str] = None,
    auth_username: Optional[str] = None,
    auth_password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional["datetime"]:
    """
    Get pwdLastSet for a single user (with caching).

    Convenience wrapper around batch_get_user_attributes for single user lookup.

    Args:
        username: Username to look up (DOMAIN\\user or just user)
        domain: Domain name
        dc_ip: Domain controller IP
        auth_username: LDAP auth username
        auth_password: LDAP auth password
        hashes: NTLM hashes
        kerberos: Use Kerberos

    Returns:
        datetime of password last set, or None if not found
    """
    # Normalize username
    norm_user = username.split("\\")[-1].lower() if "\\" in username else username.lower()

    # Check cache first
    cache = get_cache()
    if cache:
        cached = cache.get("user_attrs", norm_user)
        if cached:
            pwd_ts = cached.get("pwdLastSet")
            if pwd_ts:
                from datetime import datetime
                if isinstance(pwd_ts, (int, float)):
                    return datetime.fromtimestamp(pwd_ts)
                return pwd_ts

    # Query LDAP
    results = batch_get_user_attributes(
        usernames=[username],
        domain=domain,
        dc_ip=dc_ip,
        username=auth_username,
        password=auth_password,
        hashes=hashes,
        kerberos=kerberos,
        attributes=["pwdLastSet", "sAMAccountName"],
    )

    if norm_user in results:
        return results[norm_user].get("pwdLastSet")

    return None


def format_runas_with_sid_resolution(
    runas: str,
    hv_loader: Optional[HighValueLoader] = None,
    bh_connector=None,
    smb_connection=None,
    no_ldap: bool = False,
    no_rpc: bool = False,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
    local_domain_sid_prefix: Optional[str] = None,
    known_domain_prefixes: Optional[Dict[str, TrustData]] = None,
    gc_server: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Format RunAs field with SID resolution if needed.

    Args:
        runas: The RunAs field value to potentially resolve
        hv_loader: BloodHound data loader (optional)
        bh_connector: BloodHound API connector (optional, for live queries)
        smb_connection: Active SMB connection (optional)
        no_ldap: Disable LDAP resolution
        no_rpc: Disable all RPC operations (both target LSARPC and DC LSARPC)
        domain: Domain name for LDAP
        dc_ip: Domain controller IP
        username: Authentication username
        password: Authentication password
        hashes: NTLM hashes
        kerberos: Use Kerberos
        aes_key: AES key for Kerberos (optional)
        ldap_domain: Separate LDAP domain (for local admin case)
        ldap_user: Separate LDAP username (for local admin case)
        ldap_password: Separate LDAP password (for local admin case - plaintext only)
        ldap_hashes: Separate LDAP NTLM hashes (for local admin case - use instead of ldap_password)
        local_domain_sid_prefix: Known local domain SID prefix for foreign domain detection
        known_domain_prefixes: Dict mapping SID prefixes to TrustInfo (with trust type) or FQDN strings
        gc_server: Global Catalog server IP (optional, auto-discovers if not provided)

    Returns:
        Tuple of (display_runas, resolved_username)
        - display_runas: Formatted string for display
        - resolved_username: Just the resolved username (for internal use)
    """
    if not runas:
        return runas, None

    # Check if it's a SID
    if is_sid(runas):
        return resolve_sid(
            runas,
            hv_loader,
            bh_connector,
            smb_connection,
            no_ldap,
            no_rpc,
            domain,
            dc_ip,
            username,
            password,
            hashes,
            kerberos,
            aes_key,
            ldap_domain,
            ldap_user,
            ldap_password,
            ldap_hashes,
            local_domain_sid_prefix,
            known_domain_prefixes,
            gc_server,
        )
    else:
        # Regular username, return as-is
        return runas, None



# Well-known privileged group RIDs (relative to domain SID)
# These are the primary Tier-0 groups that grant domain-wide administrative access
TIER0_GROUP_RIDS = {
    512: "Domain Admins",
    519: "Enterprise Admins",
    518: "Schema Admins",
    516: "Domain Controllers",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}

# Well-known privileged ACCOUNT RIDs (these are accounts, not groups)
# Users with these RIDs are inherently Tier-0
TIER0_ACCOUNT_RIDS = {
    500: "Domain Administrator",  # Built-in Administrator account
    502: "krbtgt",  # Kerberos TGT service account
}

# Well-known built-in privileged groups (fixed SIDs)
TIER0_BUILTIN_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-551": "Backup Operators",
}


# Type alias for Tier-0 cache: normalized_username -> (is_tier0, list_of_group_names)
Tier0Cache = Dict[str, Tuple[bool, List[str]]]


def fetch_tier0_members(
    domain: str,
    dc_ip: Optional[str] = None,
    auth_username: Optional[str] = None,
    auth_password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
) -> Tier0Cache:
    """
    Pre-flight fetch of all Tier-0 group members via LDAP.

    This queries each Tier-0 group once and collects all members,
    building a lookup cache. This is more efficient than querying
    per-user membership (O(G) queries vs O(U) queries).

    Uses LDAP_MATCHING_RULE_IN_CHAIN for transitive membership.

    Args:
        domain: Domain name (FQDN format, e.g., "domain.local")
        dc_ip: Domain controller IP address
        auth_username: LDAP authentication username
        auth_password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos authentication (128 or 256 bit)

    Returns:
        Tier0Cache: Dict of normalized_username -> (is_tier0, list_of_group_names)
    """
    tier0_cache: Tier0Cache = {}

    # Validate domain - must be non-empty and contain at least one dot for LDAP DN construction
    if not domain or "." not in domain:
        debug(f"Invalid domain '{domain}' for Tier-0 pre-flight - must be FQDN")
        return tier0_cache

    # Check persistent cache first
    cache = get_cache()
    cache_key = f"tier0_members@{domain.lower()}"
    if cache:
        cached = cache.get("tier0_preflight", cache_key)
        if cached is not None:
            debug(f"Tier-0 pre-flight: Using cached data for {domain}")
            return cached

    # Get LDAP connection (handles DC discovery if dc_ip is None)
    try:
        conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=auth_username or "",
            password=auth_password,
            hashes=hashes,
            kerberos=kerberos,
            aes_key=aes_key,
        )
    except LDAPConnectionError as e:
        debug(f"LDAP connection failed for Tier-0 pre-flight: {e}")
        return tier0_cache

    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    try:
        # Step 1: Get domain SID by querying a domain controller
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"  # Domain Controllers
        search_results = conn.search(
            searchBase=base_dn,
            searchFilter=search_filter,
            attributes=["objectSid"],
            searchControls=None,
        )

        domain_sid = None
        if search_results:
            for entry in search_results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    for attribute in entry["attributes"]:
                        attr_name = str(attribute["type"])
                        if attr_name.lower() == "objectsid":
                            try:
                                binary_sid = attribute["vals"][0].asOctets()
                                sid_str = binary_to_sid(binary_sid)
                                if sid_str:
                                    domain_sid = "-".join(sid_str.split("-")[:-1])
                                    break
                            except (ValueError, TypeError, AttributeError):
                                pass  # Malformed SID data
                    if domain_sid:
                        break

        if not domain_sid:
            debug("Could not determine domain SID for Tier-0 pre-flight")
            return tier0_cache

        debug(f"Tier-0 pre-flight: Domain SID is {domain_sid}")

        # Step 2: Build list of privileged group DNs to query
        group_sids = []
        for rid, _name in TIER0_GROUP_RIDS.items():
            group_sids.append(f"(objectSid={domain_sid}-{rid})")

        # Add built-in groups
        for sid in TIER0_BUILTIN_SIDS:
            group_sids.append(f"(objectSid={sid})")

        search_filter = f"(|{''.join(group_sids)})"
        search_results = conn.search(
            searchBase=base_dn,
            searchFilter=search_filter,
            attributes=["distinguishedName", "sAMAccountName"],
            searchControls=None,
        )

        privileged_groups = []  # List of (dn, samAccountName)
        if search_results:
            for entry in search_results:
                if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                    dn = None
                    sam = None
                    for attribute in entry["attributes"]:
                        attr_name = str(attribute["type"])
                        attr_vals = [str(val) for val in attribute["vals"]]
                        if attr_name.lower() == "distinguishedname" and attr_vals:
                            dn = attr_vals[0]
                        elif attr_name.lower() == "samaccountname" and attr_vals:
                            sam = attr_vals[0]
                    if dn:
                        privileged_groups.append((dn, sam or dn))

        if not privileged_groups:
            debug("Tier-0 pre-flight: No privileged groups found")
            return tier0_cache

        debug(f"Tier-0 pre-flight: Found {len(privileged_groups)} privileged groups")

        # Step 3: Query members of each privileged group (using transitive membership)
        # This gets all users who are members (direct or nested) of each group
        member_groups: Dict[str, List[str]] = {}  # normalized_username -> list of group names

        for group_dn, group_name in privileged_groups:
            # Escape DN for LDAP filter
            escaped_dn = group_dn.replace("\\", "\\5c").replace("(", "\\28").replace(")", "\\29")

            # Query all users who are (transitively) members of this group
            # LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) handles nested groups
            search_filter = f"(&(objectCategory=user)(memberOf:1.2.840.113556.1.4.1941:={escaped_dn}))"

            try:
                search_results = conn.search(
                    searchBase=base_dn,
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    searchControls=None,
                )

                member_count = 0
                if search_results:
                    for entry in search_results:
                        if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                            for attribute in entry["attributes"]:
                                attr_name = str(attribute["type"])
                                if attr_name.lower() == "samaccountname":
                                    for val in attribute["vals"]:
                                        username = str(val).lower()
                                        if username not in member_groups:
                                            member_groups[username] = []
                                        member_groups[username].append(group_name)
                                        member_count += 1

                debug(f"Tier-0 pre-flight: {group_name} has {member_count} members")

            except Exception as e:
                debug(f"Tier-0 pre-flight: Failed to query members of {group_name}: {e}")
                continue

        # Step 4: Also check for privileged accounts by RID (e.g., Administrator RID 500)
        # Query users and check if their RID matches a privileged account
        for rid, account_name in TIER0_ACCOUNT_RIDS.items():
            account_sid = f"{domain_sid}-{rid}"
            search_filter = f"(&(objectCategory=user)(objectSid={account_sid}))"

            try:
                search_results = conn.search(
                    searchBase=base_dn,
                    searchFilter=search_filter,
                    attributes=["sAMAccountName"],
                    searchControls=None,
                )

                if search_results:
                    for entry in search_results:
                        if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                            for attribute in entry["attributes"]:
                                attr_name = str(attribute["type"])
                                if attr_name.lower() == "samaccountname":
                                    for val in attribute["vals"]:
                                        username = str(val).lower()
                                        if username not in member_groups:
                                            member_groups[username] = []
                                        member_groups[username].append(account_name)
                                        debug(f"Tier-0 pre-flight: Found {account_name} account: {username}")
            except Exception as e:
                debug(f"Tier-0 pre-flight: Failed to query {account_name}: {e}")

        # Build final cache
        for username, groups in member_groups.items():
            tier0_cache[username] = (True, groups)

        debug(f"Tier-0 pre-flight: Found {len(tier0_cache)} unique Tier-0 users")

        # Save to persistent cache
        if cache and tier0_cache:
            cache.set("tier0_preflight", cache_key, tier0_cache)

        return tier0_cache

    except Exception as e:
        debug(f"Tier-0 pre-flight failed: {e}")
        return tier0_cache


def check_tier0_membership(
    username: str,
    tier0_cache: Tier0Cache,
) -> Tuple[bool, List[str]]:
    """
    Check if a user is Tier-0 using pre-fetched cache.

    This is the fast lookup function to use after fetch_tier0_members().

    Args:
        username: Username to check (can be DOMAIN\\user or just user)
        tier0_cache: Pre-fetched Tier0Cache from fetch_tier0_members()

    Returns:
        Tuple of (is_tier0, list_of_matching_groups)
    """
    if not username or not tier0_cache:
        return False, []

    # Normalize username - extract just the username part
    if "\\" in username:
        username = username.split("\\")[-1]
    elif "@" in username:
        username = username.split("@")[0]

    username_lower = username.lower()

    # Skip well-known system accounts
    if username_lower in ("system", "local service", "network service"):
        return False, []

    # Simple lookup
    return tier0_cache.get(username_lower, (False, []))


