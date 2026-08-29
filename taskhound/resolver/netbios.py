# NETBIOS Resolution
#
# Maps NETBIOS domain names (e.g., "YOURCOMPANY") to FQDNs (e.g., "corp.example.com")
# Uses lazy loading from LDAP on first lookup.

from typing import Any

from ..utils.helpers import domain_to_base_dn
from ..utils.logging import debug

# Module-level state
_netbios_to_fqdn_cache: dict[str, str] = {}
_netbios_cache_loaded: bool = False
_netbios_cache_ldap_creds: dict[str, Any] | None = None


def set_netbios_ldap_credentials(
    domain: str,
    dc_ip: str | None = None,
    username: str | None = None,
    password: str | None = None,
    hashes: str | None = None,
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


def resolve_netbios_to_fqdn(netbios_name: str) -> str | None:
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


def get_netbios_cache() -> dict[str, str]:
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


def normalize_netbios_domain_to_fqdn(domain_prefix: str) -> str:
    """
    Normalize a NETBIOS domain prefix to FQDN if possible.

    Useful for normalizing LSARPC output like "TRUSTEDDOM\\User" to
    "TRUSTEDDOM.LOCAL\\User" in the final display.

    Args:
        domain_prefix: NETBIOS domain name (e.g., "YOURCOMPANY")

    Returns:
        FQDN if mapping found, otherwise returns original input
    """
    fqdn = resolve_netbios_to_fqdn(domain_prefix)
    return fqdn if fqdn else domain_prefix


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

    if not domain or len(domain) < 3 or "." not in domain:
        debug("NETBIOS cache: Invalid domain, skipping LDAP query")
        return

    debug("NETBIOS cache: Loading mappings from LDAP (lazy load triggered)")

    try:
        from impacket.ldap.ldapasn1 import SearchResultEntry

        from ..utils.ldap import get_ldap_connection

        conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
        )

        base_dn = domain_to_base_dn(domain)

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

    except Exception as e:
        debug(f"NETBIOS cache: Unexpected error: {e}")


def reset_cache() -> None:
    """
    Reset the NETBIOS cache state (useful for testing).
    """
    global _netbios_to_fqdn_cache, _netbios_cache_loaded, _netbios_cache_ldap_creds
    _netbios_to_fqdn_cache = {}
    _netbios_cache_loaded = False
    _netbios_cache_ldap_creds = None
