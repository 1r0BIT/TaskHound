# Name to SID Resolution Chain
#
# Resolves hostnames and usernames to Windows SIDs.
# Simpler chain than SID→Name because names are typically in the local domain.
#
# Resolution Chain:
#   Tier 1: Cache lookup
#   Tier 2: BloodHound data (for computers)
#   Tier 3: LDAP query (objectSid attribute)
#
# TODO: This module will contain the clean implementation

from typing import Any, Dict, List, Optional

from ..utils.logging import debug, status


def resolve_name_to_sid(
    name: str,
    domain: str,
    is_computer: bool = False,
    hv_loader: Optional[Any] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional[str]:
    """
    Resolve a username or computer name to its SID.

    Resolution order:
        1. BloodHound data (if hv_loader provided)
        2. Cache lookup
        3. LDAP query

    Args:
        name: Computer name (without domain) or username
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
    from ..utils.cache_manager import get_cache

    if not name:
        return None

    # Normalize computer name (strip $ suffix and domain parts)
    lookup_name = name.upper()
    if is_computer:
        lookup_name = lookup_name.rstrip("$")
        if "." in lookup_name:
            lookup_name = lookup_name.split(".")[0]

    cache = get_cache()
    cache_key = f"name:{lookup_name}:{domain.upper() if domain else 'LOCAL'}"

    # Tier 1: Check cache
    if cache:
        cached = cache.get("name_to_sid", cache_key)
        if cached:
            debug(f"[Name→SID] Cache hit: {lookup_name} → {cached}")
            return cached

    # Tier 2: BloodHound data (for computers)
    if hv_loader and is_computer:
        if hasattr(hv_loader, "loaded") and hv_loader.loaded:
            if hasattr(hv_loader, "hv_computers") and hv_loader.hv_computers:
                # Try with $ suffix (how BH stores computer names)
                sid = hv_loader.hv_computers.get(f"{lookup_name}$")
                if not sid:
                    # Try without $ suffix
                    sid = hv_loader.hv_computers.get(lookup_name)
                if sid:
                    debug(f"[Name→SID] BloodHound hit: {lookup_name} → {sid}")
                    if cache:
                        cache.set("name_to_sid", cache_key, sid)
                    return sid

    # Tier 3: LDAP query
    from .backends.ldap import resolve_name_to_sid_via_ldap

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

    if sid and cache:
        cache.set("name_to_sid", cache_key, sid)

    return sid


def prefetch_computer_sids(
    targets: List[str],
    domain: str,
    hv_loader: Optional[Any] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
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
        domain: Domain name (e.g., "corp.local") - main auth domain
        hv_loader: HighValueLoader with BloodHound data (optional)
        dc_ip: Domain controller IP address
        username: Main authentication username
        password: Main authentication password
        hashes: Main authentication NTLM hashes
        kerberos: Use Kerberos authentication
        ldap_domain: Override domain for LDAP queries (takes precedence)
        ldap_user: Override username for LDAP queries (takes precedence)
        ldap_password: Override password for LDAP queries (takes precedence)
        ldap_hashes: Override NTLM hashes for LDAP queries (takes precedence)

    Returns:
        Dict mapping normalized hostname -> SID for all resolved targets
    """
    from ..utils.cache_manager import get_cache
    from ..utils.helpers import is_ipv4
    from .backends.ldap import resolve_name_to_sid_via_ldap

    if not targets:
        return {}

    resolved: Dict[str, str] = {}
    remaining: List[str] = []
    cache = get_cache()

    # Normalize all target names
    normalized_targets = {}
    for target in targets:
        # Skip IP addresses - they can't be resolved to SIDs
        if is_ipv4(target):
            continue

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
    # Use LDAP-specific credentials if provided, otherwise fall back to main credentials
    effective_domain = ldap_domain or domain
    effective_user = ldap_user or username
    effective_password = ldap_password or password
    effective_hashes = ldap_hashes or hashes

    # Only proceed with LDAP if we have valid credentials and a proper FQDN domain
    # FQDN must have at least two non-empty parts (e.g., "domain.local", not just ".")
    is_valid_fqdn = effective_domain and "." in effective_domain and len(effective_domain) > 2
    if remaining and is_valid_fqdn and effective_user and (effective_password or effective_hashes):
        debug(f"Pre-fetch: Querying LDAP for {len(remaining)} remaining computers")
        for hostname in remaining:
            sid = resolve_name_to_sid_via_ldap(
                name=hostname,
                domain=effective_domain,
                is_computer=True,
                dc_ip=dc_ip,
                username=effective_user,
                password=effective_password,
                hashes=effective_hashes,
                kerberos=kerberos,
            )
            if sid:
                resolved[hostname] = sid
                # Already cached by resolve_name_to_sid_via_ldap

        ldap_resolved = len(resolved) - bh_hits - cache_hits
        if ldap_resolved > 0:
            status(f"[SID Prefetch] {ldap_resolved} computer SIDs from LDAP")

    # Log results
    total_resolved = len(resolved)
    total_targets = len(normalized_targets)
    if total_resolved < total_targets:
        unresolved = total_targets - total_resolved
        debug(f"Pre-fetch: {unresolved} computers could not be resolved to SIDs")

    return resolved
