# SID to Name Resolution Chain
#
# Main orchestration for resolving Windows SIDs to human-readable names.
# This implements a multi-tier resolution strategy with clear fallback order.
#
# Resolution Chain (in order):
#   Tier 0: Well-known SIDs (instant, no network)
#   Tier 0.5: Special SID patterns (service SIDs, capability SIDs)
#   Tier 1: Cache lookup (fast, persistent)
#   Tier 2: BloodHound (offline data + API)
#   Tier 3: Target LSARPC (via SMB to task source host)
#   Tier 3.5: DC LSARPC (via SMB to domain controller - handles cross-trust)
#   Tier 4: LDAP (domain controller)
#   Tier 5: Global Catalog (forest-wide, cross-domain)

from typing import Any, Dict, Optional, Tuple

from ..utils.cache_manager import get_cache
from ..utils.logging import debug, info

from .constants import (
    WELL_KNOWN_SIDS,
    get_domain_sid_prefix,
    is_sid,
    resolve_special_sid_pattern,
)
from .trusts import (
    TrustData,
    get_trust_fqdn,
    is_external_trust,
    is_foreign_domain_sid,
    is_known_external_trust,
    is_unknown_domain_sid,
    mark_as_external_trust,
    resolve_trust_sid_to_name,
    resolve_unknown_sid_to_local_name,
)
from .backends import (
    get_discovered_gc_server,
    resolve_sid_from_bloodhound,
    resolve_sid_via_bloodhound_api,
    resolve_sid_via_dc_lsarpc,
    resolve_sid_via_global_catalog,
    resolve_sid_via_ldap,
    resolve_sid_via_smb,
)


def resolve_sid(
    sid: str,
    hv_loader: Optional[Any] = None,
    bh_connector: Optional[Any] = None,
    smb_connection: Optional[Any] = None,
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

    Resolution order:
        Tier 0: Well-known SIDs (static lookup - instant, no network)
        Tier 0.5: Special SID patterns (service SIDs, capability SIDs)
        Tier 1: Cache (SQLite persistent)
        Tier 2: BloodHound (offline data + live API)
        Tier 3: Target LSARPC (SMB to target host)
        Tier 3.5: DC LSARPC (SMB to DC - handles cross-trust)
        Tier 4: LDAP (domain controller query)
        Tier 5: Global Catalog (forest-wide lookup)

    Foreign domain SIDs are handled specially:
        - Intra-forest trusts: DC LSARPC → GC lookup
        - External trusts: DC LSARPC → trust FQDN fallback
        - Unknown domains: DC LSARPC → well-known RID fallback

    Args:
        sid: Windows SID to resolve
        hv_loader: BloodHound HighValueLoader (optional)
        bh_connector: BloodHound API connector (optional)
        smb_connection: Active SMB connection to target (optional)
        no_ldap: Disable LDAP/GC resolution
        no_rpc: Disable all RPC operations
        domain: Domain name for authentication
        dc_ip: Domain controller IP
        username: Authentication username
        password: Authentication password
        hashes: NTLM hashes (lm:nt or just nt)
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos
        ldap_domain: Separate LDAP domain (for local admin scenarios)
        ldap_user: Separate LDAP username
        ldap_password: Separate LDAP password
        ldap_hashes: Separate LDAP NTLM hashes
        local_domain_sid_prefix: Known local domain SID prefix
        known_domain_prefixes: Dict mapping SID prefixes to TrustInfo
        gc_server: Global Catalog server IP (optional, auto-discovers)

    Returns:
        Tuple of (display_name, resolved_username)
        - display_name: For output (e.g., "DOMAIN\\User (S-1-5-21-...)")
        - resolved_username: Just the username (for internal use)
    """
    # Validate input
    if not is_sid(sid):
        return sid, None

    cache = get_cache()

    # =========================================================================
    # Tier 0: Well-known SIDs (instant, no network)
    # =========================================================================
    if sid in WELL_KNOWN_SIDS:
        resolved = WELL_KNOWN_SIDS[sid]
        debug(f"[Tier 0] Well-known SID: {sid} → {resolved}")
        return f"{resolved} ({sid})", resolved

    # =========================================================================
    # Tier 0.5: Special SID patterns (service SIDs, capability SIDs)
    # =========================================================================
    special = resolve_special_sid_pattern(sid)
    if special:
        debug(f"[Tier 0.5] Special pattern: {sid} → {special}")
        return special, None

    # =========================================================================
    # Tier 1: Cache lookup
    # =========================================================================
    if cache:
        cached = cache.get("sids", sid)
        if cached:
            debug(f"[Tier 1] Cache hit: {sid} → {cached}")
            return f"{cached} ({sid})", cached

        # Check failure count
        fail_count = cache.get("sid_failures", sid) or 0
        if fail_count >= 3:
            debug(f"[Tier 1] Skipping {sid} (failed {fail_count} times)")
            return f"{sid} (Unresolvable)", None

    # Helper to cache successful resolution
    def _cache_success(resolved_name: str) -> None:
        if cache:
            cache.set("sids", sid, resolved_name)
            cache.delete("sid_failures", sid)

    # =========================================================================
    # Tier 2: BloodHound (offline data + API)
    # =========================================================================
    resolved = resolve_sid_from_bloodhound(sid, hv_loader)
    if resolved:
        debug(f"[Tier 2] BloodHound offline: {sid} → {resolved}")
        _cache_success(resolved)
        return f"{resolved} ({sid})", resolved

    if bh_connector:
        resolved = resolve_sid_via_bloodhound_api(sid, bh_connector)
        if resolved:
            debug(f"[Tier 2] BloodHound API: {sid} → {resolved}")
            _cache_success(resolved)
            return f"{resolved} ({sid})", resolved

    # =========================================================================
    # Foreign domain detection
    # =========================================================================
    is_foreign = is_foreign_domain_sid(sid, local_domain_sid_prefix)
    sid_prefix = get_domain_sid_prefix(sid) if is_foreign else None
    trust_data = known_domain_prefixes.get(sid_prefix) if (sid_prefix and known_domain_prefixes) else None

    # =========================================================================
    # Handle foreign domain SIDs (different resolution path)
    # =========================================================================
    if is_foreign:
        return _resolve_foreign_sid(
            sid=sid,
            sid_prefix=sid_prefix,
            trust_data=trust_data,
            known_domain_prefixes=known_domain_prefixes,
            no_rpc=no_rpc,
            no_ldap=no_ldap,
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
            aes_key=aes_key,
            ldap_domain=ldap_domain,
            ldap_user=ldap_user,
            ldap_password=ldap_password,
            ldap_hashes=ldap_hashes,
            gc_server=gc_server,
            cache=cache,
            cache_success=_cache_success,
        )

    # =========================================================================
    # Tier 3: Target LSARPC (SMB to target host)
    # =========================================================================
    if smb_connection and not no_rpc:
        resolved = resolve_sid_via_smb(sid, smb_connection)
        if resolved:
            debug(f"[Tier 3] Target LSARPC: {sid} → {resolved}")
            _cache_success(resolved)
            return f"{resolved} ({sid})", resolved

    # =========================================================================
    # Tier 3.5: DC LSARPC (fallback for local domain SIDs)
    # =========================================================================
    if not no_rpc and dc_ip and username:
        sid_prefix_local = get_domain_sid_prefix(sid)
        if sid_prefix_local:
            debug(f"[Tier 3.5] Trying DC LSARPC for local domain SID: {sid}")
            resolved = resolve_sid_via_dc_lsarpc(
                sid, dc_ip, domain, username, password, hashes, kerberos, aes_key
            )
            if resolved:
                debug(f"[Tier 3.5] DC LSARPC: {sid} → {resolved}")
                _cache_success(resolved)
                return f"{resolved} ({sid})", resolved

    # =========================================================================
    # Tier 4: LDAP (domain controller)
    # =========================================================================
    ldap_auth_domain = ldap_domain or domain
    ldap_auth_user = ldap_user or username
    ldap_auth_password = ldap_password or password
    ldap_auth_hashes = ldap_hashes or hashes
    use_kerberos_for_ldap = kerberos and not (ldap_password or ldap_hashes)

    if not no_ldap and ldap_auth_domain and ldap_auth_user:
        resolved = resolve_sid_via_ldap(
            sid, ldap_auth_domain, dc_ip, ldap_auth_user, ldap_auth_password,
            ldap_auth_hashes, use_kerberos_for_ldap
        )
        if resolved:
            debug(f"[Tier 4] LDAP: {sid} → {resolved}")
            _cache_success(resolved)
            return f"{resolved} ({sid})", resolved

    # =========================================================================
    # Resolution failed - check for unknown domain
    # =========================================================================
    if known_domain_prefixes and is_unknown_domain_sid(sid, known_domain_prefixes):
        local_name = resolve_unknown_sid_to_local_name(sid)
        if local_name:
            debug(f"[Fallback] Unknown domain RID: {sid} → {local_name}")
            _cache_success(local_name)
            return f"{local_name} ({sid})", local_name
        debug(f"[Unresolved] Unknown domain: {sid}")
        return f"{sid} (SID - unknown domain)", None

    # Record failure
    if cache:
        cache.increment("sid_failures", sid, max_value=3)

    # Return appropriate message
    if no_ldap:
        return f"{sid} (SID - LDAP disabled)", None
    elif not ldap_auth_domain or not ldap_auth_user:
        return f"{sid} (SID - insufficient auth)", None
    else:
        return f"{sid} (SID - could not resolve)", None


def _resolve_foreign_sid(
    sid: str,
    sid_prefix: Optional[str],
    trust_data: Optional[TrustData],
    known_domain_prefixes: Optional[Dict[str, TrustData]],
    no_rpc: bool,
    no_ldap: bool,
    domain: Optional[str],
    dc_ip: Optional[str],
    username: Optional[str],
    password: Optional[str],
    hashes: Optional[str],
    kerberos: bool,
    aes_key: Optional[str],
    ldap_domain: Optional[str],
    ldap_user: Optional[str],
    ldap_password: Optional[str],
    ldap_hashes: Optional[str],
    gc_server: Optional[str],
    cache: Any,
    cache_success: callable,
) -> Tuple[str, Optional[str]]:
    """
    Handle resolution for foreign domain SIDs (different domain than local).

    Strategy varies by trust type:
    - External trust: DC LSARPC → trust FQDN fallback (GC useless)
    - Intra-forest trust: DC LSARPC → GC lookup
    - Unknown domain: DC LSARPC → well-known RID fallback
    """
    debug(f"[Foreign] Handling foreign domain SID: {sid}")

    # CASE 1: Known external trust (different forest - GC won't help)
    if trust_data and is_external_trust(trust_data):
        trust_fqdn = get_trust_fqdn(trust_data)
        debug(f"[Foreign] External trust: {trust_fqdn}")

        # Try well-known RID first
        trust_name = resolve_trust_sid_to_name(sid, trust_fqdn)
        if trust_name:
            debug(f"[Foreign] Well-known RID: {sid} → {trust_name}")
            cache_success(trust_name)
            info(f"[CROSS-TRUST] SID from {trust_fqdn}")
            return f"[CROSS-TRUST] {trust_name} ({sid})", trust_name

        # Try DC LSARPC (DC can follow trust paths)
        if not no_rpc and dc_ip and username:
            resolved = resolve_sid_via_dc_lsarpc(
                sid, dc_ip, domain, username, password, hashes, kerberos, aes_key
            )
            if resolved:
                debug(f"[Foreign] DC LSARPC: {sid} → {resolved}")
                cache_success(resolved)
                return f"[CROSS-TRUST] {resolved} ({sid})", resolved

        # Fall back to trust FQDN display
        display_name = f"{trust_fqdn}\\SID-{sid.split('-')[-1]}"
        cache_success(display_name)
        info(f"[CROSS-TRUST] Unknown account from {trust_fqdn}")
        return f"[CROSS-TRUST] {display_name} ({sid})", display_name

    # CASE 2: Known cached external trust (previously failed GC)
    if sid_prefix and is_known_external_trust(sid_prefix):
        debug(f"[Foreign] Cached external trust prefix: {sid_prefix}")
        return f"{sid} (SID - external trust)", None

    # CASE 3: Unknown foreign domain (not in BloodHound trust data)
    if sid_prefix and known_domain_prefixes and sid_prefix not in known_domain_prefixes:
        debug(f"[Foreign] Unknown domain prefix: {sid_prefix}")

        # Try DC LSARPC
        if not no_rpc and dc_ip and username:
            resolved = resolve_sid_via_dc_lsarpc(
                sid, dc_ip, domain, username, password, hashes, kerberos, aes_key
            )
            if resolved:
                debug(f"[Foreign] DC LSARPC: {sid} → {resolved}")
                cache_success(resolved)
                return f"{resolved} ({sid})", resolved

        # Fall back to well-known RID
        local_name = resolve_unknown_sid_to_local_name(sid)
        if local_name:
            debug(f"[Foreign] Unknown domain RID: {sid} → {local_name}")
            cache_success(local_name)
            return f"{local_name} ({sid})", local_name

        return f"{sid} (SID - unknown domain)", None

    # CASE 4: Intra-forest trust or unknown - try DC LSARPC then GC
    trust_fqdn = get_trust_fqdn(trust_data) if trust_data else None
    if trust_fqdn:
        debug(f"[Foreign] Intra-forest trust: {trust_fqdn}")

    # Try DC LSARPC first
    if not no_rpc and dc_ip and username:
        resolved = resolve_sid_via_dc_lsarpc(
            sid, dc_ip, domain, username, password, hashes, kerberos, aes_key
        )
        if resolved:
            debug(f"[Foreign] DC LSARPC: {sid} → {resolved}")
            cache_success(resolved)
            return f"{resolved} ({sid})", resolved

    # Try Global Catalog
    ldap_auth_domain = ldap_domain or domain
    ldap_auth_user = ldap_user or username
    ldap_auth_password = ldap_password or password
    ldap_auth_hashes = ldap_hashes or hashes
    use_kerberos_for_ldap = kerberos and not (ldap_password or ldap_hashes)

    if not no_ldap and ldap_auth_domain and ldap_auth_user:
        effective_gc = gc_server or get_discovered_gc_server(ldap_auth_domain)
        resolved = resolve_sid_via_global_catalog(
            sid=sid,
            domain=ldap_auth_domain,
            gc_server=effective_gc,
            username=ldap_auth_user,
            password=ldap_auth_password,
            hashes=ldap_auth_hashes,
            kerberos=use_kerberos_for_ldap,
        )
        if resolved:
            debug(f"[Foreign] GC: {sid} → {resolved}")
            cache_success(resolved)
            return f"{resolved} ({sid})", resolved

        # GC failed - handle based on trust type
        if trust_data and not is_external_trust(trust_data):
            # Intra-forest but GC failed - use trust FQDN
            trust_name = resolve_trust_sid_to_name(sid, trust_fqdn)
            if trust_name:
                cache_success(trust_name)
                return f"{trust_name} ({sid})", trust_name
        elif sid_prefix:
            # Unknown domain - cache as external trust
            mark_as_external_trust(sid_prefix)
            debug(f"[Foreign] Caching {sid_prefix} as external trust")

    # Final fallback
    if trust_fqdn:
        trust_name = resolve_trust_sid_to_name(sid, trust_fqdn)
        if trust_name:
            cache_success(trust_name)
            return f"{trust_name} ({sid})", trust_name

    return f"{sid} (SID - foreign domain)", None


def format_runas_with_sid_resolution(
    runas: str,
    hv_loader: Optional[Any] = None,
    bh_connector: Optional[Any] = None,
    smb_connection: Optional[Any] = None,
    no_ldap: bool = False,
    no_rpc: bool = False,
    domain: Optional[str] = None,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    aes_key: Optional[str] = None,
    kerberos: bool = False,
    ldap_domain: Optional[str] = None,
    ldap_user: Optional[str] = None,
    ldap_password: Optional[str] = None,
    ldap_hashes: Optional[str] = None,
    local_domain_sid_prefix: Optional[str] = None,
    known_domain_prefixes: Optional[Dict[str, TrustData]] = None,
    gc_server: Optional[str] = None,
    # Legacy parameters (accepted but ignored for compatibility)
    ldap_connection: Optional[Any] = None,
    no_bloodhound: bool = False,
    bh_url: Optional[str] = None,
    bh_token_id: Optional[str] = None,
    bh_token_key: Optional[str] = None,
    use_gc: bool = True,
    machine_name: Optional[str] = None,
    trust_data: Optional[TrustData] = None,
    check_foreign: bool = True,
) -> Tuple[str, Optional[str]]:
    """
    Format a RunAs value with SID resolution if applicable.

    This is a compatibility wrapper that delegates to resolve_sid().
    If the input is a SID, resolve it. Otherwise return unchanged.

    Args:
        runas: The RunAs value (may be a SID or already a name)
        ... (same args as resolve_sid)

    Returns:
        Tuple of (display_runas, resolved_username)
        - display_runas: Formatted string for display
        - resolved_username: Just the resolved username (for internal use), or None
    """
    if not runas:
        return runas, None

    # If it's not a SID, return as-is (runas, None)
    if not is_sid(runas):
        return runas, None

    # Resolve the SID - returns (display_name, resolved_name)
    return resolve_sid(
        sid=runas,
        hv_loader=hv_loader,
        bh_connector=bh_connector,
        smb_connection=smb_connection,
        no_ldap=no_ldap,
        no_rpc=no_rpc,
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        hashes=hashes,
        kerberos=kerberos,
        aes_key=aes_key,
        ldap_domain=ldap_domain,
        ldap_user=ldap_user,
        ldap_password=ldap_password,
        ldap_hashes=ldap_hashes,
        local_domain_sid_prefix=local_domain_sid_prefix,
        known_domain_prefixes=known_domain_prefixes,
        gc_server=gc_server,
    )
