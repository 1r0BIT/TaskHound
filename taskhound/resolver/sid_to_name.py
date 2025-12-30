# SID to Name Resolution Chain
#
# Main orchestration for resolving Windows SIDs to human-readable names.
# This implements the multi-tier resolution strategy.
#
# Resolution Chain (in order):
#   Tier 0: Well-known SIDs (instant, no network)
#   Tier 1: Cache lookup (fast, persistent)
#   Tier 2: BloodHound (if available)
#   Tier 3: Target LSARPC (via SMB to target host)
#   Tier 3.5: DC LSARPC (via SMB to domain controller)
#   Tier 4: LDAP (domain controller)
#   Tier 5: Global Catalog (forest-wide, cross-domain)
#
# TODO: This module will be the clean implementation of the resolve_sid() function
# that consolidates the 377-line monster from sid_resolver.py

from typing import Any, Dict, Optional

from ..utils.logging import debug


def resolve_sid(
    sid: str,
    target: Optional[str] = None,
    domain: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    lm_hash: Optional[str] = None,
    nt_hash: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    dc_ip: Optional[str] = None,
    hv: Optional[Any] = None,
    known_domain_prefixes: Optional[Dict[str, Any]] = None,
    local_domain_sid_prefix: Optional[str] = None,
    nameserver: Optional[str] = None,
    use_tcp: bool = False,
) -> Optional[str]:
    """
    Resolve a Windows SID to a human-readable username.

    This is the main entry point for SID resolution, implementing a multi-tier
    fallback strategy for maximum coverage across different AD environments.

    Resolution tiers (in order):
        Tier 0: Well-known SIDs - Instant lookup for SYSTEM, LOCAL SERVICE, etc.
        Tier 1: Cache - Check persistent cache for previously resolved SIDs
        Tier 2: BloodHound - Query loaded HighValue data or BloodHound API
        Tier 3: Target LSARPC - Direct SMB connection to task source host
        Tier 3.5: DC LSARPC - SMB to domain controller (handles cross-trust)
        Tier 4: LDAP - Domain controller query using objectSid
        Tier 5: Global Catalog - Forest-wide lookup (ports 3268/3269)

    Args:
        sid: The Windows SID to resolve (e.g., "S-1-5-21-...")
        target: Target host IP for LSARPC resolution (task source)
        domain: Domain FQDN (e.g., "corp.local")
        username: Authentication username
        password: Authentication password
        hashes: NTLM hashes (format: lm:nt or just nt)
        lm_hash: LM hash (deprecated, use hashes)
        nt_hash: NT hash (deprecated, use hashes)
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos
        dc_ip: Domain controller IP (for LDAP/LSARPC)
        hv: HighValue data object (for BloodHound lookups)
        known_domain_prefixes: Dict of domain SID prefixes to TrustInfo
        local_domain_sid_prefix: Our domain's SID prefix (for foreign detection)
        nameserver: DNS server for GC discovery
        use_tcp: Force DNS over TCP (for SOCKS proxies)

    Returns:
        Resolved username in DOMAIN\\User format, or None if unresolvable
    """
    # TODO: Implement clean multi-tier resolution logic
    # For now, delegate to the old implementation
    from ..utils.sid_resolver import resolve_sid as old_resolve_sid

    return old_resolve_sid(
        sid=sid,
        target=target,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
        lm_hash=lm_hash,
        nt_hash=nt_hash,
        kerberos=kerberos,
        aes_key=aes_key,
        dc_ip=dc_ip,
        hv=hv,
        known_domain_prefixes=known_domain_prefixes,
        local_domain_sid_prefix=local_domain_sid_prefix,
        nameserver=nameserver,
        use_tcp=use_tcp,
    )
