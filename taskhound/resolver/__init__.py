# Resolver Module - SID/Name Resolution for TaskHound
#
# This module provides multi-tier resolution chains for:
# - SID → Name (resolve Windows SIDs to human-readable names)
# - Name → SID (resolve hostnames/usernames to SIDs)
# - NETBIOS → FQDN (resolve short domain names to FQDNs)
# - Tier-0 detection (identify privileged accounts)

# Primary resolution functions
# Backend access (for advanced usage)
from .backends import (
    batch_get_user_attributes,
    extract_domain_sid_from_hv,
    get_discovered_gc_server,
    resolve_name_to_sid_via_ldap,
    resolve_sid_from_bloodhound,
    resolve_sid_via_bloodhound_api,
    resolve_sid_via_dc_lsarpc,
    resolve_sid_via_global_catalog,
    resolve_sid_via_ldap,
    resolve_sid_via_smb,
)

# Utilities and constants
from .constants import (
    WELL_KNOWN_LOCAL_RIDS,
    WELL_KNOWN_SIDS,
    binary_to_sid,
    get_domain_sid_prefix,
    is_bare_name,
    is_probably_local_bare_name,
    is_sid,
    looks_like_domain_user,
    resolve_special_sid_pattern,
    sid_to_binary,
)
from .name_to_sid import prefetch_computer_sids, resolve_name_to_sid

# NETBIOS resolution
from .netbios import (
    get_netbios_cache,
    resolve_netbios_to_fqdn,
    set_netbios_ldap_credentials,
)
from .sid_to_name import format_runas_with_sid_resolution, resolve_sid

# Tier-0 detection
from .tier0 import (
    TIER0_ACCOUNT_RIDS,
    TIER0_BUILTIN_SIDS,
    TIER0_GROUP_RIDS,
    Tier0Cache,
    check_tier0_membership,
    fetch_tier0_members,
)

# Trust handling
from .trusts import (
    TrustData,
    TrustInfo,
    fetch_known_domain_sids_via_ldap,
    get_trust_fqdn,
    is_external_trust,
    is_foreign_domain_sid,
    is_known_external_trust,
    is_unknown_domain_sid,
    mark_as_external_trust,
    resolve_trust_sid_to_name,
    resolve_unknown_sid_to_local_name,
)

__all__ = [
    # Primary functions
    "resolve_sid",
    "format_runas_with_sid_resolution",
    "resolve_name_to_sid",
    "prefetch_computer_sids",
    # NETBIOS
    "set_netbios_ldap_credentials",
    "resolve_netbios_to_fqdn",
    "get_netbios_cache",
    # Trusts
    "TrustInfo",
    "TrustData",
    "fetch_known_domain_sids_via_ldap",
    "is_foreign_domain_sid",
    "is_unknown_domain_sid",
    "is_external_trust",
    "get_trust_fqdn",
    "mark_as_external_trust",
    "is_known_external_trust",
    "resolve_unknown_sid_to_local_name",
    "resolve_trust_sid_to_name",
    # Tier-0
    "fetch_tier0_members",
    "check_tier0_membership",
    "TIER0_GROUP_RIDS",
    "TIER0_ACCOUNT_RIDS",
    "TIER0_BUILTIN_SIDS",
    "Tier0Cache",
    # Utilities
    "is_sid",
    "is_bare_name",
    "is_probably_local_bare_name",
    "get_domain_sid_prefix",
    "looks_like_domain_user",
    "resolve_special_sid_pattern",
    "sid_to_binary",
    "binary_to_sid",
    "extract_domain_sid_from_hv",
    "WELL_KNOWN_SIDS",
    "WELL_KNOWN_LOCAL_RIDS",
    # Backends
    "resolve_sid_via_smb",
    "resolve_sid_via_dc_lsarpc",
    "resolve_sid_via_ldap",
    "resolve_sid_via_global_catalog",
    "resolve_sid_from_bloodhound",
    "resolve_sid_via_bloodhound_api",
    "resolve_name_to_sid_via_ldap",
    "batch_get_user_attributes",
    "get_discovered_gc_server",
]
