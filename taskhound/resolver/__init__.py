# Resolver Module - SID/Name Resolution for TaskHound
#
# This module provides multi-tier resolution chains for:
# - SID → Name (resolve Windows SIDs to human-readable names)
# - Name → SID (resolve hostnames/usernames to SIDs)
# - NETBIOS → FQDN (resolve short domain names to FQDNs)
# - Tier-0 detection (identify privileged accounts)

# Primary resolution functions
from .sid_to_name import resolve_sid
from .name_to_sid import resolve_name_to_sid, prefetch_computer_sids

# NETBIOS resolution
from .netbios import (
    set_netbios_ldap_credentials,
    resolve_netbios_to_fqdn,
    add_netbios_mapping,
    get_netbios_cache,
)

# Trust handling
from .trusts import (
    TrustInfo,
    TrustData,
    fetch_known_domain_sids_via_ldap,
    is_foreign_domain_sid,
    is_unknown_domain_sid,
    is_external_trust,
    get_trust_fqdn,
    mark_as_external_trust,
    is_known_external_trust,
    resolve_unknown_sid_to_local_name,
    resolve_trust_sid_to_name,
    TRUST_ATTRIBUTE_WITHIN_FOREST,
    TRUST_ATTRIBUTE_FOREST_TRANSITIVE,
)

# Tier-0 detection
from .tier0 import fetch_tier0_members, check_tier0_membership

# Utilities and constants
from .constants import (
    is_sid,
    get_domain_sid_prefix,
    looks_like_domain_user,
    resolve_rid_to_name,
    resolve_special_sid_pattern,
    sid_to_binary,
    binary_to_sid,
    WELL_KNOWN_SIDS,
    WELL_KNOWN_LOCAL_RIDS,
)

# Backend access (for advanced usage)
from .backends import (
    resolve_sid_via_smb,
    resolve_sid_via_dc_lsarpc,
    resolve_sid_via_ldap,
    resolve_sid_via_global_catalog,
    resolve_sid_from_bloodhound,
    resolve_sid_via_bloodhound_api,
    resolve_name_to_sid_via_ldap,
    batch_get_user_attributes,
    get_user_pwd_last_set,
    get_discovered_gc_server,
)

__all__ = [
    # Primary functions
    "resolve_sid",
    "resolve_name_to_sid",
    "prefetch_computer_sids",
    # NETBIOS
    "set_netbios_ldap_credentials",
    "resolve_netbios_to_fqdn",
    "add_netbios_mapping",
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
    "TRUST_ATTRIBUTE_WITHIN_FOREST",
    "TRUST_ATTRIBUTE_FOREST_TRANSITIVE",
    # Tier-0
    "fetch_tier0_members",
    "check_tier0_membership",
    # Utilities
    "is_sid",
    "get_domain_sid_prefix",
    "looks_like_domain_user",
    "resolve_rid_to_name",
    "resolve_special_sid_pattern",
    "sid_to_binary",
    "binary_to_sid",
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
    "get_user_pwd_last_set",
    "get_discovered_gc_server",
]
