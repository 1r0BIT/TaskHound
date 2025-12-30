# Resolution Backends
#
# Individual resolution methods that can be called directly or
# orchestrated by the main resolution chains.

from .bloodhound import (
    resolve_sid_from_bloodhound,
    resolve_sid_via_bloodhound_api,
    extract_domain_sid_from_hv,
)
from .lsarpc import (
    resolve_sid_via_smb,
    resolve_sid_via_dc_lsarpc,
)
from .ldap import (
    resolve_sid_via_ldap,
    resolve_name_to_sid_via_ldap,
    batch_get_user_attributes,
    get_user_pwd_last_set,
)
from .gc import (
    resolve_sid_via_global_catalog,
    get_discovered_gc_server,
)

__all__ = [
    # BloodHound
    "resolve_sid_from_bloodhound",
    "resolve_sid_via_bloodhound_api",
    "extract_domain_sid_from_hv",
    # LSARPC
    "resolve_sid_via_smb",
    "resolve_sid_via_dc_lsarpc",
    # LDAP
    "resolve_sid_via_ldap",
    "resolve_name_to_sid_via_ldap",
    "batch_get_user_attributes",
    "get_user_pwd_last_set",
    # Global Catalog
    "resolve_sid_via_global_catalog",
    "get_discovered_gc_server",
]
