# Tier-0 Membership Detection
#
# Functions for detecting membership in privileged groups (Domain Admins,
# Enterprise Admins, etc.) via LDAP with transitive group expansion.


from impacket.ldap import ldapasn1 as ldapasn1_impacket

from ..utils.cache_manager import get_cache
from ..utils.helpers import domain_to_base_dn
from ..utils.ldap import LDAPConnectionError, get_ldap_connection
from ..utils.logging import debug
from .constants import binary_to_sid

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
Tier0Cache = dict[str, tuple[bool, list[str]]]


def fetch_tier0_members(
    domain: str,
    dc_ip: str | None = None,
    auth_username: str | None = None,
    auth_password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    aes_key: str | None = None,
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
    if not domain or len(domain) < 3 or "." not in domain:
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

    base_dn = domain_to_base_dn(domain)

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
                                binary_sid_data = attribute["vals"][0].asOctets()
                                sid_str = binary_to_sid(binary_sid_data)
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
        member_groups: dict[str, list[str]] = {}  # normalized_username -> list of group names

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
) -> tuple[bool, list[str]]:
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
