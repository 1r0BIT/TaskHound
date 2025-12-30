# LDAP Backend
#
# Resolution via LDAP queries to domain controllers (port 389/636).

import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional

from impacket.ldap import ldapasn1 as ldapasn1_impacket

from ..constants import binary_to_sid, sid_to_binary
from ...utils.cache_manager import get_cache
from ...utils.ldap import LDAPConnectionError, get_ldap_connection
from ...utils.logging import debug, info, warn


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

        # Get LDAP connection using shared utility
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
            search_filter = f"(&(objectClass=computer)(cn={search_name}))"
        else:
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
                                attr_vals = [bytes(val) for val in attribute["vals"]]
                            else:
                                attr_vals = [str(val) for val in attribute["vals"]]
                            attributes[attr_name] = attr_vals[0] if len(attr_vals) == 1 else attr_vals

                        # Extract the binary objectSid
                        binary_sid_data = attributes.get("objectSid")

                        if binary_sid_data and isinstance(binary_sid_data, bytes):
                            sid_string = binary_to_sid(binary_sid_data)

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


def batch_get_user_attributes(
    usernames: List[str],
    domain: str,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    aes_key: Optional[str] = None,
    attributes: List[str] = None,
) -> Dict[str, Dict]:
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
    """
    if not usernames:
        return {}

    if attributes is None:
        attributes = ["pwdLastSet", "lastLogon", "sAMAccountName", "objectSid"]

    # Normalize usernames - extract just the username part
    users_to_query = set()
    username_mapping = {}
    for user in usernames:
        if not user:
            continue
        normalized = user.split("\\")[-1].lower() if "\\" in user else user.lower()
        users_to_query.add(normalized)
        username_mapping[user] = normalized

    if not users_to_query:
        return {}

    # Validate domain
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
                                try:
                                    filetime = int(attr_vals[0]) if attr_vals else 0
                                    if filetime > 0:
                                        unix_ts = (filetime - 116444736000000000) / 10000000
                                        entry_attrs["pwdLastSet"] = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                                except (ValueError, OSError):
                                    pass
                            elif attr_name.lower() == "lastlogon":
                                try:
                                    filetime = int(attr_vals[0]) if attr_vals else 0
                                    if filetime > 0:
                                        unix_ts = (filetime - 116444736000000000) / 10000000
                                        entry_attrs["lastLogon"] = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                                except (ValueError, OSError):
                                    pass
                            elif attr_name.lower() == "objectsid" and attr_vals:
                                try:
                                    binary_sid_data = attribute["vals"][0].asOctets()
                                    sid_str = binary_to_sid(binary_sid_data)
                                    if sid_str:
                                        entry_attrs["sid"] = sid_str
                                except (ValueError, TypeError, AttributeError):
                                    pass

                        if sam_name and entry_attrs:
                            results[sam_name] = entry_attrs
                            if cache:
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
    user: str,
    domain: str,
    dc_ip: Optional[str] = None,
    auth_username: Optional[str] = None,
    auth_password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
) -> Optional[datetime]:
    """
    Get pwdLastSet for a single user (with caching).

    Convenience wrapper around batch_get_user_attributes for single user lookup.

    Args:
        user: Username to look up (DOMAIN\\user or just user)
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
    norm_user = user.split("\\")[-1].lower() if "\\" in user else user.lower()

    # Check cache first
    cache = get_cache()
    if cache:
        cached = cache.get("user_attrs", norm_user)
        if cached:
            pwd_ts = cached.get("pwdLastSet")
            if pwd_ts:
                if isinstance(pwd_ts, (int, float)):
                    return datetime.fromtimestamp(pwd_ts)
                return pwd_ts

    # Query LDAP
    results = batch_get_user_attributes(
        usernames=[user],
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
