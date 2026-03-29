# Global Catalog Backend
#
# Resolution via Global Catalog (port 3268/3269) for forest-wide SID lookups.


from impacket.ldap import ldapasn1 as ldapasn1_impacket

from ...utils.logging import debug, info, warn
from ..constants import sid_to_binary

# Module-level cache for discovered GC server
_discovered_gc_server: str | None = None
_gc_discovery_attempted: bool = False


def get_discovered_gc_server(domain: str) -> str | None:
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

    if not domain or len(domain) < 3 or "." not in domain:
        debug(f"Invalid domain '{domain}' for GC discovery")
        return None

    try:
        from ...utils.dns import discover_global_catalog_servers

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


def resolve_sid_via_global_catalog(
    sid: str,
    domain: str,
    gc_server: str | None = None,
    username: str | None = None,
    password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    aes_key: str | None = None,
    nameserver: str | None = None,
    use_tcp: bool = False,
) -> str | None:
    """
    Resolve a SID from a foreign domain within the same AD forest via Global Catalog.

    Global Catalog (ports 3268/3269) contains a partial replica of ALL objects in the
    forest. Use this for resolving SIDs from other domains in the same forest where
    local LDAP (port 389) cannot find them.

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
    from ...utils.ldap import LDAPConnectionError, get_global_catalog_connection

    try:
        debug(f"Attempting Global Catalog resolution for foreign SID: {sid}")

        if not username or not (password or hashes or kerberos):
            debug("No valid credentials provided for GC SID resolution")
            return None

        if not domain or len(domain) < 3 or "." not in domain:
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

        # Use forest root DN for search base
        base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
        debug(f"Using GC search base: {base_dn}")

        # Create search filter using binary SID
        binary_sid_escaped = "".join([f"\\{b:02x}" for b in binary_sid])
        search_filter = f"(objectSid={binary_sid_escaped})"
        debug(f"GC search filter: {search_filter}")

        # Perform the search
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
                            # Sanity check: ensure we didn't get the SID back as the "name"
                            if isinstance(username_resolved, list):
                                username_resolved = username_resolved[0]
                            resolved_str = username_resolved.strip()
                            if resolved_str.startswith("S-1-") or resolved_str == sid:
                                debug(f"GC returned SID as name attribute for {sid} - treating as not found")
                            else:
                                info(f"Resolved foreign SID {sid} to {resolved_str} via Global Catalog")
                                return resolved_str
                        else:
                            debug(f"GC entry for SID {sid} has no name attributes")
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
