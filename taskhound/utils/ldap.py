# LDAP utilities for TaskHound
#
# This module provides shared LDAP connection and query utilities
# used across TaskHound modules (LAPS, SID resolver, etc.)

import contextlib
import socket
from typing import Optional

from impacket.ldap import ldap as ldap_impacket

from .helpers import parse_ntlm_hashes
from .logging import debug


def resolve_dc_hostname(dc_ip: str, domain: str, use_tcp: bool = False) -> str | None:
    """
    Resolve DC IP to hostname for Kerberos SPN construction.

    Tries multiple methods:
    1. DNS PTR lookup via DC itself (most reliable for AD environments)
    2. System reverse DNS lookup
    3. Construct from short name + domain

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (for constructing FQDN)
        use_tcp: Force DNS queries over TCP (required for SOCKS proxies)

    Returns:
        DC hostname (FQDN) or None if resolution fails
    """
    # Method 1: Try DNS PTR lookup using the DC as nameserver
    # This is most reliable in AD environments
    try:
        import dns.resolver
        import dns.reversename

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dc_ip]
        resolver.timeout = 3
        resolver.lifetime = 3

        rev_name = dns.reversename.from_address(dc_ip)
        # Force TCP if requested (required for SOCKS/proxychains)
        answers = resolver.resolve(rev_name, "PTR", tcp=use_tcp)
        if answers:
            hostname = str(answers[0]).rstrip(".")
            # If we got a short name, append the domain
            if hostname and "." not in hostname:
                hostname = f"{hostname}.{domain}"
            # Verify it's not just the domain name
            if hostname and hostname.lower() != domain.lower():
                return hostname
    except ImportError:
        pass  # dnspython not available
    except (TimeoutError, OSError):
        pass  # DNS lookup failed: {e}

    # Method 2: System reverse DNS lookup
    try:
        hostname = socket.gethostbyaddr(dc_ip)[0]
        # Check if we got the domain name instead of the DC hostname
        if hostname and hostname.lower() != domain.lower():
            return hostname
    except socket.herror:
        pass

    # Method 3: Try socket.getfqdn
    try:
        hostname = socket.getfqdn(dc_ip)
        if hostname and hostname != dc_ip and hostname.lower() != domain.lower():
            return hostname
    except OSError:
        pass

    return None


def get_ldap_connection(
    dc_ip: str | None,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    aes_key: str | None = None,
    dc_host: str | None = None,
    use_tcp: bool = False,
    nameserver: str | None = None,
    timeout: int = 10,
) -> ldap_impacket.LDAPConnection:
    """
    Establish LDAP connection to domain controller.

    Tries LDAPS (port 636) first for secure connection, then falls back to
    LDAP (port 389) if LDAPS fails. This handles DCs that require channel
    binding or LDAP signing (strongerAuthRequired error).

    If dc_ip is not provided, attempts to discover DCs via DNS SRV records.

    Args:
        dc_ip: Domain controller IP address (optional - will auto-discover if not provided)
        domain: Domain name (FQDN format, e.g., "domain.local")
        username: Username for authentication
        password: Password (plaintext)
        hashes: NTLM hashes in LM:NT or NT format
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos (128-bit or 256-bit hex string)
        dc_host: DC hostname for Kerberos SPN (optional, will try to resolve)
        use_tcp: Force DNS queries over TCP (required for SOCKS proxies)
        nameserver: DNS server for lookups (defaults to dc_ip or system DNS)
        timeout: Timeout for DC discovery only (default: 10s). Note: actual LDAP
            connection uses OS-level TCP timeout (~75s on most systems) because
            impacket doesn't support per-connection timeouts.

    Returns:
        LDAPConnection object

    Raises:
        LDAPConnectionError: If connection fails
    """
    from .dns import DEFAULT_LDAP_TIMEOUT, get_working_dc

    # Use provided timeout or default
    effective_timeout = timeout if timeout else DEFAULT_LDAP_TIMEOUT

    # NOTE: The timeout parameter only applies to DC discovery, not the LDAP connection.
    # We cannot use socket.setdefaulttimeout() because it breaks SSL connections
    # (causes WantReadError during handshake). impacket's LDAPConnection doesn't
    # support per-connection timeouts, so we rely on OS-level TCP timeout (~75s)
    # for unreachable DCs. The DC discovery phase tests port connectivity with
    # proper timeouts, so unreachable DCs should be filtered out before we get here.

    # If no DC IP provided, try to discover one
    if not dc_ip:
        # Use nameserver if provided, otherwise let discovery use system DNS
        effective_ns = nameserver
        dc_ip = get_working_dc(
            domain=domain,
            nameserver=effective_ns,
            use_tcp=use_tcp,
            timeout=effective_timeout,
        )
        if not dc_ip:
            raise LDAPConnectionError(
                f"Could not discover DC for domain {domain}. "
                "Specify --dc-ip explicitly or check DNS configuration."
            )
        debug(f"LDAP: Auto-discovered DC: {dc_ip}")

    # Build base DN from domain
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    # Parse hashes
    lmhash, nthash = parse_ntlm_hashes(hashes)

    # For Kerberos (or AES key auth), we need the DC hostname for the SPN (ldap/dc01.domain.local)
    # If not provided, try to resolve
    kerberos_target = dc_host
    if (kerberos or aes_key) and not kerberos_target:
        kerberos_target = resolve_dc_hostname(dc_ip, domain, use_tcp=use_tcp)
        if kerberos_target:
            debug(f"LDAP: Resolved DC hostname for Kerberos SPN: {kerberos_target}")
        else:
            debug("LDAP: Could not resolve DC hostname, Kerberos may fail")
            kerberos_target = dc_ip

    # Try LDAPS first (port 636), then LDAP (port 389)
    # Modern DCs often require LDAP signing which plain LDAP doesn't provide
    connection_attempts = [
        ("ldaps", 636, True),  # LDAPS with SSL
        ("ldap", 389, False),  # Plain LDAP (may fail with strongerAuthRequired)
    ]

    last_error = None
    for protocol, port, use_ssl in connection_attempts:
        try:
            # For Kerberos (or AES key), use hostname in URL WITHOUT port (so SPN is ldap/hostname, not ldap/hostname:port)
            # The port is inferred from the protocol (ldaps=636, ldap=389)
            # Connect via dstIp for actual network connection
            if (kerberos or aes_key) and kerberos_target:
                ldap_url = f"{protocol}://{kerberos_target}"
            else:
                ldap_url = f"{protocol}://{dc_ip}:{port}"
            debug(f"LDAP: Attempting {protocol.upper()} connection to {ldap_url}")

            ldap_conn = ldap_impacket.LDAPConnection(
                ldap_url,
                baseDN=base_dn,
                dstIp=dc_ip,  # Always connect via IP
            )

            # Authenticate
            # AES key implies Kerberos authentication
            if kerberos or aes_key:
                # kdcHost is used for AS-REQ/TGS-REQ, not for SPN
                ldap_conn.kerberosLogin(
                    user=username,
                    password=password or "",
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    aesKey=aes_key or "",
                    kdcHost=kerberos_target,
                )
            else:
                ldap_conn.login(
                    user=username,
                    password=password or "",
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                )

            debug(f"LDAP: Successfully connected via {protocol.upper()}")
            return ldap_conn

        except Exception as e:
            error_str = str(e)
            debug(f"LDAP: {protocol.upper()} connection failed: {error_str}")
            last_error = e

            # If it's a certificate error on LDAPS, try plain LDAP
            if use_ssl and ("certificate" in error_str.lower() or "ssl" in error_str.lower()):
                debug("LDAP: SSL/certificate issue, trying plain LDAP...")
                continue

            # If strongerAuthRequired on plain LDAP, we already tried LDAPS
            if "strongerAuthRequired" in error_str:
                # LDAPS should have worked, but if we're here it didn't
                debug("LDAP: DC requires signing/encryption but LDAPS also failed")
                break

            # For other errors, try next protocol
            continue

    # All attempts failed
    raise LDAPConnectionError(f"LDAP connection failed: {last_error}")


def enumerate_domain_computers(
    dc_ip: str | None,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    aes_key: str | None = None,
    ldap_filter: str | None = None,
    use_tcp: bool = False,
    include_dcs: bool = False,
) -> list[str]:
    """
    Enumerate all computer objects from Active Directory via LDAP.

    Returns a list of computer hostnames (dNSHostName or sAMAccountName without $).
    By default, excludes Domain Controllers (userAccountControl bit 0x2000 = 8192).

    Args:
        dc_ip: Domain controller IP address (optional - will auto-discover if not provided)
        domain: Domain name (FQDN format, e.g., "domain.local")
        username: Username for authentication
        password: Password (plaintext)
        hashes: NTLM hashes in LM:NT or NT format
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos
        ldap_filter: Optional additional LDAP filter (e.g., "(operatingSystem=*Server*)")
        use_tcp: Force DNS queries over TCP
        include_dcs: Include Domain Controllers (default: False, DCs excluded)

    Returns:
        List of computer hostnames

    Raises:
        LDAPConnectionError: If connection fails
    """
    from impacket.ldap.ldapasn1 import SearchResultEntry

    # Connect to LDAP
    ldap_conn = get_ldap_connection(
        dc_ip=dc_ip,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
        kerberos=kerberos,
        aes_key=aes_key,
        use_tcp=use_tcp,
    )

    # Build search filter
    # Base filter: all computer objects
    base_filter = "(objectClass=computer)"

    # Exclude Domain Controllers by default (userAccountControl bit 0x2000 = 8192)
    # LDAP OID 1.2.840.113556.1.4.803 = bitwise AND matching rule
    if not include_dcs:
        dc_exclusion_filter = "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        base_filter = f"(&{base_filter}{dc_exclusion_filter})"
        debug("LDAP: Excluding Domain Controllers from enumeration")

    # Combine with custom filter if provided
    search_filter = (
        f"(&{base_filter}{ldap_filter})" if ldap_filter else base_filter
    )

    debug(f"LDAP: Enumerating computers with filter: {search_filter}")

    # Search for computers - request dNSHostName and sAMAccountName
    try:
        results = ldap_conn.search(
            searchFilter=search_filter,
            attributes=["dNSHostName", "sAMAccountName"],
            sizeLimit=0,  # No limit
        )
    except Exception as e:
        raise LDAPConnectionError(f"LDAP search failed: {e}") from e

    computers = []
    for result in results:
        if not isinstance(result, SearchResultEntry):
            continue

        # Extract attributes
        dns_hostname = None
        sam_name = None

        for attr in result["attributes"]:
            attr_type = str(attr["type"])
            if attr["vals"]:
                attr_value = str(attr["vals"][0])

                if attr_type.lower() == "dnshostname":
                    dns_hostname = attr_value
                elif attr_type.lower() == "samaccountname":
                    sam_name = attr_value

        # Prefer dNSHostName (FQDN), fall back to sAMAccountName (strip trailing $)
        if dns_hostname:
            computers.append(dns_hostname)
        elif sam_name:
            # Strip trailing $ from computer account name
            hostname = sam_name.rstrip("$")
            # Append domain to make it resolvable
            computers.append(f"{hostname}.{domain}")

    debug(f"LDAP: Found {len(computers)} computer objects")
    return computers


def enumerate_domain_computers_filtered(
    dc_ip: str | None,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    aes_key: str | None = None,
    ldap_filter: str | None = None,
    use_tcp: bool = False,
    include_dcs: bool = False,
    include_disabled: bool = False,
    stale_threshold: int = 60,
) -> list[str]:
    """
    Enumerate domain computers with filtering support.

    Enhanced version of enumerate_domain_computers that supports filtering by:
    - Disabled accounts (userAccountControl bit 0x2 = 2)
    - Stale accounts (pwdLastSet older than threshold)
    - Domain Controllers (userAccountControl bit 0x2000 = 8192)
    - Custom LDAP filter

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (FQDN format)
        username: Username for authentication
        password: Password (plaintext)
        hashes: NTLM hashes
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos
        ldap_filter: Additional LDAP filter
        use_tcp: Force DNS queries over TCP
        include_dcs: Include Domain Controllers (default: False)
        include_disabled: Include disabled accounts (default: False)
        stale_threshold: Exclude accounts with pwdLastSet older than this many days (0 to disable)

    Returns:
        List of computer hostnames

    Raises:
        LDAPConnectionError: If connection fails
    """
    import time

    from impacket.ldap.ldapasn1 import SearchResultEntry

    # Connect to LDAP
    ldap_conn = get_ldap_connection(
        dc_ip=dc_ip,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
        kerberos=kerberos,
        aes_key=aes_key,
        use_tcp=use_tcp,
    )

    # Build search filter
    filters = ["(objectClass=computer)"]

    # Exclude Domain Controllers by default
    if not include_dcs:
        # userAccountControl bit 0x2000 (8192) = SERVER_TRUST_ACCOUNT (DC)
        filters.append("(!(userAccountControl:1.2.840.113556.1.4.803:=8192))")
        debug("LDAP: Excluding Domain Controllers")

    # Exclude disabled accounts by default
    if not include_disabled:
        # userAccountControl bit 0x2 (2) = ACCOUNTDISABLE
        filters.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
        debug("LDAP: Excluding disabled accounts")

    # Add custom LDAP filter
    if ldap_filter:
        filters.append(ldap_filter)
        debug(f"LDAP: Adding custom filter: {ldap_filter}")

    # Combine all filters
    search_filter = filters[0] if len(filters) == 1 else f"(&{''.join(filters)})"

    debug(f"LDAP: Enumerating computers with filter: {search_filter}")

    # Request attributes needed for filtering
    attributes = ["dNSHostName", "sAMAccountName", "pwdLastSet"]

    try:
        results = ldap_conn.search(
            searchFilter=search_filter,
            attributes=attributes,
            sizeLimit=0,
        )
    except Exception as e:
        raise LDAPConnectionError(f"LDAP search failed: {e}") from e

    # Calculate stale threshold in Windows FILETIME
    # Windows FILETIME: 100-nanosecond intervals since Jan 1, 1601
    # Unix epoch is 11644473600 seconds after 1601
    now_ts = int(time.time())
    stale_cutoff_ts = now_ts - (stale_threshold * 86400) if stale_threshold > 0 else 0
    # Convert to Windows FILETIME (100-ns intervals)
    stale_cutoff_filetime = (stale_cutoff_ts + 11644473600) * 10000000 if stale_cutoff_ts else 0

    computers = []
    stats = {"total": 0, "stale": 0}

    for result in results:
        if not isinstance(result, SearchResultEntry):
            continue

        stats["total"] += 1

        # Extract attributes
        dns_hostname = None
        sam_name = None
        pwd_last_set = None

        for attr in result["attributes"]:
            attr_type = str(attr["type"])
            if attr["vals"]:
                attr_value = str(attr["vals"][0])

                if attr_type.lower() == "dnshostname":
                    dns_hostname = attr_value
                elif attr_type.lower() == "samaccountname":
                    sam_name = attr_value
                elif attr_type.lower() == "pwdlastset":
                    with contextlib.suppress(ValueError, TypeError):
                        pwd_last_set = int(attr_value)

        # Filter stale accounts
        if stale_threshold > 0 and pwd_last_set and pwd_last_set < stale_cutoff_filetime:
            stats["stale"] += 1
            continue

        # Build hostname
        if dns_hostname:
            computers.append(dns_hostname)
        elif sam_name:
            hostname = sam_name.rstrip("$")
            computers.append(f"{hostname}.{domain}")

    debug(f"LDAP: Found {len(computers)} computers ({stats['total']} total, {stats['stale']} stale filtered)")
    return computers


def get_netbios_domain_name(
    dc_ip: str | None,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    aes_key: str | None = None,
    use_tcp: bool = False,
    ldap_conn: Optional["ldap_impacket.LDAPConnection"] = None,
) -> str | None:
    """
    Query the NetBIOS domain name from Active Directory.

    The NetBIOS name is stored in CN=Partitions,CN=Configuration,DC=domain,DC=tld
    as the nETBIOSName attribute. This is different from the first part of the FQDN
    (e.g., domain corp.example.com might have NetBIOS name YOURCOMPANY).

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (FQDN format, e.g., "domain.local")
        username: Username for authentication
        password: Password (plaintext)
        hashes: NTLM hashes in LM:NT or NT format
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos
        use_tcp: Force DNS queries over TCP
        ldap_conn: Existing LDAP connection (optional - will create new one if not provided)

    Returns:
        NetBIOS domain name (e.g., "CONTOSO"), or None if not found
    """
    from impacket.ldap.ldapasn1 import SearchResultEntry

    # Build base DN for Configuration partition
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
    config_dn = f"CN=Partitions,CN=Configuration,{base_dn}"

    # Use existing connection or create new one
    conn = ldap_conn
    should_close = False
    if not conn:
        try:
            conn = get_ldap_connection(
                dc_ip=dc_ip,
                domain=domain,
                username=username,
                password=password,
                hashes=hashes,
                kerberos=kerberos,
                aes_key=aes_key,
                use_tcp=use_tcp,
            )
            should_close = True
        except LDAPConnectionError as e:
            debug(f"LDAP: Failed to connect for NetBIOS lookup: {e}")
            return None

    try:
        # Search for the crossRef object that has nETBIOSName
        # Filter: (&(objectClass=crossRef)(nETBIOSName=*)(dnsRoot={domain}))
        search_filter = f"(&(objectClass=crossRef)(nETBIOSName=*)(dnsRoot={domain}))"

        debug(f"LDAP: Querying NetBIOS name from {config_dn}")

        results = conn.search(
            searchBase=config_dn,
            searchFilter=search_filter,
            attributes=["nETBIOSName"],
            sizeLimit=1,
        )

        for result in results:
            if not isinstance(result, SearchResultEntry):
                continue

            for attr in result["attributes"]:
                attr_type = str(attr["type"])
                if attr_type.lower() == "netbiosname" and attr["vals"]:
                    netbios_name = str(attr["vals"][0]).upper()
                    debug(f"LDAP: Found NetBIOS name: {netbios_name} for domain {domain}")
                    return netbios_name

        debug(f"LDAP: No NetBIOS name found for domain {domain}")
        return None

    except Exception as e:
        debug(f"LDAP: NetBIOS name query failed: {e}")
        return None
    finally:
        # Don't close if we were passed an existing connection
        if should_close and conn:
            with contextlib.suppress(Exception):
                conn.close()


def get_global_catalog_connection(
    gc_server: str | None,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    aes_key: str | None = None,
    use_tcp: bool = False,
    nameserver: str | None = None,
    timeout: int = 10,
) -> ldap_impacket.LDAPConnection:
    """
    Establish connection to Global Catalog server.

    Global Catalog is an LDAP service that contains a partial replica of ALL
    objects in the AD forest. It runs on ports 3268 (GC) and 3269 (GC-SSL).
    Any DC can be a GC server - we discover one via DNS SRV records.

    Use this for resolving SIDs from OTHER domains in the SAME forest, where
    local LDAP (port 389) cannot find them because they're in different partitions.

    Args:
        gc_server: Global Catalog server IP (optional - will auto-discover if not provided)
        domain: Forest root domain name (FQDN format)
        username: Username for authentication
        password: Password (plaintext)
        hashes: NTLM hashes in LM:NT or NT format
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos
        use_tcp: Force DNS queries over TCP (required for SOCKS proxies)
        nameserver: DNS server for lookups
        timeout: Timeout for GC discovery

    Returns:
        LDAPConnection object connected to Global Catalog

    Raises:
        LDAPConnectionError: If connection fails
    """
    from .dns import get_working_gc

    # If no GC server provided, discover one via DNS
    if not gc_server:
        effective_ns = nameserver
        gc_server = get_working_gc(
            domain=domain,
            nameserver=effective_ns,
            use_tcp=use_tcp,
            timeout=timeout,
        )
        if not gc_server:
            raise LDAPConnectionError(
                f"Could not discover Global Catalog for forest {domain}. "
                "No GC servers found or all unreachable."
            )
        debug(f"GC: Auto-discovered Global Catalog server: {gc_server}")

    # Global Catalog uses empty base DN (forest-wide search)
    # or we can use the forest root DN
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    # Parse hashes
    lmhash, nthash = parse_ntlm_hashes(hashes)

    # For Kerberos, we need the GC hostname for the SPN
    kerberos_target = None
    if kerberos or aes_key:
        kerberos_target = resolve_dc_hostname(gc_server, domain, use_tcp=use_tcp)
        if kerberos_target:
            debug(f"GC: Resolved GC hostname for Kerberos SPN: {kerberos_target}")
        else:
            debug("GC: Could not resolve GC hostname, Kerberos may fail")
            kerberos_target = gc_server

    # Try GC-SSL first (port 3269), then GC (port 3268)
    connection_attempts = [
        ("ldaps", 3269, True),   # GC-SSL
        ("ldap", 3268, False),   # Plain GC
    ]

    last_error = None
    for protocol, port, use_ssl in connection_attempts:
        try:
            if (kerberos or aes_key) and kerberos_target:
                # For Kerberos, use hostname but still specify port for GC
                ldap_url = f"{protocol}://{kerberos_target}:{port}"
            else:
                ldap_url = f"{protocol}://{gc_server}:{port}"
            debug(f"GC: Attempting {protocol.upper()} connection to {ldap_url} (Global Catalog)")

            gc_conn = ldap_impacket.LDAPConnection(
                ldap_url,
                baseDN=base_dn,
                dstIp=gc_server,
            )

            # Authenticate
            if kerberos or aes_key:
                gc_conn.kerberosLogin(
                    user=username,
                    password=password or "",
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                    aesKey=aes_key or "",
                    kdcHost=kerberos_target,
                )
            else:
                gc_conn.login(
                    user=username,
                    password=password or "",
                    domain=domain,
                    lmhash=lmhash,
                    nthash=nthash,
                )

            debug(f"GC: Successfully connected to Global Catalog via {protocol.upper()} (port {port})")
            return gc_conn

        except Exception as e:
            error_str = str(e)
            debug(f"GC: {protocol.upper()} connection to port {port} failed: {error_str}")
            last_error = e

            # If SSL error on GC-SSL, try plain GC
            if use_ssl and ("certificate" in error_str.lower() or "ssl" in error_str.lower()):
                debug("GC: SSL/certificate issue, trying plain GC...")
                continue
            continue

    raise LDAPConnectionError(f"Global Catalog connection failed: {last_error}")


class LDAPConnectionError(Exception):
    """Failed to connect to domain controller via LDAP"""

    pass
