# DNS utilities for TaskHound
#
# This module provides DNS discovery and resolution utilities,
# including DC discovery via SRV records and configurable nameserver support.

import socket

from .helpers import is_ipv4
from .logging import debug, warn

# Default timeout for DNS operations (seconds)
DEFAULT_DNS_TIMEOUT = 5

# Default timeout for LDAP connections (seconds)
DEFAULT_LDAP_TIMEOUT = 10


def discover_domain_controllers(
    domain: str,
    nameserver: str | None = None,
    use_tcp: bool = False,
    timeout: int = DEFAULT_DNS_TIMEOUT,
) -> list[str]:
    """
    Discover domain controllers via DNS SRV records.

    Queries _ldap._tcp.dc._msdcs.<domain> SRV record to find all DCs.
    Falls back to A record lookup if SRV fails.

    Args:
        domain: Domain name (e.g., "corp.local")
        nameserver: Optional DNS server to use (defaults to system DNS)
        use_tcp: Force DNS queries over TCP (required for SOCKS proxies)
        timeout: DNS query timeout in seconds

    Returns:
        List of DC hostnames/IPs (may be empty if discovery fails)
    """
    dcs = []

    # Try DNS SRV record first (proper AD DC discovery)
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=True)
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # Query SRV record for LDAP service on DCs
        srv_name = f"_ldap._tcp.dc._msdcs.{domain}"
        debug(f"DNS: Querying SRV record {srv_name}")

        answers = resolver.resolve(srv_name, "SRV", tcp=use_tcp)
        for rdata in answers:
            dc_host = str(rdata.target).rstrip(".")
            if dc_host:
                dcs.append(dc_host)
                debug(f"DNS: Found DC via SRV: {dc_host} (priority={rdata.priority}, weight={rdata.weight})")

        # Sort by priority (lower = better), then by weight (higher = better)
        # SRV records already come sorted, but let's be explicit
        if dcs:
            debug(f"DNS: Discovered {len(dcs)} DCs via SRV records")
            return dcs

    except ImportError:
        debug("DNS: dnspython not available, falling back to system DNS")
    except Exception as e:
        debug(f"DNS: SRV lookup failed: {e}")

    # Fallback: Try A record for domain name
    try:
        debug(f"DNS: Falling back to A record lookup for {domain}")

        # If nameserver specified, use dnspython
        if nameserver:
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [nameserver]
                resolver.timeout = timeout
                resolver.lifetime = timeout

                answers = resolver.resolve(domain, "A", tcp=use_tcp)
                for rdata in answers:
                    ip = str(rdata)
                    dcs.append(ip)
                    debug(f"DNS: Found DC via A record: {ip}")
                return dcs
            except Exception as e:
                debug(f"DNS: A record lookup with custom nameserver failed: {e}")

        # System DNS fallback
        ip = socket.gethostbyname(domain)
        if ip:
            dcs.append(ip)
            debug(f"DNS: Resolved domain to IP: {ip}")

    except socket.gaierror as e:
        debug(f"DNS: Could not resolve domain {domain}: {e}")
    except Exception as e:
        debug(f"DNS: Domain resolution failed: {e}")

    return dcs


def resolve_hostname(
    hostname: str,
    nameserver: str | None = None,
    use_tcp: bool = False,
    timeout: int = DEFAULT_DNS_TIMEOUT,
) -> str | None:
    """
    Resolve a hostname to an IP address.

    Args:
        hostname: Hostname to resolve
        nameserver: Optional DNS server to use
        use_tcp: Force DNS queries over TCP
        timeout: DNS query timeout in seconds

    Returns:
        IP address string, or None if resolution fails
    """
    # If already an IP, return as-is
    if is_ipv4(hostname):
        return hostname

    try:
        if nameserver:
            import dns.resolver
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [nameserver]
            resolver.timeout = timeout
            resolver.lifetime = timeout

            answers = resolver.resolve(hostname, "A", tcp=use_tcp)
            if answers:
                return str(answers[0])
        else:
            return socket.gethostbyname(hostname)
    except Exception as e:
        debug(f"DNS: Could not resolve {hostname}: {e}")

    return None


def get_working_dc(
    domain: str,
    dc_ip: str | None = None,
    nameserver: str | None = None,
    use_tcp: bool = False,
    timeout: int = DEFAULT_LDAP_TIMEOUT,
) -> str | None:
    """
    Get a working DC IP for LDAP connections.

    If dc_ip is provided, returns it directly (user override).
    Otherwise, discovers DCs and tests connectivity.

    Args:
        domain: Domain name
        dc_ip: User-specified DC IP (if provided, used directly)
        nameserver: DNS server for discovery
        use_tcp: Force DNS over TCP
        timeout: Connection timeout for testing

    Returns:
        DC IP address, or None if no working DC found
    """
    # User explicitly specified DC - use it
    if dc_ip:
        return dc_ip

    # Discover DCs
    dcs = discover_domain_controllers(domain, nameserver=nameserver, use_tcp=use_tcp)

    if not dcs:
        warn(f"Could not discover any DCs for domain {domain}")
        return None

    # Resolve hostnames to IPs and test connectivity
    for dc in dcs:
        # Resolve if hostname
        dc_resolved = resolve_hostname(dc, nameserver=nameserver, use_tcp=use_tcp, timeout=timeout)
        if not dc_resolved:
            debug(f"DNS: Could not resolve DC hostname {dc}")
            continue

        # Test LDAP port connectivity (quick check)
        if _test_port(dc_resolved, 636, timeout=min(timeout, 3)):
            debug(f"DNS: DC {dc_resolved} is reachable on LDAPS (636)")
            return dc_resolved
        elif _test_port(dc_resolved, 389, timeout=min(timeout, 3)):
            debug(f"DNS: DC {dc_resolved} is reachable on LDAP (389)")
            return dc_resolved
        else:
            debug(f"DNS: DC {dc_resolved} not reachable on LDAP ports")

    # If no DC responded on LDAP ports, return first one anyway
    # (let LDAP connection handle the error with better diagnostics)
    if dcs:
        first_dc = resolve_hostname(dcs[0], nameserver=nameserver, use_tcp=use_tcp)
        if first_dc:
            warn(f"No DC responded on LDAP ports, trying {first_dc} anyway")
            return first_dc

    return None


def _test_port(host: str, port: int, timeout: int = 3) -> bool:
    """Test if a TCP port is reachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except OSError:
        return False


def discover_global_catalog_servers(
    domain: str,
    nameserver: str | None = None,
    use_tcp: bool = False,
    timeout: int = DEFAULT_DNS_TIMEOUT,
) -> list[str]:
    """
    Discover Global Catalog servers via DNS SRV records.

    Queries _gc._tcp.<forest_root> SRV record to find GC servers.
    Global Catalog runs on ports 3268 (GC) and 3269 (GC-SSL).

    Args:
        domain: Forest root domain name (e.g., "corp.local")
        nameserver: Optional DNS server to use
        use_tcp: Force DNS queries over TCP
        timeout: DNS query timeout in seconds

    Returns:
        List of GC server hostnames/IPs
    """
    gc_servers = []

    try:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=True)
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # Query SRV record for Global Catalog
        srv_name = f"_gc._tcp.{domain}"
        debug(f"DNS: Querying SRV record {srv_name} for Global Catalog")

        answers = resolver.resolve(srv_name, "SRV", tcp=use_tcp)
        for rdata in answers:
            gc_host = str(rdata.target).rstrip(".")
            if gc_host:
                gc_servers.append(gc_host)
                debug(f"DNS: Found GC via SRV: {gc_host} (priority={rdata.priority})")

        if gc_servers:
            debug(f"DNS: Discovered {len(gc_servers)} GC servers via SRV records")
            return gc_servers

    except ImportError:
        debug("DNS: dnspython not available for GC discovery")
    except Exception as e:
        debug(f"DNS: GC SRV lookup failed: {e}")

    return gc_servers


def get_working_gc(
    domain: str,
    gc_server: str | None = None,
    nameserver: str | None = None,
    use_tcp: bool = False,
    timeout: int = DEFAULT_LDAP_TIMEOUT,
) -> str | None:
    """
    Get a working Global Catalog server IP.

    Global Catalog is used for cross-domain SID resolution within
    the same AD forest. It contains a partial replica of all objects.

    Args:
        domain: Forest root domain name
        gc_server: User-specified GC IP (if provided, used directly)
        nameserver: DNS server for discovery
        use_tcp: Force DNS over TCP
        timeout: Connection timeout for testing

    Returns:
        GC server IP address, or None if no working GC found
    """
    # User explicitly specified GC - use it
    if gc_server:
        return gc_server

    # Discover GC servers
    gc_servers = discover_global_catalog_servers(domain, nameserver=nameserver, use_tcp=use_tcp)

    if not gc_servers:
        debug(f"DNS: Could not discover any GC servers for forest {domain}")
        return None

    # Resolve hostnames to IPs and test connectivity
    for gc in gc_servers:
        gc_resolved = resolve_hostname(gc, nameserver=nameserver, use_tcp=use_tcp, timeout=timeout)
        if not gc_resolved:
            debug(f"DNS: Could not resolve GC hostname {gc}")
            continue

        # Test GC port connectivity (3269 SSL, 3268 plain)
        if _test_port(gc_resolved, 3269, timeout=min(timeout, 3)):
            debug(f"DNS: GC {gc_resolved} is reachable on GC-SSL (3269)")
            return gc_resolved
        elif _test_port(gc_resolved, 3268, timeout=min(timeout, 3)):
            debug(f"DNS: GC {gc_resolved} is reachable on GC (3268)")
            return gc_resolved
        else:
            debug(f"DNS: GC {gc_resolved} not reachable on GC ports")

    # If no GC responded on ports, return first one anyway
    if gc_servers:
        first_gc = resolve_hostname(gc_servers[0], nameserver=nameserver, use_tcp=use_tcp)
        if first_gc:
            debug(f"DNS: No GC responded on ports, trying {first_gc} anyway")
            return first_gc

    return None
