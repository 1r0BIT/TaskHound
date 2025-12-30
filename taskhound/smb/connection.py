# SMB connection helpers.
#
# Small wrapper around Impacket's SMBConnection to handle cleartext
# passwords, NTLM hashes (LM:NT or NT-only), and optional Kerberos
# authentication. The intent is to keep calling code concise and
# centralize parsing of the different credential formats.
# This is horribly vibe-y but it works. Feel free to PR.

import socket
from typing import Optional, Tuple

from impacket.smbconnection import SMBConnection

from ..utils.helpers import is_ipv4


def _parse_hashes(password: str):
    # Parse a provided password or NTLM hash string.
    #
    # Accepts:
    #   - None/empty -> (None, '', '')
    #   - 'lm:nt' format -> (None, lm, nt)
    #   - 32-hex NT-only -> (None, '', nt)
    #   - cleartext -> (password, '', '')
    #
    # Returns a tuple suitable for passing into Impacket's login APIs.
    if not password:
        return None, "", ""

    if ":" in password:
        lm, nt = password.split(":", 1)
        return None, lm.strip(), nt.strip()

    # If it's hex length 32, treat as NT hash
    p = password.strip()
    if len(p) == 32 and all(c in "0123456789abcdefABCDEF" for c in p):
        return None, "", p

    # Otherwise treat as cleartext password
    return password, "", ""


def smb_connect(
    target: str,
    domain: str,
    username: str,
    password: str = None,
    kerberos: bool = False,
    dc_ip: str = None,
    timeout: int = 60,
    aes_key: str = None,
) -> SMBConnection:
    # Create and authenticate an SMBConnection to `target`.
    #
    # This function prefers passing an explicit lm/nthash when provided and
    # falls back to a cleartext password. For Kerberos mode we delegate to
    # Impacket's kerberosLogin (which supports a KDC host if provided).
    # If an AES key is provided, Kerberos authentication is used automatically.
    smb = SMBConnection(remoteName=target, remoteHost=target, sess_port=445, timeout=timeout)

    pwd, lmhash, nthash = _parse_hashes(password)

    # AES key implies Kerberos authentication
    if kerberos or aes_key:
        smb.kerberosLogin(
            user=username,
            password=pwd,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=aes_key or "",
            TGT=None,
            TGS=None,
            kdcHost=dc_ip,
        )
    else:
        if lmhash or nthash:
            # When presenting hashes to SMB, the cleartext password is empty
            smb.login(username, "", domain, lmhash=lmhash, nthash=nthash)
        else:
            smb.login(username, pwd, domain)
    return smb


def smb_negotiate(target: str, timeout: int = 60) -> SMBConnection:
    """
    Create an SMBConnection and perform negotiation only (no authentication).

    This is useful for LAPS mode where we need to discover the hostname
    before we know which credentials to use.

    Args:
        target: Target IP or hostname
        timeout: Connection timeout in seconds

    Returns:
        SMBConnection after negotiate (not yet authenticated)

    The caller can then:
    1. Call smb.getServerName() to get the hostname
    2. Look up credentials based on hostname
    3. Call smb_login() to authenticate
    """
    return SMBConnection(remoteName=target, remoteHost=target, sess_port=445, timeout=timeout)


def smb_login(
    smb: SMBConnection,
    domain: str,
    username: str,
    password: str = None,
    kerberos: bool = False,
    dc_ip: str = None,
    aes_key: str = None,
) -> None:
    """
    Authenticate an existing SMBConnection.

    This is the second half of a two-phase connection, used for LAPS mode
    where we negotiate first, then authenticate with looked-up credentials.

    Args:
        smb: Existing SMBConnection (after negotiate)
        domain: Domain name (use "." for local accounts like LAPS)
        username: Username to authenticate as
        password: Password or NTLM hash
        kerberos: Use Kerberos authentication
        dc_ip: Domain controller IP (for Kerberos)
        aes_key: AES key for Kerberos authentication (128 or 256 bit)
    """
    pwd, lmhash, nthash = _parse_hashes(password)

    # AES key implies Kerberos authentication
    if kerberos or aes_key:
        smb.kerberosLogin(
            user=username,
            password=pwd,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=aes_key or "",
            TGT=None,
            TGS=None,
            kdcHost=dc_ip,
        )
    else:
        if lmhash or nthash:
            smb.login(username, "", domain, lmhash=lmhash, nthash=nthash)
        else:
            smb.login(username, pwd, domain)


def smb_connect_with_laps(
    target: str,
    laps_cache,  # LAPSCache from laps.py
    fallback_domain: str,
    fallback_username: str,
    fallback_password: Optional[str] = None,
    fallback_hashes: Optional[str] = None,
    fallback_kerberos: bool = False,
    dc_ip: Optional[str] = None,
    timeout: int = 60,
) -> Tuple[SMBConnection, str, Optional[str], bool]:
    """
    Connect to target using LAPS credentials if available.

    This function implements the optimized LAPS flow:
    1. Create SMB connection (negotiate only)
    2. Extract hostname from negotiate response
    3. Look up LAPS password for that hostname
    4. Authenticate with LAPS credentials (or fallback if not found)

    Args:
        target: Target IP or hostname
        laps_cache: LAPSCache with LAPS passwords
        fallback_domain: Domain for fallback auth (not used with LAPS)
        fallback_username: Username for fallback auth
        fallback_password: Password for fallback auth
        fallback_hashes: Hashes for fallback auth
        fallback_kerberos: Use Kerberos for fallback auth
        dc_ip: Domain controller IP
        timeout: Connection timeout

    Returns:
        Tuple of (smb_connection, hostname, laps_type_used, used_laps)
        - smb_connection: Authenticated SMBConnection
        - hostname: Discovered hostname from SMB negotiate
        - laps_type_used: "legacy" or "mslaps" if LAPS was used, None otherwise
        - used_laps: True if LAPS credentials were used
    """
    # Phase 1: Negotiate to discover hostname
    smb = smb_negotiate(target, timeout=timeout)

    # Get hostname from negotiate response
    hostname = smb.getServerName()
    if not hostname:
        # Fallback to target if hostname not available
        hostname = target

    # Phase 2: Look up LAPS credentials
    laps_cred = laps_cache.get(hostname) if laps_cache else None

    if laps_cred and not laps_cred.encrypted:
        # Use LAPS credentials (local account, domain = ".")
        try:
            smb_login(
                smb,
                domain=".",  # Local account
                username=laps_cred.username,
                password=laps_cred.password,
                kerberos=False,  # LAPS is always NTLM
            )
            return smb, hostname, laps_cred.laps_type, True
        except Exception:
            # LAPS auth failed, connection is likely dead
            # Re-raise to let caller handle
            raise

    # Phase 3: Fallback to provided credentials
    smb_login(
        smb,
        domain=fallback_domain,
        username=fallback_username,
        password=fallback_hashes or fallback_password,
        kerberos=fallback_kerberos,
        dc_ip=dc_ip,
    )
    return smb, hostname, None, False


def get_server_sid(
    smb: SMBConnection,
    dc_ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    hashes: Optional[str] = None,
    kerberos: bool = False,
    hv_loader=None,
) -> Optional[str]:
    """
    Get the server's machine account SID using a multi-tier fallback chain.

    Fallback order:
    1. Cache (fast, persistent)
    2. BloodHound data (if hv_loader provided)
    3. LDAP query (if credentials provided)

    Note: SAMR on the target machine cannot resolve domain computer SIDs because
    the COMPUTER$ account exists in Active Directory, not the local SAM.

    Args:
        smb: Established SMBConnection
        dc_ip: Domain controller IP (for LDAP)
        username: Username for LDAP
        password: Password for LDAP
        hashes: NTLM hashes for LDAP
        kerberos: Use Kerberos for LDAP
        hv_loader: HighValueLoader with BloodHound data (optional)

    Returns:
        SID or None

    Example:
        >>> smb = smb_connect("DC01.corp.local", "CORP", "user", "pass")
        >>> sid = get_server_sid(smb)
        >>> print(sid)
        S-1-5-21-XXXXXXXXX-XXXXXXXX-XXXXXXXX-1002
    """
    try:
        from ..resolver import resolve_name_to_sid

        # Get computer name and domain from SMB
        computer_name = smb.getServerName()
        if not computer_name:
            return None

        # Get FQDN for lookup
        fqdn = smb.getServerDNSHostName()
        if not fqdn:
            server_domain = smb.getServerDNSDomainName()
            if computer_name and server_domain:
                fqdn = f"{computer_name}.{server_domain}"

        domain = smb.getServerDNSDomainName()

        # Use unified name→SID resolution with full fallback chain
        return resolve_name_to_sid(
            name=fqdn or computer_name,
            domain=domain,
            is_computer=True,
            hv_loader=hv_loader,
            dc_ip=dc_ip,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
        )

    except Exception:  # noqa: BLE001 - SID lookup has many failure modes (LDAP, LSA, network)
        return None


def get_server_fqdn(smb: SMBConnection, target_ip: Optional[str] = None, dc_ip: Optional[str] = None, dns_tcp: bool = False) -> str:
    """
    Extract the server's FQDN from an established SMB connection.

    Attempts multiple resolution methods in order:
    1. If target is already an FQDN (has dots, not an IP), use it directly
    2. SMB DNS hostname (most reliable)
    3. Constructed from SMB hostname + DNS domain
    4. DNS PTR lookup using DC as nameserver (if dc_ip provided)
    5. System DNS PTR lookup (fallback)

    Args:
        smb: Established SMBConnection
        target_ip: Original target IP address (used for DNS fallback)
        dc_ip: Domain Controller IP to use as DNS server
        dns_tcp: Force DNS queries over TCP (required for SOCKS proxies)

    Returns:
        FQDN string (e.g., "DC.badsuccessor.lab") or "UNKNOWN_HOST"
    """
    # Method 0: If target already looks like an FQDN (has dots and isn't an IP), use it
    if target_ip and "." in target_ip and not is_ipv4(target_ip):
        return target_ip

    try:
        # Method 1: Try to get the full DNS hostname directly from SMB
        fqdn = smb.getServerDNSHostName()
        if fqdn:
            return fqdn

        # Method 2: Construct from hostname + DNS domain
        server_name = smb.getServerName()
        server_domain = smb.getServerDNSDomainName()

        if server_name and server_domain:
            return f"{server_name}.{server_domain}"
        elif server_name:
            # Have hostname but no domain from SMB, try DNS fallback
            pass
        else:
            # No SMB hostname info at all
            server_name = None
    except (OSError, AttributeError):
        server_name = None

    # Method 3 & 4: DNS fallback - try to resolve via PTR record
    if target_ip and is_ipv4(target_ip):
        # Method 3: Try using DC as DNS server (if provided)
        if dc_ip:
            fqdn = _dns_ptr_lookup(target_ip, nameserver=dc_ip, use_tcp=dns_tcp)
            if fqdn:
                return fqdn

        # Method 4: Try system DNS
        fqdn = _dns_ptr_lookup(target_ip, nameserver=None, use_tcp=dns_tcp)
        if fqdn:
            return fqdn

    # Final fallback: return just the hostname if we have it
    if server_name:
        return server_name

    return "UNKNOWN_HOST"


def _dns_ptr_lookup(ip: str, nameserver: Optional[str] = None, use_tcp: bool = False) -> Optional[str]:
    """
    Perform DNS PTR lookup to resolve IP to hostname.

    Args:
        ip: IP address to resolve
        nameserver: Optional DNS server to query (e.g., DC IP)
        use_tcp: Force DNS queries over TCP (required for SOCKS proxies)

    Returns:
        FQDN if successful, None otherwise
    """
    try:
        # Try using dnspython if available (supports custom nameserver and TCP)
        if nameserver or use_tcp:
            try:
                import dns.resolver
                import dns.reversename

                # Create resolver with custom nameserver
                resolver = dns.resolver.Resolver(configure=False)
                if nameserver:
                    resolver.nameservers = [nameserver]
                resolver.timeout = 3
                resolver.lifetime = 3

                # Force TCP if requested (required for SOCKS/proxychains)
                tcp_flag = use_tcp

                # Perform PTR lookup
                rev_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(rev_name, "PTR", tcp=tcp_flag)

                if answers:
                    # Return first answer, strip trailing dot
                    fqdn = str(answers[0]).rstrip(".")
                    return fqdn
            except ImportError:
                # dnspython not available, fall through to socket method
                pass
            except (OSError, socket.timeout):
                # DNS query failed, fall through to socket method
                pass

        # Fallback: Use system resolver (socket.getfqdn)
        # This uses system DNS settings
        fqdn = socket.getfqdn(ip)

        # Validate we got an actual FQDN, not just the IP back
        if fqdn and fqdn != ip and "." in fqdn:
            return fqdn

        # Also try gethostbyaddr
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            return hostname

    except (OSError, socket.herror, socket.gaierror):
        pass

    return None
