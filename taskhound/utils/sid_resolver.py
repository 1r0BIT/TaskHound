# SID Resolution utilities for TaskHound
#
# This module handles resolving Windows SIDs to human-readable usernames
# using BloodHound data first, then falling back to LDAP queries when available.

import re
import socket
import struct
from typing import Optional, Tuple

from ..parsers.highvalue import HighValueLoader
from ..utils.logging import debug, info, warn


def is_sid(value: str) -> bool:
    """Check if a string looks like a Windows SID."""
    if not value:
        return False
    # SID pattern: S-1-<revision>-<authority>-<sub-authorities>
    # Must have at least revision and authority, sub-authorities are optional but common
    pattern = r'^S-1-\d+(-\d+)+$'  # At least one sub-authority required
    return bool(re.match(pattern, value.strip()))


def sid_to_binary(sid_string: str) -> Optional[bytes]:
    """
    Convert a SID string (S-1-5-21-...) to binary format for LDAP queries.
    
    Args:
        sid_string: String representation of SID
        
    Returns:
        Binary representation of SID for LDAP queries, None if invalid
    """
    try:
        if not sid_string.startswith('S-'):
            return None

        parts = sid_string[2:].split('-')
        if len(parts) < 3:
            return None

        revision = int(parts[0])
        authority = int(parts[1])
        subauthorities = [int(x) for x in parts[2:]]

        # Pack the SID according to Windows SID binary format
        # Revision (1 byte) + SubAuthorityCount (1 byte) + Authority (6 bytes) + SubAuthorities (4 bytes each)
        binary_sid = struct.pack('B', revision)  # Revision
        binary_sid += struct.pack('B', len(subauthorities))  # SubAuthorityCount
        binary_sid += struct.pack('>Q', authority)[2:]  # Authority (6 bytes, big-endian)

        for subauth in subauthorities:
            binary_sid += struct.pack('<I', subauth)  # SubAuthorities (little-endian)

        return binary_sid

    except (ValueError, struct.error) as e:
        debug(f"Error converting SID {sid_string} to binary: {e}")
        return None


def binary_to_sid(binary_sid: bytes) -> Optional[str]:
    """
    Convert a binary SID (from LDAP objectSid attribute) to string format.
    
    Args:
        binary_sid: Binary representation of SID from LDAP
        
    Returns:
        String representation like "S-1-5-21-...", None if invalid
    """
    try:
        if not binary_sid or len(binary_sid) < 8:
            return None

        # Unpack the SID binary format
        revision = struct.unpack('B', binary_sid[0:1])[0]
        subauth_count = struct.unpack('B', binary_sid[1:2])[0]
        
        # Authority is 6 bytes, big-endian (bytes 2-8)
        # We need to pad it to 8 bytes for unpacking as Q
        authority = struct.unpack('>Q', b'\x00\x00' + binary_sid[2:8])[0]
        
        # Build the SID string
        sid_parts = [f"S-{revision}-{authority}"]
        
        # Extract sub-authorities (4 bytes each, little-endian)
        offset = 8
        for _ in range(subauth_count):
            if offset + 4 > len(binary_sid):
                debug(f"Binary SID too short for claimed sub-authority count")
                return None
            subauth = struct.unpack('<I', binary_sid[offset:offset+4])[0]
            sid_parts.append(str(subauth))
            offset += 4
        
        return '-'.join(sid_parts)

    except (ValueError, struct.error) as e:
        debug(f"Error converting binary SID to string: {e}")
        return None


def resolve_sid_from_bloodhound(sid: str, hv_loader: Optional[HighValueLoader]) -> Optional[str]:
    """
    Resolve SID to username using BloodHound data.
    
    Args:
        sid: Windows SID to resolve
        hv_loader: Loaded BloodHound data (can be None)
        
    Returns:
        Username if found in BloodHound data, None otherwise
    """
    if not hv_loader or not hv_loader.loaded:
        return None

    # Check if SID exists in BloodHound data
    user_data = hv_loader.hv_sids.get(sid)
    if user_data:
        # Try to get samaccountname or name
        username = user_data.get("samaccountname") or user_data.get("name")
        if username:
            info(f"Resolved SID {sid} to {username} via BloodHound data")
            return username.strip().strip('"')

    return None


def resolve_sid_via_ldap(sid: str, domain: str, dc_ip: Optional[str] = None,
                        username: Optional[str] = None, password: Optional[str] = None,
                        hashes: Optional[str] = None, kerberos: bool = False) -> Optional[str]:
    """
    Resolve SID to username using LDAP query with ldap3 library.
    
    Args:
        sid: Windows SID to resolve
        domain: Domain name
        dc_ip: Domain controller IP (optional)
        username: Authentication username
        password: Authentication password
        hashes: NTLM hashes for authentication
        kerberos: Use Kerberos authentication
        
    Returns:
        Username if resolved via LDAP, None otherwise
    """
    try:
        from ldap3 import ALL, KERBEROS, NTLM, SASL, Connection, Server
        from ldap3.core.exceptions import LDAPBindError, LDAPException

    except ImportError:
        warn("ldap3 library not available - SID resolution via LDAP disabled")
        return None

    # Convert SID to binary format for LDAP search
    binary_sid = sid_to_binary(sid)
    if not binary_sid:
        warn(f"Failed to convert SID {sid} to binary format")
        return None

    try:
        # Determine DC address
        if not dc_ip:
            try:
                dc_ip = socket.gethostbyname(domain)
                debug(f"Resolved domain {domain} to IP {dc_ip}")
            except socket.gaierror:
                warn(f"Could not resolve domain {domain} to IP for LDAP query")
                return None

        # Create LDAP server connection with proper timeout settings and SSL support
        # Try LDAPS first (636), then LDAP with StartTLS (389), then plain LDAP as fallback
        server = None
        server_ssl = False
        server_port = 389

        for port, use_ssl, use_tls in [(636, True, False), (389, False, True), (389, False, False)]:
            try:
                debug(f"Trying LDAP connection on port {port}, SSL={use_ssl}, TLS={use_tls}")
                server = Server(dc_ip, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=10)
                # Test connection
                test_conn = Connection(server)
                if test_conn.open():
                    if use_tls:
                        test_conn.start_tls()
                    test_conn.unbind()
                    debug(f"Successfully connected to {dc_ip}:{port} (SSL={use_ssl}, TLS={use_tls})")
                    server_ssl = use_ssl
                    server_port = port
                    break
            except Exception as e:
                debug(f"Connection to {dc_ip}:{port} failed: {e}")
                server = None
                continue

        if not server:
            warn(f"Could not establish LDAP connection to {dc_ip} on any port")
            return None

        # Determine authentication method - prioritize NTLM over Kerberos for reliability
        conn = None
        if kerberos and not hashes:
            # Only use Kerberos if specifically requested and no hashes provided
            try:
                debug("Attempting Kerberos authentication for LDAP SID resolution")
                conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
            except Exception as e:
                warn(f"Kerberos authentication failed for LDAP, falling back to NTLM: {e}")
                conn = None

        # Use NTLM authentication (more reliable for our use case)
        if not conn:
            if hashes:
                # NTLM hash authentication
                if ':' in hashes:
                    lm_hash, nt_hash = hashes.split(':', 1)
                else:
                    lm_hash, nt_hash = '', hashes
                debug("Using NTLM hash authentication for LDAP SID resolution")
                try:
                    # For NTLM hash authentication, we need to use a different approach
                    # ldap3 doesn't directly support NTLM hash authentication in newer versions
                    # We'll skip hash authentication for now and only use password-based auth
                    warn("LDAP hash authentication not supported with current ldap3 version")
                    warn("Please provide password instead of hashes for LDAP SID resolution")
                    return None

                except Exception as e:
                    warn(f"NTLM hash authentication failed for LDAP: {e}")
                    return None
            else:
                # Username/password authentication with NTLM
                debug("Using NTLM username/password authentication for LDAP SID resolution")
                try:
                    # Try NTLM first
                    conn = Connection(server,
                                    user=f"{domain}\\{username}",
                                    password=password,
                                    authentication=NTLM,
                                      auto_bind=False)

                    # Handle StartTLS if needed
                    if server_port == 389 and not server_ssl:
                        try:
                            conn.start_tls()
                        except Exception:
                            pass

                    if not conn.bind():
                        debug(f"NTLM bind failed, trying simple bind: {conn.last_error}")
                        # Try simple bind as fallback
                        conn = Connection(server,
                                        user=f"{username}@{domain}",
                                        password=password,
                                        auto_bind=False)

                        # Handle StartTLS for simple bind too
                        if server_port == 389 and not server_ssl:
                            try:
                                conn.start_tls()
                            except Exception:
                                pass

                        if not conn.bind():
                            warn(f"All authentication methods failed: {conn.last_error}")
                            return None
                except Exception as e:
                    warn(f"Authentication failed for LDAP: {e}")
                    return None

        if not conn or not conn.bound:
            warn(f"Failed to bind to LDAP server {dc_ip} for SID resolution")
            return None

        debug(f"Successfully bound to LDAP server {dc_ip}")

        # Build search base DN from domain
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        debug(f"Using LDAP base DN: {base_dn}")

        # Create search filter using binary SID
        # The binary SID needs to be properly escaped for LDAP
        binary_sid_escaped = ''.join([f'\\{b:02x}' for b in binary_sid])
        search_filter = f"(objectSid={binary_sid_escaped})"
        debug(f"LDAP search filter: {search_filter}")

        # Perform the search
        search_success = conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            attributes=['samAccountName', 'name', 'displayName', 'objectClass']
        )

        if search_success and conn.entries:
            entry = conn.entries[0]
            debug(f"Found LDAP entry: {entry.entry_dn}")

            # Try different name attributes in order of preference
            sam_account_name = str(entry.samAccountName) if hasattr(entry, 'samAccountName') and entry.samAccountName else None
            display_name = str(entry.displayName) if hasattr(entry, 'displayName') and entry.displayName else None
            name = str(entry.name) if hasattr(entry, 'name') and entry.name else None

            username_resolved = sam_account_name or display_name or name

            if username_resolved:
                info(f"Resolved SID {sid} to {username_resolved} via LDAP")
                conn.unbind()
                return username_resolved.strip()
            else:
                debug(f"No usable name attribute found in LDAP entry for SID {sid}")
        else:
            debug(f"No LDAP entries found for SID {sid}")

        conn.unbind()
        return None

    except LDAPBindError as e:
        warn(f"LDAP bind error during SID resolution: {e}")
        return None
    except LDAPException as e:
        warn(f"LDAP error during SID resolution: {e}")
        return None
    except Exception as e:
        warn(f"Unexpected error during LDAP SID resolution: {e}")
        debug(f"Full traceback: {e}", exc_info=True)
        return None


def resolve_name_to_sid_via_ldap(name: str, domain: str, is_computer: bool = False,
                                 dc_ip: Optional[str] = None,
                                 username: Optional[str] = None, password: Optional[str] = None,
                                 hashes: Optional[str] = None, kerberos: bool = False) -> Optional[str]:
    """
    Resolve a computer name or username to its SID using LDAP.
    This is the reverse operation of resolve_sid_via_ldap.
    
    Args:
        name: Computer name (without domain) or username (USER@DOMAIN.TLD format or just USER)
        domain: Domain name (e.g., "corp.local")
        is_computer: True if resolving a computer account, False for user
        dc_ip: Domain controller IP address (optional, will try to resolve if not provided)
        username: LDAP authentication username (can be different from the name being resolved)
        password: LDAP authentication password
        hashes: NTLM hashes for pass-the-hash (format: lm:nt)
        kerberos: Use Kerberos authentication
        
    Returns:
        SID string (e.g., "S-1-5-21-..."), None if resolution fails
    """
    try:
        from ldap3 import Server, Connection, Tls, NTLM, SIMPLE, AUTO_BIND_NO_TLS
        from ldap3.core.exceptions import LDAPException, LDAPBindError
        import ssl

        # Extract just the name part if it's in USER@DOMAIN format
        search_name = name
        if '@' in name and not is_computer:
            search_name = name.split('@')[0]
        
        # For computers, strip the trailing $ if present
        if is_computer and search_name.endswith('$'):
            search_name = search_name[:-1]

        # If no DC IP provided, try to resolve it
        if not dc_ip:
            try:
                dc_ip = socket.gethostbyname(domain)
                debug(f"Resolved domain {domain} to DC IP: {dc_ip}")
            except socket.gaierror:
                warn(f"Could not resolve domain {domain} to IP address")
                return None

        # Try LDAPS (636) first, then LDAP (389)
        for server_port, server_ssl in [(636, True), (389, False)]:
            try:
                debug(f"Attempting LDAP connection to {dc_ip}:{server_port} (SSL: {server_ssl})")

                if server_ssl:
                    # For LDAPS, create TLS object with validation disabled
                    tls_config = Tls(validate=ssl.CERT_NONE)
                    server = Server(f"ldaps://{dc_ip}:{server_port}", use_ssl=True, tls=tls_config)
                else:
                    server = Server(f"ldap://{dc_ip}:{server_port}", use_ssl=False)

                conn = None

                # Try Kerberos first if requested
                if kerberos and username and not password and not hashes:
                    debug(f"Attempting Kerberos authentication")
                    try:
                        conn = Connection(server,
                                        user=f"{username}@{domain}",
                                        auto_bind=False)

                        if server_port == 389 and not server_ssl:
                            try:
                                conn.start_tls()
                            except Exception:
                                pass

                        if not conn.bind():
                            debug(f"Kerberos bind failed: {conn.last_error}")
                            conn = None
                    except Exception as e:
                        debug(f"Kerberos authentication failed: {e}")
                        conn = None

                # Try NTLM with password or hashes
                if not conn and username and (password or hashes):
                    try:
                        auth_user = f"{domain}\\{username}" if '\\' not in username and '@' not in username else username

                        if hashes:
                            # Pass-the-hash
                            debug(f"Attempting NTLM authentication with hashes")
                            lm_hash, nt_hash = hashes.split(':') if ':' in hashes else ('', hashes)
                            conn = Connection(server,
                                            user=auth_user,
                                            password=f"{lm_hash}:{nt_hash}",
                                            authentication=NTLM,
                                            auto_bind=False)
                        else:
                            # Password authentication
                            debug(f"Attempting NTLM authentication with password")
                            conn = Connection(server,
                                            user=auth_user,
                                            password=password,
                                            authentication=NTLM,
                                            auto_bind=False)

                        if server_port == 389 and not server_ssl:
                            try:
                                conn.start_tls()
                            except Exception:
                                pass

                        if not conn.bind():
                            debug(f"NTLM bind failed: {conn.last_error}")
                            conn = Connection(server,
                                            user=f"{username}@{domain}",
                                            password=password,
                                            auto_bind=False)

                            if server_port == 389 and not server_ssl:
                                try:
                                    conn.start_tls()
                                except Exception:
                                    pass

                            if not conn.bind():
                                debug(f"Simple bind also failed: {conn.last_error}")
                                conn = None
                    except Exception as e:
                        debug(f"NTLM authentication failed: {e}")
                        conn = None

                # If we got a connection, break the loop
                if conn and conn.bound:
                    break

            except Exception as e:
                debug(f"Failed to connect to {dc_ip}:{server_port}: {e}")
                continue

        if not conn or not conn.bound:
            warn(f"Failed to bind to LDAP server {dc_ip} for name resolution")
            return None

        debug(f"Successfully bound to LDAP server {dc_ip}")

        # Build search base DN from domain
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        debug(f"Using LDAP base DN: {base_dn}")

        # Create search filter based on object type
        if is_computer:
            # For computers, search by cn (computer name without $)
            search_filter = f"(&(objectClass=computer)(cn={search_name}))"
        else:
            # For users, try both samAccountName and userPrincipalName
            # Use OR to handle cases where UPN might not be set (e.g., built-in accounts)
            if '@' in name:
                # If in UPN format, try both UPN and samAccountName
                search_filter = f"(&(objectClass=user)(|(userPrincipalName={name})(samAccountName={search_name})))"
            else:
                # Otherwise search by samAccountName only
                search_filter = f"(&(objectClass=user)(samAccountName={search_name}))"

        debug(f"LDAP search filter: {search_filter}")

        # Perform the search
        search_success = conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            attributes=['objectSid', 'samAccountName', 'cn']
        )

        if search_success and conn.entries:
            entry = conn.entries[0]
            debug(f"Found LDAP entry: {entry.entry_dn}")

            # Extract the binary objectSid
            if hasattr(entry, 'objectSid') and entry.objectSid:
                # Handle different ways ldap3 might return the objectSid
                if hasattr(entry.objectSid, 'value'):
                    binary_sid = entry.objectSid.value
                elif hasattr(entry.objectSid, 'raw_values'):
                    # Sometimes it's in raw_values as a list
                    binary_sid = entry.objectSid.raw_values[0] if entry.objectSid.raw_values else None
                else:
                    binary_sid = entry.objectSid
                
                debug(f"objectSid type: {type(binary_sid)}, value: {binary_sid!r}")
                
                # Ensure we have bytes
                if isinstance(binary_sid, str):
                    # If it's already a string SID, return it
                    if binary_sid.startswith('S-1-'):
                        info(f"Resolved {name} to SID {binary_sid} via LDAP (already string)")
                        conn.unbind()
                        return binary_sid
                    else:
                        debug(f"objectSid is string but not SID format: {binary_sid}")
                        binary_sid = None
                
                if isinstance(binary_sid, bytes):
                    # Convert binary SID to string
                    sid_string = binary_to_sid(binary_sid)
                    
                    if sid_string:
                        account_name = str(entry.samAccountName) if hasattr(entry, 'samAccountName') else str(entry.cn) if hasattr(entry, 'cn') else name
                        info(f"Resolved {account_name} to SID {sid_string} via LDAP")
                        conn.unbind()
                        return sid_string
                    else:
                        debug(f"Failed to convert binary SID to string for {name}")
                else:
                    debug(f"objectSid is not bytes or string SID: {type(binary_sid)}")
            else:
                debug(f"No objectSid attribute found in LDAP entry for {name}")
        else:
            debug(f"No LDAP entries found for {name}")

        conn.unbind()
        return None

    except LDAPBindError as e:
        warn(f"LDAP bind error during name→SID resolution: {e}")
        return None
    except LDAPException as e:
        warn(f"LDAP error during name→SID resolution: {e}")
        return None
    except Exception as e:
        warn(f"Unexpected error during LDAP name→SID resolution: {e}")
        debug(f"Full traceback: {e}", exc_info=True)
        return None


def resolve_sid(sid: str, hv_loader: Optional[HighValueLoader] = None,
               no_ldap: bool = False, domain: Optional[str] = None,
               dc_ip: Optional[str] = None, username: Optional[str] = None,
               password: Optional[str] = None, hashes: Optional[str] = None,
               kerberos: bool = False, ldap_domain: Optional[str] = None,
               ldap_user: Optional[str] = None, ldap_password: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """
    Comprehensive SID resolution with fallback chain.
    
    Args:
        sid: Windows SID to resolve
        hv_loader: BloodHound data loader (optional)
        no_ldap: Disable LDAP resolution
        domain: Domain name for LDAP
        dc_ip: Domain controller IP
        username: Authentication username
        password: Authentication password  
        hashes: NTLM hashes
        kerberos: Use Kerberos
        
    Returns:
        Tuple of (display_name, resolved_username)
        - display_name: What to show in output (SID + username or just SID)
        - resolved_username: Just the resolved username (for internal use)
    """
    if not is_sid(sid):
        # Not a SID, return as-is
        return sid, None

    debug(f"Attempting to resolve SID: {sid}")

    # Try BloodHound first
    resolved = resolve_sid_from_bloodhound(sid, hv_loader)
    if resolved:
        debug(f"SID {sid} resolved via BloodHound: {resolved}")
        return f"{resolved} ({sid})", resolved

    # Try LDAP if enabled and we have sufficient authentication info
    # Prioritize dedicated LDAP credentials over main auth credentials
    ldap_auth_domain = ldap_domain if ldap_domain else domain
    ldap_auth_user = ldap_user if ldap_user else username
    ldap_auth_password = ldap_password if ldap_password else password

    # Only use LDAP hash authentication if no dedicated LDAP password is provided
    ldap_auth_hashes = None if ldap_password else hashes

    if not no_ldap and ldap_auth_domain and ldap_auth_user:
        debug(f"Attempting LDAP resolution for SID {sid}")
        resolved = resolve_sid_via_ldap(sid, ldap_auth_domain, dc_ip, ldap_auth_user, ldap_auth_password, ldap_auth_hashes, kerberos)
        if resolved:
            debug(f"SID {sid} resolved via LDAP: {resolved}")
            return f"{resolved} ({sid})", resolved

    # Could not resolve - return SID with appropriate explanation
    if no_ldap:
        debug(f"SID {sid} not resolved: LDAP resolution disabled")
        return f"{sid} (SID - LDAP resolution disabled)", None
    elif not ldap_auth_domain or not ldap_auth_user:
        debug(f"SID {sid} not resolved: insufficient authentication information")
        return f"{sid} (SID - insufficient auth for LDAP resolution)", None
    else:
        debug(f"SID {sid} not resolved: could not find in BloodHound or LDAP")
        return f"{sid} (SID - could not resolve: deleted user, cross-domain, or access denied)", None


def format_runas_with_sid_resolution(runas: str, hv_loader: Optional[HighValueLoader] = None,
                                   no_ldap: bool = False, domain: Optional[str] = None,
                                   dc_ip: Optional[str] = None, username: Optional[str] = None,
                                   password: Optional[str] = None, hashes: Optional[str] = None,
                                   kerberos: bool = False, ldap_domain: Optional[str] = None,
                                   ldap_user: Optional[str] = None, ldap_password: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """
    Format RunAs field with SID resolution if needed.
    
    Args:
        runas: The RunAs field value to potentially resolve
        hv_loader: BloodHound data loader (optional)
        no_ldap: Disable LDAP resolution
        domain: Domain name for LDAP
        dc_ip: Domain controller IP
        username: Authentication username
        password: Authentication password  
        hashes: NTLM hashes
        kerberos: Use Kerberos
    
    Returns:
        Tuple of (display_runas, resolved_username)
        - display_runas: Formatted string for display
        - resolved_username: Just the resolved username (for internal use)
    """
    if not runas:
        return runas, None

    # Check if it's a SID
    if is_sid(runas):
        return resolve_sid(runas, hv_loader, no_ldap, domain, dc_ip, username, password, hashes, kerberos, ldap_domain, ldap_user, ldap_password)
    else:
        # Regular username, return as-is
        return runas, None
