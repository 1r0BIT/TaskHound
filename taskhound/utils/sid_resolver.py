# SID Resolution utilities for TaskHound
#
# This module handles resolving Windows SIDs to human-readable usernames
# using BloodHound data first, then falling back to LDAP queries when available.
# REFACTORED: Now uses Impacket LDAP with NTLM hash support

import re
import socket
import struct
from typing import Optional, Tuple

from impacket.ldap import ldap as ldap_impacket
from impacket.ldap import ldapasn1 as ldapasn1_impacket

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
    Resolve a SID to a username using LDAP queries to a domain controller.
    
    This function attempts to query Active Directory via LDAP to resolve a SID to a username.
    It uses the provided credentials for authentication and supports both NTLM and Kerberos.
    NOW SUPPORTS NTLM HASH AUTHENTICATION via Impacket LDAP!
    
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

        # If no DC IP provided, try to resolve it
        if not dc_ip:
            try:
                dc_ip = socket.gethostbyname(domain)
                debug(f"Resolved domain {domain} to DC IP: {dc_ip}")
            except socket.gaierror:
                warn(f"Could not resolve domain {domain} to IP address")
                return None

        # Convert SID to binary format for LDAP search
        binary_sid = sid_to_binary(sid)
        if not binary_sid:
            warn(f"Could not convert SID {sid} to binary format")
            return None

        # Parse NTLM hashes if provided
        lmhash = ""
        nthash = ""
        if hashes:
            if ':' in hashes:
                lmhash, nthash = hashes.split(':', 1)
            else:
                nthash = hashes
            debug(f"Using NTLM hash authentication for LDAP SID resolution")

        # Try connection with multiple ports/protocols: LDAPS (636) → LDAP (389)
        conn = None
        for use_ssl, target_port in [(True, 636), (False, 389)]:
            try:
                protocol = "ldaps" if use_ssl else "ldap"
                ldap_url = f"{protocol}://{dc_ip}:{target_port}"
                debug(f"Attempting LDAP connection to {ldap_url}")

                conn = ldap_impacket.LDAPConnection(ldap_url, dstIp=dc_ip)

                # Authenticate based on available credentials
                if hashes:
                    # NTLM hash authentication (NEW CAPABILITY!)
                    debug(f"Authenticating with NTLM hash as {domain}\\{username}")
                    conn.login(user=username, password="", domain=domain, lmhash=lmhash, nthash=nthash)
                elif kerberos:
                    # Kerberos authentication
                    debug(f"Authenticating with Kerberos as {username}@{domain}")
                    # Impacket's LDAP Kerberos requires ticket in cache
                    conn.kerberosLogin(username, password, domain, lmhash, nthash)
                else:
                    # Password authentication
                    debug(f"Authenticating with password as {domain}\\{username}")
                    conn.login(user=username, password=password, domain=domain)

                debug(f"Successfully authenticated to LDAP server {dc_ip}")
                break  # Success, exit loop

            except Exception as e:
                debug(f"Failed to connect/authenticate to {ldap_url}: {e}")
                conn = None
                continue

        if not conn:
            warn(f"Failed to bind to LDAP server {dc_ip} for SID resolution")
            return None

        # Build search base DN from domain
        base_dn = ','.join([f"DC={part}" for part in domain.split('.')])
        debug(f"Using LDAP base DN: {base_dn}")

        # Create search filter using binary SID
        # Impacket expects hex-escaped binary format
        binary_sid_escaped = ''.join([f'\\{b:02x}' for b in binary_sid])
        search_filter = f"(objectSid={binary_sid_escaped})"
        debug(f"LDAP search filter: {search_filter}")

        # Perform the search
        try:
            search_results = conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=['sAMAccountName', 'name', 'displayName', 'objectClass'],
                searchControls=None
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        attributes = {}
                        for attribute in entry['attributes']:
                            attr_name = str(attribute['type'])
                            attr_vals = [str(val) for val in attribute['vals']]
                            attributes[attr_name] = attr_vals[0] if len(attr_vals) == 1 else attr_vals

                        # Try different name attributes in order of preference
                        sam_account_name = attributes.get('sAMAccountName')
                        display_name = attributes.get('displayName')
                        name = attributes.get('name')

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


def resolve_name_to_sid_via_ldap(name: str, domain: str, is_computer: bool = False,
                                 dc_ip: Optional[str] = None,
                                 username: Optional[str] = None, password: Optional[str] = None,
                                 hashes: Optional[str] = None, kerberos: bool = False) -> Optional[str]:
    """
    Resolve a computer name or username to its SID using LDAP.
    This is the reverse operation of resolve_sid_via_ldap.
    NOW SUPPORTS NTLM HASH AUTHENTICATION via Impacket LDAP!
    
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
    try:
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

        # Parse NTLM hashes if provided
        lmhash = ""
        nthash = ""
        if hashes:
            if ':' in hashes:
                lmhash, nthash = hashes.split(':', 1)
            else:
                nthash = hashes
            debug(f"Using NTLM hash authentication for LDAP name resolution")

        # Try connection with multiple ports/protocols: LDAPS (636) → LDAP (389)
        conn = None
        for use_ssl, target_port in [(True, 636), (False, 389)]:
            try:
                protocol = "ldaps" if use_ssl else "ldap"
                ldap_url = f"{protocol}://{dc_ip}:{target_port}"
                debug(f"Attempting LDAP connection to {ldap_url}")

                conn = ldap_impacket.LDAPConnection(ldap_url, dstIp=dc_ip)

                # Authenticate based on available credentials
                if hashes:
                    # NTLM hash authentication (NEW CAPABILITY!)
                    debug(f"Authenticating with NTLM hash as {domain}\\{username}")
                    conn.login(user=username, password="", domain=domain, lmhash=lmhash, nthash=nthash)
                elif kerberos:
                    # Kerberos authentication
                    debug(f"Authenticating with Kerberos as {username}@{domain}")
                    conn.kerberosLogin(username, password, domain, lmhash, nthash)
                else:
                    # Password authentication
                    debug(f"Authenticating with password as {domain}\\{username}")
                    conn.login(user=username, password=password, domain=domain)

                debug(f"Successfully authenticated to LDAP server {dc_ip}")
                break  # Success, exit loop

            except Exception as e:
                debug(f"Failed to connect/authenticate to {ldap_url}: {e}")
                conn = None
                continue

        if not conn:
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
            if '@' in name:
                search_filter = f"(&(objectClass=user)(|(userPrincipalName={name})(samAccountName={search_name})))"
            else:
                search_filter = f"(&(objectClass=user)(samAccountName={search_name}))"

        debug(f"LDAP search filter: {search_filter}")

        # Perform the search
        try:
            search_results = conn.search(
                searchBase=base_dn,
                searchFilter=search_filter,
                attributes=['objectSid', 'sAMAccountName', 'cn'],
                searchControls=None
            )

            if search_results:
                for entry in search_results:
                    if isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                        attributes = {}
                        for attribute in entry['attributes']:
                            attr_name = str(attribute['type'])
                            # objectSid is binary, keep as bytes
                            if attr_name.lower() == 'objectsid':
                                # Get raw bytes
                                attr_vals = [bytes(val) for val in attribute['vals']]
                            else:
                                attr_vals = [str(val) for val in attribute['vals']]
                            attributes[attr_name] = attr_vals[0] if len(attr_vals) == 1 else attr_vals

                        # Extract the binary objectSid
                        binary_sid = attributes.get('objectSid')
                        
                        if binary_sid and isinstance(binary_sid, bytes):
                            # Convert binary SID to string
                            sid_string = binary_to_sid(binary_sid)
                            
                            if sid_string:
                                account_name = attributes.get('sAMAccountName') or attributes.get('cn') or name
                                info(f"Resolved {account_name} to SID {sid_string} via LDAP")
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


def resolve_sid(sid: str, hv_loader: Optional[HighValueLoader] = None,
               no_ldap: bool = False, domain: Optional[str] = None,
               dc_ip: Optional[str] = None, username: Optional[str] = None,
               password: Optional[str] = None, hashes: Optional[str] = None,
               kerberos: bool = False, ldap_domain: Optional[str] = None,
               ldap_user: Optional[str] = None, ldap_password: Optional[str] = None,
               ldap_hashes: Optional[str] = None) -> Tuple[str, Optional[str]]:
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
        ldap_domain: Separate LDAP domain (for local admin case)
        ldap_user: Separate LDAP username (for local admin case)
        ldap_password: Separate LDAP password (for local admin case - plaintext only)
        ldap_hashes: Separate LDAP NTLM hashes (for local admin case - use instead of ldap_password)
        
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
    ldap_auth_hashes = ldap_hashes if ldap_hashes else hashes

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
                                   ldap_user: Optional[str] = None, ldap_password: Optional[str] = None,
                                   ldap_hashes: Optional[str] = None) -> Tuple[str, Optional[str]]:
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
        ldap_domain: Separate LDAP domain (for local admin case)
        ldap_user: Separate LDAP username (for local admin case)
        ldap_password: Separate LDAP password (for local admin case - plaintext only)
        ldap_hashes: Separate LDAP NTLM hashes (for local admin case - use instead of ldap_password)
    
    Returns:
        Tuple of (display_runas, resolved_username)
        - display_runas: Formatted string for display
        - resolved_username: Just the resolved username (for internal use)
    """
    if not runas:
        return runas, None

    # Check if it's a SID
    if is_sid(runas):
        return resolve_sid(runas, hv_loader, no_ldap, domain, dc_ip, username, password, hashes, kerberos, ldap_domain, ldap_user, ldap_password, ldap_hashes)
    else:
        # Regular username, return as-is
        return runas, None
