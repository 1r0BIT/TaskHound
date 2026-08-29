# LSARPC Backend
#
# Resolution via LSARPC over SMB to target machine or Domain Controller.


from ...utils.logging import debug, info


def resolve_sid_via_smb(sid: str, smb_connection) -> str | None:
    """
    Resolve SID to username using LSARPC over an existing SMB connection.

    This is useful when we have a valid SMB session (e.g. via Kerberos CIFS ticket)
    but cannot authenticate to the DC via LDAP (e.g. missing TGT/LDAP ticket).

    Args:
        sid: Windows SID to resolve
        smb_connection: Active impacket.smbconnection.SMBConnection

    Returns:
        Resolved username (DOMAIN\\User) or None
    """
    if not smb_connection:
        return None

    try:
        from impacket.dcerpc.v5 import lsad, lsat, transport
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        debug(f"Attempting SMB/LSARPC resolution for SID: {sid}")

        # Connect to LSARPC pipe
        # We reuse the existing SMB connection
        rpctransport = transport.SMBTransport(
            smb_connection.getRemoteName(),
            smb_connection.getRemoteHost(),
            filename=r"\lsarpc",
            smb_connection=smb_connection,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)

        # Open policy using lsad module (hLsarOpenPolicy2 is in lsad, not lsat)
        # We need POLICY_LOOKUP_NAMES to resolve SIDs
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp["PolicyHandle"]

        # Lookup SID
        try:
            resp = lsat.hLsarLookupSids(dce, policyHandle, [sid], lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            names = resp["TranslatedNames"]["Names"]
            domains = resp["ReferencedDomains"]["Domains"]

            if names:
                name_entry = names[0]
                domain_idx = name_entry["DomainIndex"]
                name = name_entry["Name"]

                # If we have a domain index, try to resolve domain name too
                domain_name = ""
                if domain_idx >= 0 and domain_idx < len(domains):
                    domain_name = domains[domain_idx]["Name"]

                full_name = f"{domain_name}\\{name}" if domain_name else name
                info(f"Resolved SID {sid} to {full_name} via SMB/LSARPC")
                return full_name

        except DCERPCException as e:
            debug(f"LSARPC lookup failed for {sid}: {e}")
        finally:
            try:
                lsad.hLsarClose(dce, policyHandle)
            except Exception:
                pass

        dce.disconnect()

    except Exception as e:
        debug(f"SMB SID resolution failed: {e}")

    return None


def resolve_sid_via_dc_lsarpc(
    sid: str,
    dc_ip: str,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    aes_key: str | None = None,
) -> str | None:
    """
    Resolve SID to username using LSARPC directly to the Domain Controller.

    Unlike resolve_sid_via_smb() which queries the TARGET machine, this function
    queries the DC directly. The DC can resolve SIDs from trusted domains by
    following the trust path - making this ideal for cross-domain/cross-forest
    SID resolution.

    Args:
        sid: Windows SID to resolve
        dc_ip: Domain Controller IP address
        domain: Domain name for authentication
        username: Username for authentication
        password: Password (plaintext or LM:NT hash format)
        hashes: NTLM hashes in LM:NT format (alternative to password)
        kerberos: Use Kerberos authentication
        aes_key: AES key for Kerberos authentication

    Returns:
        Resolved username (DOMAIN\\User) or None
    """
    if not dc_ip or not username:
        return None

    try:
        from impacket.dcerpc.v5 import lsad, lsat, transport
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        debug(f"Attempting DC LSARPC resolution for SID: {sid} via {dc_ip}")

        # Parse hashes if provided
        lmhash = ""
        nthash = ""
        pwd = password or ""

        if hashes:
            if ":" in hashes:
                lmhash, nthash = hashes.split(":", 1)
            else:
                nthash = hashes
            pwd = ""  # Don't use password when hashes provided
        elif password and ":" in password and len(password) == 65:
            # Password might be in hash format
            lmhash, nthash = password.split(":", 1)
            pwd = ""

        # Create RPC transport to DC's LSARPC pipe
        # Use named pipe over SMB (ncacn_np)
        string_binding = f"ncacn_np:{dc_ip}[\\pipe\\lsarpc]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        # Set credentials
        rpc_transport.set_credentials(
            username=username,
            password=pwd,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=aes_key or "",
        )

        if kerberos:
            rpc_transport.set_kerberos(True, kdcHost=dc_ip)

        # Connect and bind
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)

        # Open policy handle
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policy_handle = resp["PolicyHandle"]

        # Lookup SID - use LsapLookupWksta level which follows trusts
        try:
            resp = lsat.hLsarLookupSids(dce, policy_handle, [sid], lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            names = resp["TranslatedNames"]["Names"]
            domains = resp["ReferencedDomains"]["Domains"]

            if names:
                name_entry = names[0]
                domain_idx = name_entry["DomainIndex"]
                name = name_entry["Name"]

                # Build full name with domain prefix
                domain_name = ""
                if domain_idx >= 0 and domain_idx < len(domains):
                    domain_name = domains[domain_idx]["Name"]

                full_name = f"{domain_name}\\{name}" if domain_name else name
                info(f"Resolved SID {sid} to {full_name} via DC LSARPC ({dc_ip})")

                # Clean up
                try:
                    lsad.hLsarClose(dce, policy_handle)
                except Exception:
                    pass
                dce.disconnect()

                return full_name

        except DCERPCException as e:
            # STATUS_NONE_MAPPED means DC couldn't resolve it either
            # This is expected for truly external/unknown SIDs
            if "STATUS_NONE_MAPPED" in str(e):
                debug(f"DC LSARPC: SID {sid} not found (STATUS_NONE_MAPPED)")
            else:
                debug(f"DC LSARPC lookup failed for {sid}: {e}")

        # Clean up
        try:
            lsad.hLsarClose(dce, policy_handle)
        except Exception:
            pass
        dce.disconnect()

    except Exception as e:
        debug(f"DC LSARPC resolution failed for {sid}: {e}")

    return None
