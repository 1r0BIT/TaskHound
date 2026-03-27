# Local user enumeration via SAMR (Security Account Manager Remote Protocol).
#
# Uses the existing SMB connection to enumerate local user accounts on a target
# without code execution. Results are cached per-host to avoid repeated RPC calls.

from typing import TYPE_CHECKING, Dict

from impacket.dcerpc.v5 import samr, transport
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

from ..utils.cache_manager import get_cache
from ..utils.logging import debug, info

if TYPE_CHECKING:
    from impacket.smbconnection import SMBConnection

_CACHE_CATEGORY = "local_users"
_CACHE_TTL_HOURS = 24


def enumerate_local_users(smb: "SMBConnection", hostname: str) -> Dict[str, int]:
    """
    Enumerate local user accounts on a Windows host via SAMR (\\pipe\\samr).

    Connects to the SAM Remote protocol using the existing SMB session,
    looks up the host's account domain, and enumerates all normal user accounts.

    Results are cached under ("local_users", hostname.upper()) for 24 hours so
    subsequent calls — including offline OpenGraph generation — pay no RPC cost.

    Args:
        smb: Active impacket SMBConnection (already authenticated)
        hostname: FQDN or NetBIOS name of the target (used as cache key)

    Returns:
        {lowercase_name: rid} for all normal local accounts, or {} on any failure.
    """
    cache_key = hostname.upper()

    # Return cached result immediately — zero extra RPC calls after first scan
    cached = get_cache().get(_CACHE_CATEGORY, cache_key)
    if cached is not None:
        debug(f"{hostname}: Using cached local user list ({len(cached)} accounts)")
        return cached

    try:
        # Reuse the existing SMB session for the SAMR named pipe
        rpc_transport = transport.SMBTransport(
            smb.getRemoteName(),
            smb.getRemoteHost(),
            filename=r"\samr",
            smb_connection=smb,
        )
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Connect to the SAM server
        server_h = samr.hSamrConnect5(dce, "\x00", MAXIMUM_ALLOWED)["ServerHandle"]

        # Get the account domain SID using the machine's own NetBIOS name.
        # The account domain holds local user accounts (RID 500, 501, etc.).
        # This is distinct from the BUILTIN domain (S-1-5-32) which holds groups.
        machine_name = smb.getServerName()
        domain_sid_resp = samr.hSamrLookupDomainInSamServer(dce, server_h, machine_name)
        domain_sid = domain_sid_resp["DomainId"]

        # Open the account domain
        domain_h = samr.hSamrOpenDomain(dce, server_h, MAXIMUM_ALLOWED, domain_sid)["DomainHandle"]

        # Enumerate all normal user accounts.
        # preferedMaximumLength=0xffffffff fetches all entries in a single call for
        # typical workstation/server account counts (rarely more than a dozen).
        result: Dict[str, int] = {}
        enum_context = 0

        while True:
            try:
                resp = samr.hSamrEnumerateUsersInDomain(
                    dce,
                    domain_h,
                    userAccountControl=samr.USER_NORMAL_ACCOUNT,
                    enumerationContext=enum_context,
                    preferedMaximumLength=0xFFFFFFFF,
                )
                entries = resp["Buffer"]["Buffer"]
                for entry in entries:
                    name = str(entry["Name"])
                    rid = entry["RelativeId"]
                    result[name.lower()] = rid
                enum_context = resp["EnumerationContext"]
                if enum_context == 0:
                    break
            except Exception as page_err:
                # STATUS_MORE_ENTRIES is raised as an exception by impacket
                if "STATUS_MORE_ENTRIES" in str(page_err):
                    # More data available — update context and continue
                    try:
                        resp = page_err.get_packet()  # type: ignore[attr-defined]
                        enum_context = resp["EnumerationContext"]
                        entries = resp["Buffer"]["Buffer"]
                        for entry in entries:
                            name = str(entry["Name"])
                            rid = entry["RelativeId"]
                            result[name.lower()] = rid
                    except Exception:
                        break
                    continue
                raise

        # Cleanup handles (best effort)
        try:
            samr.hSamrCloseHandle(dce, domain_h)
            samr.hSamrCloseHandle(dce, server_h)
        except Exception:
            pass
        dce.disconnect()

        # Cache and report
        get_cache().set(_CACHE_CATEGORY, cache_key, result, ttl_hours=_CACHE_TTL_HOURS)
        info(f"{hostname}: Discovered {len(result)} local user accounts via SAMR (RID 500 = '{_admin_name(result)}')")
        return result

    except Exception as exc:
        debug(f"{hostname}: SAMR local user enumeration failed: {exc}")
        return {}


def _admin_name(local_users: Dict[str, int]) -> str:
    """Return the name of the RID-500 account, or 'Administrator' if not found."""
    for name, rid in local_users.items():
        if rid == 500:
            return name
    return "Administrator"
