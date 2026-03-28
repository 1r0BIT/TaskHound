# Windows Service enumeration via SVCCTL RPC (MS-SCMR).
#
# Enumerates installed services on a remote host by binding to the
# \pipe\svcctl named pipe on an existing SMB connection. Uses the
# Service Control Manager (SCM) RPC interface — the same mechanism
# that Windows sc.exe uses internally.
#
# Key impacket calls:
#   hROpenSCManagerW     → get SCM handle
#   hREnumServicesStatusW → list all services with status
#   hROpenServiceW       → open individual service handle
#   hRQueryServiceConfigW → get full config (account, binary, start type)
#   hRCloseServiceHandle → cleanup
#
# The pipe is closed via _close_dce_pipe() to avoid corrupting the
# shared SMB connection for subsequent RPC operations (SAMR, LSARPC).

import contextlib
from typing import Any, Dict, List, Optional

from impacket.dcerpc.v5 import scmr, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SMBConnection

from ..utils.cache_manager import get_cache
from ..utils.logging import debug as log_debug
from ..utils.logging import warn
from .builtin_services import BUILTIN_SERVICE_NAMES

_SVC_CACHE_CATEGORY = "service_configs"

# Win32 service types we care about (skip drivers)
_WIN32_SERVICE_TYPES = (
    scmr.SERVICE_WIN32_OWN_PROCESS
    | scmr.SERVICE_WIN32_SHARE_PROCESS
)


def _close_dce_pipe(dce) -> None:
    """Close named-pipe file handle without disrupting the SMB connection.

    Replicates the pattern from smb/credguard.py — closes only the file
    handle on the IPC$ tree, leaving the tree connected for later pipes.
    """
    tp = dce.get_rpc_transport()
    smb_conn = tp.get_smb_connection()
    tid = getattr(tp, "_SMBTransport__tid", 0)
    handle = getattr(tp, "_SMBTransport__handle", 0)
    if smb_conn and tid and handle:
        with contextlib.suppress(Exception):
            smb_conn.closeFile(tid, handle)


def enumerate_services(
    smb: SMBConnection,
    host: str,
    filter_win32_only: bool = True,
) -> List[Dict[str, Any]]:
    """
    Enumerate all services on a remote host via SVCCTL RPC.

    Binds to \\pipe\\svcctl on the existing SMB connection, queries the
    Service Control Manager, and returns a list of service dicts. Only
    Win32 services are returned by default (kernel/filesystem drivers
    are filtered out).

    Args:
        smb: Authenticated SMBConnection instance
        host: Hostname for logging
        filter_win32_only: If True, skip kernel/filesystem drivers

    Returns:
        List of dicts with keys: name, display_name, account,
        binary_path, start_type, service_type, state
    """
    dce: Optional[Any] = None
    sc_handle: Optional[bytes] = None

    try:
        # Bind to SVCCTL
        rpc = transport.DCERPCTransportFactory(r"ncacn_np:445[\pipe\svcctl]")
        rpc.set_smb_connection(smb)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        log_debug(f"{host}: SVCCTL - connected to SCM (\\pipe\\svcctl)")

        # Open SCM with enumerate permission
        ans = scmr.hROpenSCManagerW(
            dce,
            lpMachineName="",
            dwDesiredAccess=scmr.SC_MANAGER_ENUMERATE_SERVICE,
        )
        sc_handle = ans["lpScHandle"]

        # Enumerate services — hREnumServicesStatusW handles the
        # ERROR_MORE_DATA / resume-handle loop internally in impacket
        resp = scmr.hREnumServicesStatusW(
            dce,
            sc_handle,
            dwServiceType=scmr.SERVICE_WIN32_OWN_PROCESS | scmr.SERVICE_WIN32_SHARE_PROCESS,
            dwServiceState=scmr.SERVICE_STATE_ALL,
        )

        services: List[Dict[str, Any]] = []
        cache = get_cache()
        cache_hits = 0
        builtin_skips = 0

        for svc in resp:
            svc_name = svc["lpServiceName"][:-1]  # strip null terminator
            display_name = svc["lpDisplayName"][:-1]
            state = svc["ServiceStatus"]["dwCurrentState"]
            svc_type = svc["ServiceStatus"]["dwServiceType"]

            # Filter to Win32 services only
            if filter_win32_only and not (svc_type & _WIN32_SERVICE_TYPES):
                continue

            # Skip known Windows built-in services (always LocalSystem/LocalService/NetworkService)
            if svc_name.lower() in BUILTIN_SERVICE_NAMES:
                builtin_skips += 1
                continue

            # Check cache before RPC round-trip
            cache_key = f"{host.upper()}:{svc_name.lower()}"
            cached = cache.get(_SVC_CACHE_CATEGORY, cache_key) if cache else None
            if cached:
                config = cached
                cache_hits += 1
            else:
                config = _query_service_config(dce, sc_handle, svc_name, host)
                if config is None:
                    continue
                if cache:
                    cache.set(_SVC_CACHE_CATEGORY, cache_key, config)

            services.append({
                "name": svc_name,
                "display_name": display_name,
                "account": config["account"],
                "binary_path": config["binary_path"],
                "start_type": config["start_type"],
                "service_type": svc_type,
                "state": state,
            })

        if builtin_skips:
            log_debug(f"{host}: SVCCTL - skipped {builtin_skips} known built-in services")
        if cache_hits:
            log_debug(f"{host}: SVCCTL - {cache_hits} service configs from cache")
        log_debug(f"{host}: SVCCTL - enumerated {len(services)} Win32 services")
        return services

    except DCERPCException as e:
        warn(f"{host}: SVCCTL RPC error: {e}")
        return []
    except Exception as e:
        warn(f"{host}: SVCCTL enumeration failed: {e}")
        return []
    finally:
        if sc_handle and dce:
            with contextlib.suppress(Exception):
                scmr.hRCloseServiceHandle(dce, sc_handle)
        if dce is not None:
            _close_dce_pipe(dce)


def _query_service_config(
    dce,
    sc_handle: bytes,
    svc_name: str,
    host: str,
) -> Optional[Dict[str, Any]]:
    """Query full service config (account, binary path, start type).

    Opens a service handle, queries config, closes the handle.
    Returns None if the service cannot be queried (access denied, etc).
    """
    svc_handle = None
    try:
        ans = scmr.hROpenServiceW(
            dce,
            sc_handle,
            svc_name + "\x00",
            scmr.SERVICE_QUERY_CONFIG,
        )
        svc_handle = ans["lpServiceHandle"]

        config = scmr.hRQueryServiceConfigW(dce, svc_handle)
        lp = config["lpServiceConfig"]

        account = (lp["lpServiceStartName"] or "")[:-1]  # strip null
        binary_path = (lp["lpBinaryPathName"] or "")[:-1]
        start_type = lp["dwStartType"]

        return {
            "account": account,
            "binary_path": binary_path,
            "start_type": start_type,
        }
    except DCERPCException:
        log_debug(f"{host}: SVCCTL - cannot query config for '{svc_name}' (access denied or gone)")
        return None
    except Exception as e:
        log_debug(f"{host}: SVCCTL - error querying '{svc_name}': {e}")
        return None
    finally:
        if svc_handle:
            with contextlib.suppress(Exception):
                scmr.hRCloseServiceHandle(dce, svc_handle)
