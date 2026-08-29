# Remote registry helpers for Credential Guard detection
#
# This module provides a function to remotely check if Credential Guard is enabled on a Windows host
# via the SYSTEM\CurrentControlSet\Control\Lsa registry keys. Uses Impacket's scmr and rrp modules.
#
# Follows Impacket's RemoteOperations pattern from secretsdump.py and reg.py:
# - Connects to SCM via \pipe\svcctl
# - Checks RemoteRegistry service status
# - Starts service if stopped, enables if disabled
# - Performs registry check via \pipe\winreg
# - Restores service to original state (stops if was stopped, disables if was disabled)
#
# Returns:
#   True  - Credential Guard is detected (DPAPI extraction will fail)
#   False - Credential Guard is NOT detected (DPAPI extraction may work)
#   None  - Unable to check (insufficient permissions or other failure)

import contextlib
import time

from impacket.dcerpc.v5 import rrp, scmr, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException

from ..utils.logging import debug as log_debug


class RemoteRegistryOps:
    """
    Manages Remote Registry service lifecycle for registry operations.
    Follows Impacket's RemoteOperations pattern from secretsdump.py/reg.py.
    """

    SERVICE_NAME = "RemoteRegistry"
    WINREG_BINDING = r"ncacn_np:445[\pipe\winreg]"
    SVCCTL_BINDING = r"ncacn_np:445[\pipe\svcctl]"

    def __init__(self, smb_conn, host):
        self._smb_conn = smb_conn
        self._host = host

        # SCM/service state
        self._scmr = None
        self._sc_manager_handle = None
        self._service_handle = None
        self._should_stop = False  # True if we started service that was stopped
        self._disabled = False  # True if we enabled service that was disabled

        # WinReg state
        self._rrp = None

    def _connect_svc_ctl(self):
        """Connect to the Service Control Manager via \\pipe\\svcctl"""
        rpc = transport.DCERPCTransportFactory(self.SVCCTL_BINDING)
        rpc.set_smb_connection(self._smb_conn)
        self._scmr = rpc.get_dce_rpc()
        self._scmr.connect()
        self._scmr.bind(scmr.MSRPC_UUID_SCMR)
        log_debug(f"{self._host}: CredGuard - connected to SCM (\\pipe\\svcctl)")

    def _connect_win_reg(self):
        """Connect to the Remote Registry via \\pipe\\winreg"""
        rpc = transport.DCERPCTransportFactory(self.WINREG_BINDING)
        rpc.set_smb_connection(self._smb_conn)
        self._rrp = rpc.get_dce_rpc()
        self._rrp.connect()
        self._rrp.bind(rrp.MSRPC_UUID_RRP)
        log_debug(f"{self._host}: CredGuard - connected to Remote Registry (\\pipe\\winreg)")

    def _check_service_status(self):
        """
        Check RemoteRegistry service status, enable/start if needed.
        Tracks original state to restore later.
        """
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self._scmr)
        self._sc_manager_handle = ans["lpScHandle"]

        # Open RemoteRegistry service
        ans = scmr.hROpenServiceW(
            self._scmr,
            self._sc_manager_handle,
            self.SERVICE_NAME + "\x00",
            scmr.SERVICE_START | scmr.SERVICE_STOP | scmr.SERVICE_CHANGE_CONFIG | scmr.SERVICE_QUERY_CONFIG | scmr.SERVICE_QUERY_STATUS,
        )
        self._service_handle = ans["lpServiceHandle"]

        # Check current status
        ans = scmr.hRQueryServiceStatus(self._scmr, self._service_handle)
        state = ans["lpServiceStatus"]["dwCurrentState"]

        if state == scmr.SERVICE_STOPPED:
            log_debug(f"{self._host}: CredGuard - RemoteRegistry service is stopped")
            self._should_stop = True

            # Check if disabled
            ans = scmr.hRQueryServiceConfigW(self._scmr, self._service_handle)
            if ans["lpServiceConfig"]["dwStartType"] == 0x4:  # SERVICE_DISABLED
                log_debug(f"{self._host}: CredGuard - RemoteRegistry is disabled, enabling it")
                self._disabled = True
                scmr.hRChangeServiceConfigW(self._scmr, self._service_handle, dwStartType=0x3)  # SERVICE_DEMAND_START

            log_debug(f"{self._host}: CredGuard - starting RemoteRegistry service")
            scmr.hRStartServiceW(self._scmr, self._service_handle)
            time.sleep(1)  # Give service time to start

        elif state == scmr.SERVICE_RUNNING:
            log_debug(f"{self._host}: CredGuard - RemoteRegistry service already running")
            self._should_stop = False
        else:
            raise Exception(f"Unknown RemoteRegistry service state: 0x{state:x}")

    def _restore(self):
        """Restore RemoteRegistry service to original state"""
        try:
            if self._should_stop and self._service_handle:
                log_debug(f"{self._host}: CredGuard - stopping RemoteRegistry service")
                scmr.hRControlService(self._scmr, self._service_handle, scmr.SERVICE_CONTROL_STOP)

            if self._disabled and self._service_handle:
                log_debug(f"{self._host}: CredGuard - disabling RemoteRegistry service")
                scmr.hRChangeServiceConfigW(self._scmr, self._service_handle, dwStartType=0x4)  # SERVICE_DISABLED
        except Exception as e:
            log_debug(f"{self._host}: CredGuard - error restoring service state: {e}")

    def enable_registry(self):
        """Enable remote registry access (start service if needed)"""
        self._connect_svc_ctl()
        self._check_service_status()
        self._connect_win_reg()

    def get_rrp(self):
        """Get the RRP DCE connection for registry operations"""
        return self._rrp

    @staticmethod
    def _close_dce_pipe(dce) -> None:
        """Close the named-pipe handle inside a DCE/RPC transport.

        Impacket's ``SMBTransport.disconnect()`` calls ``disconnectTree()``
        **without** first calling ``closeFile()``, and then disconnects the
        IPC$ tree.  When two transports share the same SMB connection
        (svcctl + winreg here), this corrupts state for later pipe users.

        We close only the file handle and leave the IPC$ tree intact so
        that subsequent named-pipe opens (e.g. SAMR) work correctly.
        """
        tp = dce.get_rpc_transport()
        smb_conn = tp.get_smb_connection()
        tid = getattr(tp, "_SMBTransport__tid", 0)
        handle = getattr(tp, "_SMBTransport__handle", 0)
        if smb_conn and tid and handle:
            with contextlib.suppress(Exception):
                smb_conn.closeFile(tid, handle)

    def finish(self):
        """Cleanup: restore service state, close pipe handles."""
        self._restore()
        if self._rrp is not None:
            with contextlib.suppress(Exception):
                self._close_dce_pipe(self._rrp)
        if self._scmr is not None:
            with contextlib.suppress(Exception):
                self._close_dce_pipe(self._scmr)


def check_credential_guard(smb_conn, host) -> bool | None:
    """
    Check if Credential Guard is enabled on a remote Windows host.

    Checks HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags
    and/or HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\IsolatedUserMode == 1

    LsaCfgFlags values:
        0 = Credential Guard disabled
        1 = Credential Guard enabled with UEFI lock
        2 = Credential Guard enabled without lock

    Automatically starts the RemoteRegistry service if stopped/disabled,
    and restores it to the original state afterward.

    Returns:
        True: Credential Guard is enabled
        False: Credential Guard is NOT enabled
        None: Unable to check (insufficient permissions or failure)
    """
    remote_ops = RemoteRegistryOps(smb_conn, host)

    try:
        remote_ops.enable_registry()
        dce = remote_ops.get_rrp()

        # Open HKLM
        reg_handle = rrp.hOpenLocalMachine(dce)["phKey"]
        log_debug(f"{host}: CredGuard check - opened HKLM")

        # Open LSA key
        lsa_path = "SYSTEM\\CurrentControlSet\\Control\\Lsa"
        ans = rrp.hBaseRegOpenKey(dce, reg_handle, lsa_path, samDesired=rrp.KEY_READ)
        lsa_handle = ans["phkResult"]
        log_debug(f"{host}: CredGuard check - opened {lsa_path}")

        # Check LsaCfgFlags (values: 0=disabled, 1=UEFI lock, 2=without lock)
        lsa_cfg_flags = None
        try:
            # hBaseRegQueryValue returns tuple (dataType, data)
            _, lsa_cfg_flags = rrp.hBaseRegQueryValue(dce, lsa_handle, "LsaCfgFlags")
            log_debug(f"{host}: CredGuard check - LsaCfgFlags = {lsa_cfg_flags}")
            if lsa_cfg_flags in (1, 2):
                log_debug(f"{host}: CredGuard check - DETECTED via LsaCfgFlags={lsa_cfg_flags}")
                return True
        except DCERPCException:
            log_debug(f"{host}: CredGuard check - LsaCfgFlags not present")

        # Check IsolatedUserMode
        isolated_user_mode = None
        try:
            # hBaseRegQueryValue returns tuple (dataType, data)
            _, isolated_user_mode = rrp.hBaseRegQueryValue(dce, lsa_handle, "IsolatedUserMode")
            log_debug(f"{host}: CredGuard check - IsolatedUserMode = {isolated_user_mode}")
            if isolated_user_mode == 1:
                log_debug(f"{host}: CredGuard check - DETECTED via IsolatedUserMode=1")
                return True
        except DCERPCException:
            log_debug(f"{host}: CredGuard check - IsolatedUserMode not present")

        log_debug(f"{host}: CredGuard check - NOT detected (LsaCfgFlags={lsa_cfg_flags}, IsolatedUserMode={isolated_user_mode})")
        return False

    except Exception as e:
        log_debug(f"{host}: CredGuard check failed: {type(e).__name__}: {e}")
        return None

    finally:
        remote_ops.finish()
