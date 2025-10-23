# Remote registry helpers for Credential Guard detection
#
# This module provides a function to remotely check if Credential Guard is enabled on a Windows host
# via the SYSTEM\CurrentControlSet\Control\Lsa registry keys. Uses Impacket's RemoteOperations and
# RemoteRegistry classes. Returns True if Credential Guard is detected, False otherwise.

from impacket.dcerpc.v5 import rrp, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException


def check_credential_guard(smb_conn, host):
    # Returns True if Credential Guard is enabled, False otherwise.
    #
    # Checks HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags == 1
    # and/or HKLM\SYSTEM\CurrentControlSet\Control\Lsa\IsolatedUserMode == 1
    #
    # Returns True if either key is set to 1, False otherwise or on error.
    try:
        stringBinding = rf'ncacn_np:{host}[\pipe\winreg]'
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_smb_connection(smb_conn)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        # Open HKLM
        reg_handle = rrp.hOpenLocalMachine(dce)['phKey']
        # Open LSA key
        lsa_path = 'SYSTEM\\CurrentControlSet\\Control\\Lsa'
        ans = rrp.hBaseRegOpenKey(dce, reg_handle, lsa_path, samDesired=rrp.KEY_READ)
        lsa_handle = ans['phkResult']
        # Check LsaCfgFlags
        try:
            val = rrp.hBaseRegQueryValue(dce, lsa_handle, 'LsaCfgFlags')
            if int.from_bytes(val['lpData'], 'little') == 1:
                return True
        except DCERPCException:
            pass
        # Check IsolatedUserMode
        try:
            val = rrp.hBaseRegQueryValue(dce, lsa_handle, 'IsolatedUserMode')
            if int.from_bytes(val['lpData'], 'little') == 1:
                return True
        except DCERPCException:
            pass
        return False
    except Exception:
        return False
