# DPAPI Blob Parser
#
# Parse DPAPI blob structure to extract metadata without decryption
# Based on: https://medium.com/@toneillcodes/decoding-dpapi-blobs-1ed9b4832cf6
#
# DPAPI Blob Structure:
# - Version (4 bytes)
# - Provider GUID (16 bytes)
# - MasterKey Version (4 bytes)
# - MasterKey GUID (16 bytes)
# - Flags (4 bytes)
# - Description Length (4 bytes)
# - Description (variable, UTF-16LE)
# - CipherAlgorithm (4 bytes)
# - CipherKeyLength (4 bytes)
# - Salt Length (4 bytes)
# - Salt (variable)
# - Strong Length (4 bytes) - HMAC length
# - Strong (variable) - HMAC of encrypted data
# - CryptAlgorithm (4 bytes)
# - CryptKeyLength (4 bytes)
# - Encrypted Data Length (4 bytes)
# - Encrypted Data (variable)
# - Sign Length (4 bytes)
# - Sign (variable) - HMAC signature

import struct
from typing import Dict, List, Optional

from ..utils.logging import debug, info, warn


class DPAPIBlobParser:
    """
    Parse DPAPI blob structure to extract metadata without decryption keys.
    
    We can extract valuable forensic information from DPAPI blobs including:
    - Master key GUID (identifies which master key was used)
    - Encryption algorithms used
    - Creation timestamps (from file metadata)
    - Data size and structure
    - Provider information
    """

    # DPAPI Algorithm identifiers
    CALG_ALGORITHMS = {
        0x0000: "None",
        0x6603: "3DES_112",
        0x6609: "3DES",
        0x660e: "AES_128",
        0x660f: "AES_192",
        0x6610: "AES_256",
        0x6602: "RC2",
        0x6801: "RC4",
        0x8003: "SHA1",
        0x8004: "SHA256",
        0x800c: "SHA384",
        0x800d: "SHA512",
    }

    def __init__(self):
        self.parsed_blobs = []

    def parse_blob(self, blob_data: bytes, blob_path: str = None) -> Optional[Dict]:
        """
        Parse a DPAPI credential blob and extract metadata.
        
        These are the credential blobs stored by Windows Scheduled Tasks.
        Format appears to be:
        - Version (4 bytes)
        - Reserved/Unknown (8 bytes)
        - Credential GUID as UTF-16LE string (variable, null-terminated)
        - Algorithm and encryption metadata
        - Encrypted credential data
        
        Args:
            blob_data: Raw DPAPI blob bytes
            blob_path: Optional path for context
            
        Returns:
            Dictionary with parsed metadata or None if parsing failed
        """
        try:
            if len(blob_data) < 16:
                warn(f"Blob too small: {len(blob_data)} bytes")
                return None

            offset = 0
            blob_info = {
                'blob_path': blob_path,
                'total_size': len(blob_data),
                'parsed_successfully': False
            }

            # Version (4 bytes) - should be 2 for credential blobs
            version = struct.unpack('<I', blob_data[offset:offset+4])[0]
            blob_info['version'] = version
            offset += 4

            # Reserved bytes (8 bytes)
            blob_info['reserved'] = blob_data[offset:offset+8].hex()
            offset += 8

            # The rest contains the GUID string in UTF-16LE
            # Try to find and decode the GUID
            try:
                # Look for GUID pattern in UTF-16LE
                # GUIDs are typically 36 chars: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                # In UTF-16LE that's 72 bytes + 2 bytes for null terminator
                remaining = blob_data[offset:]

                # Try to decode as much UTF-16LE as possible until we hit non-text
                max_guid_len = min(80, len(remaining))  # GUID + some buffer
                for test_len in range(max_guid_len, 0, -2):  # Must be even for UTF-16
                    try:
                        decoded = remaining[:test_len].decode('utf-16le', errors='strict')
                        # Check if it looks like a GUID
                        if '-' in decoded or any(c in '0123456789abcdefABCDEF' for c in decoded):
                            guid_str = decoded.rstrip('\x00')
                            blob_info['credential_guid'] = guid_str
                            offset += test_len
                            break
                    except Exception:
                        continue
            except Exception as e:
                debug(f"Could not decode GUID: {e}")
                blob_info['credential_guid'] = "Unable to decode"

            # Rest of the data contains encryption metadata and encrypted payload
            # Without full DPAPI blob structure documentation for credential blobs,
            # we can identify some patterns

            if offset < len(blob_data):
                # Look for algorithm identifiers (4-byte values)
                remaining_data = blob_data[offset:]
                blob_info['remaining_data_size'] = len(remaining_data)

                # Try to identify encryption algorithm markers
                # Common CALG values appear as 4-byte little-endian integers
                for i in range(0, min(len(remaining_data) - 4, 100), 4):
                    val = struct.unpack('<I', remaining_data[i:i+4])[0]
                    alg_name = self._algorithm_name(val)
                    if alg_name and "Unknown" not in alg_name:
                        if 'algorithms_found' not in blob_info:
                            blob_info['algorithms_found'] = []
                        blob_info['algorithms_found'].append({
                            'offset': offset + i,
                            'id': f"0x{val:04x}",
                            'name': alg_name
                        })

            blob_info['parsed_successfully'] = True
            blob_info['bytes_parsed'] = offset

            cred_guid = blob_info.get('credential_guid', 'Unknown')
            if len(cred_guid) > 50:
                cred_guid = cred_guid[:47] + "..."
            info(f"✓ Parsed credential blob: GUID={cred_guid}, Size={len(blob_data)} bytes")

            return blob_info

        except Exception as e:
            warn(f"Error parsing DPAPI blob: {e}")
            import traceback
            debug(traceback.format_exc())
            return None

    def parse_blob_file(self, file_path: str) -> Optional[Dict]:
        """
        Parse a DPAPI blob from a file.
        
        Args:
            file_path: Path to DPAPI blob file
            
        Returns:
            Dictionary with parsed metadata or None
        """
        try:
            with open(file_path, 'rb') as f:
                blob_data = f.read()

            return self.parse_blob(blob_data, file_path)

        except Exception as e:
            warn(f"Error reading blob file {file_path}: {e}")
            return None

    def _algorithm_name(self, alg_id: int) -> str:
        """Get algorithm name from ID."""
        return self.CALG_ALGORITHMS.get(alg_id, f"Unknown(0x{alg_id:04x})")

    def analyze_blob_collection(self, blob_files: List[str]) -> Dict:
        """
        Analyze a collection of DPAPI blobs to identify patterns.
        
        Args:
            blob_files: List of paths to DPAPI blob files
            
        Returns:
            Analysis summary with statistics and findings
        """
        results = {
            'total_blobs': len(blob_files),
            'successfully_parsed': 0,
            'failed_to_parse': 0,
            'credential_guids': set(),
            'cipher_algorithms': {},
            'hash_algorithms': {},
            'blob_details': []
        }

        for blob_file in blob_files:
            parsed = self.parse_blob_file(blob_file)

            if parsed and parsed.get('parsed_successfully'):
                results['successfully_parsed'] += 1
                results['blob_details'].append(parsed)

                # Track credential GUIDs
                cred_guid = parsed.get('credential_guid')
                if cred_guid:
                    results['credential_guids'].add(cred_guid)

                # Track cipher algorithms
                cipher_alg = parsed.get('cipher_algorithm', 'Unknown')
                results['cipher_algorithms'][cipher_alg] = results['cipher_algorithms'].get(cipher_alg, 0) + 1

                # Track hash algorithms
                hash_alg = parsed.get('hash_algorithm', 'Unknown')
                results['hash_algorithms'][hash_alg] = results['hash_algorithms'].get(hash_alg, 0) + 1
            else:
                results['failed_to_parse'] += 1

        # Convert set to list for JSON serialization
        results['credential_guids'] = list(results['credential_guids'])

        return results

    def print_blob_summary(self, blob_info: Dict) -> None:
        """
        Print a human-readable summary of a parsed blob.
        
        Args:
            blob_info: Parsed blob information dictionary
        """
        if not blob_info or not blob_info.get('parsed_successfully'):
            print("[!] Failed to parse blob")
            return

        print("\n" + "="*70)
        print("DPAPI BLOB ANALYSIS (Without Decryption)")
        print("="*70)

        if blob_info.get('blob_path'):
            print(f"File: {blob_info['blob_path']}")

        print(f"Total Size: {blob_info['total_size']} bytes")
        print(f"Version: {blob_info.get('version', 'Unknown')}")

        print("\n--- CREDENTIAL INFORMATION ---")
        cred_guid = blob_info.get('credential_guid', 'Unknown')
        print(f"Credential GUID: {cred_guid}")
        print("  → This identifies the specific credential protected by DPAPI")

        print("\n--- DATA STRUCTURE ---")
        print(f"Remaining Data: {blob_info.get('remaining_data_size', 0)} bytes after GUID")

        if blob_info.get('algorithms_found'):
            print("\n--- ALGORITHMS DETECTED ---")
            for alg in blob_info['algorithms_found']:
                print(f"  • {alg['name']} ({alg['id']}) at offset {alg['offset']}")

        if blob_info.get('description'):
            print(f"\nDescription: {blob_info['description']}")

        print("\n--- FORENSIC VALUE ---")
        print("  • GUID identifies which scheduled task credential this protects")
        print("  • Blob requires user/SYSTEM DPAPI master key to decrypt")
        print("  • Extract master keys from: C:\\Users\\[user]\\AppData\\Roaming\\Microsoft\\Protect\\[SID]\\")
        print("  • Or from: C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\ (SYSTEM)")

        print("="*70)

    def print_collection_summary(self, analysis: Dict) -> None:
        """
        Print a summary of analyzed blob collection.
        
        Args:
            analysis: Analysis results from analyze_blob_collection
        """
        print("\n" + "="*70)
        print("DPAPI BLOB COLLECTION ANALYSIS")
        print("="*70)

        print(f"Total Blobs Analyzed: {analysis['total_blobs']}")
        print(f"Successfully Parsed: {analysis['successfully_parsed']}")
        print(f"Failed to Parse: {analysis['failed_to_parse']}")

        print("\n--- CREDENTIAL GUID USAGE ---")
        print(f"Unique Credential GUIDs Found: {len(analysis['credential_guids'])}")
        for cred_guid in list(analysis['credential_guids'])[:10]:  # Show first 10
            count = sum(1 for b in analysis['blob_details'] if b.get('credential_guid') == cred_guid)
            print(f"  • {cred_guid[:50]}... ({count} blobs)")

        print("\n--- ENCRYPTION ALGORITHMS ---")
        for alg, count in analysis['cipher_algorithms'].items():
            print(f"  • {alg}: {count} blobs")

        print("\n--- HASH ALGORITHMS ---")
        for alg, count in analysis['hash_algorithms'].items():
            print(f"  • {alg}: {count} blobs")

        print("\n--- KEY FINDINGS ---")
        print("✓ Credential GUIDs identify specific protected credentials")
        print("✓ Encryption algorithms show Windows DPAPI protection strength")
        print("✓ These blobs require user/system master keys for decryption")
        print("✓ Extract blobs + master keys from C:\\Users\\[user]\\AppData\\Roaming\\Microsoft\\Protect for offline attack")

        print("="*70)
