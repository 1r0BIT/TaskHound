# LAPS (Local Administrator Password Solution) support for TaskHound
#
# This package handles querying LAPS passwords from Active Directory
# and provides credential lookup for SMB authentication.
#
# Supports:
#   - Windows LAPS (msLAPS-Password) - JSON format plaintext
#   - Windows LAPS (msLAPS-EncryptedPassword) - Encrypted via DPAPI-NG/MS-GKDI
#   - Legacy LAPS (ms-Mcs-AdmPwd) - plaintext
#   - Persistent caching via SQLite (respects LAPS expiration times)
#
# Author: TaskHound Contributors

# Exceptions
# Re-export date parsing utilities for backward compatibility
from ..utils.date_parser import parse_ad_timestamp

# Decryption context
from .decryption import (
    LAPSDecryptionContext,
    decrypt_laps_password,
)
from .exceptions import (
    LAPS_ERRORS,
    LAPSConnectionError,
    LAPSEmptyCacheError,
    LAPSError,
    LAPSParseError,
)

# Helper functions
from .helpers import (
    get_laps_credential_for_host,
    print_laps_summary,
)

# Data classes
from .models import (
    LAPS_CACHE_CATEGORY,
    LAPSCache,
    LAPSCredential,
    LAPSFailure,
)

# Parsing functions
from .parsing import (
    parse_filetime,
    parse_mslaps_password,
)

# Query functions
from .query import (
    get_laps_passwords,
    query_laps_passwords,
)

__all__ = [
    # Exceptions
    "LAPSError",
    "LAPSConnectionError",
    "LAPSEmptyCacheError",
    "LAPSParseError",
    "LAPS_ERRORS",
    # Data classes
    "LAPSCredential",
    "LAPSCache",
    "LAPSFailure",
    "LAPS_CACHE_CATEGORY",
    # Decryption
    "LAPSDecryptionContext",
    "decrypt_laps_password",
    # Parsing
    "parse_mslaps_password",
    "parse_filetime",
    "parse_ad_timestamp",  # Re-exported for backward compat
    # Query
    "get_laps_passwords",
    "query_laps_passwords",
    # Helpers
    "get_laps_credential_for_host",
    "print_laps_summary",
]
