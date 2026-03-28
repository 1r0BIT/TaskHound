# LSA secret extraction for credential recovery.
#
# Provides registry-only LSA extraction (no disk writes) using impacket's
# regsecrets module. Extracts service account passwords (_SC_* secrets)
# and DPAPI system keys in a single pass.

from .extractor import (
    GMSACredential,
    LSAExtractionResult,
    ServiceCredential,
    extract_lsa_secrets,
    extract_service_credentials,
)

__all__ = ["GMSACredential", "LSAExtractionResult", "ServiceCredential", "extract_lsa_secrets", "extract_service_credentials"]
