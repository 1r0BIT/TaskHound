# LSA secret extraction for Windows service credential recovery.
#
# This package provides targeted extraction of _SC_<ServiceName> LSA
# secrets, which contain plaintext passwords for services running as
# domain accounts.

from .extractor import extract_service_credentials

__all__ = ["extract_service_credentials"]
