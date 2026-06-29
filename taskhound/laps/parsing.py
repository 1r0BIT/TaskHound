# LAPS Password Parsing
import json
import re

from ..utils.date_parser import parse_filetime_hex
from .exceptions import LAPSParseError

# =============================================================================
# Windows LAPS JSON Parsing
# =============================================================================


def parse_mslaps_password(json_data: str, default_username: str | None = None) -> tuple[str, str, bool]:
    """
    Parse Windows LAPS msLAPS-Password JSON attribute.

    The attribute contains JSON like:
    {
        "n": "Administrator",     # Account name
        "t": "1d9a2b3c...",       # Timestamp (hex, Windows FILETIME)
        "p": "MyP@ssw0rd123"      # Password (plaintext or encrypted blob)
    }

    Args:
        json_data: Raw JSON string from msLAPS-Password attribute
        default_username: Fallback username if not in JSON

    Returns:
        Tuple of (password, username, is_encrypted)

    Raises:
        LAPSParseError: If JSON parsing fails
    """
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        raise LAPSParseError(f"Invalid msLAPS-Password JSON: {e}") from e

    # Extract password
    password = data.get("p", "")
    if not password:
        raise LAPSParseError("msLAPS-Password JSON missing 'p' (password) field")

    # Extract username (Windows LAPS stores the managed account name)
    username = data.get("n", default_username or "Administrator")

    # Check if encrypted
    # Encrypted passwords are base64-encoded blobs, plaintext are readable strings
    # Heuristic: if it looks like base64 and is long, it's probably encrypted
    is_encrypted = len(password) > 50 and bool(re.match(r"^[A-Za-z0-9+/]+=*$", password))

    return password, username, is_encrypted


# Alias for backward compatibility - parse_filetime_hex imported from utils.date_parser
parse_filetime = parse_filetime_hex
