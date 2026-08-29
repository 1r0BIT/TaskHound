# Small helpers used across the codebase.
#
# This module contains simple utilities for classifying RunAs values,
# normalizing target hostnames, and the ASCII banner used by the CLI.

import ipaddress
import re
import uuid


def is_ipv4(host: str) -> bool:
    # Fast, permissive IPv4 string check (no regex).
    #
    # Accepts dotted-quad notation and ensures each octet is in 0-255.
    parts = host.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def parse_ntlm_hashes(hashes: str | None) -> tuple[str, str]:
    """
    Parse NTLM hashes from string format.

    Args:
        hashes: Hash string in "LM:NT" or "NT" format, or None/empty

    Returns:
        Tuple of (lmhash, nthash) - empty strings if not provided
    """
    if not hashes:
        return "", ""

    if ":" in hashes:
        lmhash, nthash = hashes.split(":", 1)
        return lmhash, nthash
    else:
        return "", hashes


# Pre-compiled regex for GUID validation
_GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def is_guid(value: str) -> bool:
    """
    Check if a string is a valid GUID format.

    Args:
        value: String to check (e.g., "12345678-1234-1234-1234-123456789012")

    Returns:
        True if the string matches GUID format, False otherwise
    """
    return bool(_GUID_PATTERN.match(value))


def expand_cidr(cidr: str) -> list[str]:
    """Expand a CIDR notation to a list of IP addresses.

    Args:
        cidr: CIDR notation string (e.g., '192.168.1.0/24')

    Returns:
        List of IP address strings (excludes network and broadcast for /31+)

    Raises:
        ValueError: If the CIDR notation is invalid
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # For /31 and /32, return all addresses (point-to-point or single host)
        # For larger networks, exclude network and broadcast addresses
        if network.prefixlen >= 31:
            return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation '{cidr}': {e}") from e


def is_cidr(target: str) -> bool:
    """Check if a string is CIDR notation (e.g., '192.168.1.0/24')."""
    if "/" not in target:
        return False
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def normalize_targets(targets: list[str], domain: str) -> list[str]:
    """Normalize a list of targets: expand CIDRs, keep IPs, append domain for short hostnames.

    Args:
        targets: List of target strings (IPs, hostnames, FQDNs, or CIDR notation)
        domain: Domain to append to short hostnames

    Returns:
        Normalized list of targets with CIDRs expanded to individual IPs

    Empty lines are ignored. This mirrors the behavior expected by the CLI
    where users may pass bare hostnames that need to be FQDN-ified.
    """
    out = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        # Check for CIDR notation first
        if is_cidr(t):
            try:
                expanded = expand_cidr(t)
                out.extend(expanded)
            except ValueError:
                # Invalid CIDR, treat as hostname
                out.append(t)
        elif is_ipv4(t):
            out.append(t)
        else:
            # append domain if it's a short host (no dot)
            if "." not in t:
                out.append(f"{t}.{domain}")
            else:
                out.append(t)
    return out


BANNER = r"""
TTTTT  AAA   SSS  K   K H   H  OOO  U   U N   N DDDD
  T   A   A S     K  K  H   H O   O U   U NN  N D   D
  T   AAAAA  SSS  KKK   HHHHH O   O U   U N N N D   D
  T   A   A     S K  K  H   H O   O U   U N  NN D   D
  T   A   A SSSS  K   K H   H  OOO   UUU  N   N DDDD

                     by 0xr0BIT
"""


def sanitize_json_string(json_str: str) -> str:
    """
    Sanitize JSON string to handle unescaped backslashes that break JSON parsing.

    This commonly occurs in Active Directory Distinguished Names like:
    "CN=LASTNAME\\, FIRSTNAME,OU=..."

    Args:
        json_str: Raw JSON string that may contain unescaped backslashes

    Returns:
        Sanitized JSON string with properly escaped backslashes
    """
    # Replace single backslashes with double backslashes, but be careful not to
    # double-escape already escaped sequences

    # First, temporarily replace already properly escaped sequences
    placeholder = str(uuid.uuid4())

    # Protect already escaped sequences (\\, \", \n, \r, \t, \/, \b, \f, \u)
    protected = json_str.replace("\\\\", placeholder + "BACKSLASH")
    protected = protected.replace('\\"', placeholder + "QUOTE")
    protected = protected.replace("\\n", placeholder + "NEWLINE")
    protected = protected.replace("\\r", placeholder + "RETURN")
    protected = protected.replace("\\t", placeholder + "TAB")
    protected = protected.replace("\\/", placeholder + "SLASH")
    protected = protected.replace("\\b", placeholder + "BACKSPACE")
    protected = protected.replace("\\f", placeholder + "FORMFEED")

    # Protect unicode escapes (\uXXXX)
    unicode_pattern = r"\\u[0-9a-fA-F]{4}"
    unicode_matches = re.findall(unicode_pattern, protected)
    for i, match in enumerate(unicode_matches):
        protected = protected.replace(match, f"{placeholder}UNICODE{i}")

    # Now escape any remaining single backslashes
    protected = protected.replace("\\", "\\\\")

    # Restore the protected sequences
    protected = protected.replace(placeholder + "BACKSLASH", "\\\\")
    protected = protected.replace(placeholder + "QUOTE", '\\"')
    protected = protected.replace(placeholder + "NEWLINE", "\\n")
    protected = protected.replace(placeholder + "RETURN", "\\r")
    protected = protected.replace(placeholder + "TAB", "\\t")
    protected = protected.replace(placeholder + "SLASH", "\\/")
    protected = protected.replace(placeholder + "BACKSPACE", "\\b")
    protected = protected.replace(placeholder + "FORMFEED", "\\f")

    # Restore unicode escapes
    for i, match in enumerate(unicode_matches):
        protected = protected.replace(f"{placeholder}UNICODE{i}", match)

    return protected
