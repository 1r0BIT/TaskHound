# Small helpers used across the codebase.
#
# This module contains simple utilities for classifying RunAs values,
# normalizing target hostnames, and the ASCII banner used by the CLI.

from typing import List


def looks_like_domain_user(runas: str) -> bool:
    # Return True when `runas` appears to represent a domain account.
    #
    # The function returns False for well-known local/system principals
    # (including common German translations seen in German-language
    # Windows installations). It treats values with a backslash (NETBIOS\user)
    # or values containing a dot (user@domain-like or UPN) as domain-like.
    # It also recognizes domain SIDs (S-1-5-21-*-*-*-RID) as domain accounts.
    if not runas:
        return False

    val = runas.strip()

    # Check if this is a SID format
    if val.upper().startswith("S-1-"):
        # Exclude well-known local SIDs (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
        up = val.upper()
        if up.startswith("S-1-5-18") or up.startswith("S-1-5-19") or up.startswith("S-1-5-20"):
            return False

        # Domain SIDs have pattern S-1-5-21-domain-domain-domain-rid
        if up.startswith("S-1-5-21-"):
            return True

        # Other SIDs are likely not domain users
        return False

    # If username contains a backslash (DOMAIN\user), check for local/system principals
    if "\\" in val:
        domain, user = val.split("\\", 1)
        domain = domain.strip().lower()
        user = user.strip().lower()

        # Known local domains / authority names (English + some common misspellings/variants)
        local_domain_markers = ("nt authority", "nt_autority", "nt_autoritat", "nt_autorität", "localhost")
        if any(ld in domain for ld in local_domain_markers):
            return False

        # Known local users / service accounts (English + German variants)
        local_user_names = {
            "system",
            "netzwerkdienst",
            "networkservice",
            "localservice",
            "localsystem",
        }
        # quick membership and substring checks to catch slightly different forms
        if user in local_user_names or any(l in user for l in ("networkservice", "netzwerkdienst", "localservice", "system")):
            return False

        # Otherwise treat as domain-like if it has a backslash
        return True

    # If it looks like a UPN or contains a dot, treat as domain user
    if "." in val:
        return True

    return False


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


def normalize_targets(targets: List[str], domain: str) -> List[str]:
    # Normalize a list of targets: keep IPs, append domain for short hostnames.
    #
    # Empty lines are ignored. This mirrors the behavior expected by the CLI
    # where users may pass bare hostnames that need to be FQDN-ified.
    out = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if is_ipv4(t):
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
