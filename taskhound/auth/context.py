# Authentication context dataclass.
#
# This module provides a centralized AuthContext dataclass that bundles
# all authentication-related parameters. This eliminates the need to pass
# 8+ credential parameters individually through function calls.
#
# Usage:
#     auth = AuthContext(
#         username="admin",
#         password="secret",
#         domain="CORP",
#         dc_ip="192.168.1.1",
#     )
#     # Pass auth context instead of individual params
#     result = process_target(target, auth=auth, ...)

from dataclasses import dataclass


@dataclass
class AuthContext:
    """
    Bundles all authentication-related parameters for TaskHound operations.

    This dataclass consolidates credential parameters that are frequently
    passed together through the codebase, improving code readability and
    reducing parameter list complexity.

    Attributes:
        username: Primary username for authentication
        password: Primary password (mutually exclusive with hashes for auth)
        domain: Domain name for authentication
        hashes: NTLM hashes in LMHASH:NTHASH format (alternative to password)
        kerberos: Use Kerberos authentication instead of NTLM
        dc_ip: Domain controller IP for DNS/LDAP queries
        timeout: Connection timeout in seconds

        # LDAP-specific credentials (for SID resolution when different from main auth)
        ldap_domain: Alternative domain for LDAP queries
        ldap_user: Alternative username for LDAP queries
        ldap_password: Alternative password for LDAP queries
        ldap_hashes: Alternative hashes for LDAP queries
    """

    # Primary authentication
    username: str = ""
    password: str | None = None
    domain: str = ""
    hashes: str | None = None
    aes_key: str | None = None  # AES key for Kerberos (128-bit or 256-bit)
    kerberos: bool = False
    dc_ip: str | None = None
    timeout: int = 60
    dns_tcp: bool = False  # Force DNS queries over TCP (for SOCKS proxies)
    nameserver: str | None = None  # DNS nameserver (defaults to dc_ip or system DNS)

    # LDAP-specific credentials (optional override)
    ldap_domain: str | None = None
    ldap_user: str | None = None
    ldap_password: str | None = None
    ldap_hashes: str | None = None

    # Global Catalog server (optional, auto-discovers if not set)
    gc_server: str | None = None

    @property
    def has_credentials(self) -> bool:
        """Check if valid credentials are configured."""
        return bool(self.username and (self.password or self.hashes or self.aes_key or self.kerberos))

    @property
    def ldap_effective_domain(self) -> str:
        """Get the effective domain for LDAP queries."""
        return self.ldap_domain or self.domain

    @property
    def ldap_effective_user(self) -> str:
        """Get the effective username for LDAP queries."""
        return self.ldap_user or self.username

    @property
    def ldap_effective_password(self) -> str | None:
        """Get the effective password for LDAP queries."""
        return self.ldap_password or self.password

    @property
    def ldap_effective_hashes(self) -> str | None:
        """Get the effective hashes for LDAP queries."""
        return self.ldap_hashes or self.hashes

    def get_lm_hash(self) -> str:
        """Extract LM hash from hashes string."""
        if not self.hashes:
            return ""
        parts = self.hashes.split(":")
        return parts[0] if len(parts) >= 1 else ""

    def get_nt_hash(self) -> str:
        """Extract NT hash from hashes string."""
        if not self.hashes:
            return ""
        parts = self.hashes.split(":")
        return parts[1] if len(parts) >= 2 else parts[0] if parts else ""

    def __repr__(self) -> str:
        """Safe repr that doesn't expose credentials."""
        return (
            f"AuthContext(username={self.username!r}, domain={self.domain!r}, "
            f"kerberos={self.kerberos}, dc_ip={self.dc_ip!r}, "
            f"has_password={self.password is not None}, "
            f"has_hashes={self.hashes is not None}, "
            f"has_aes_key={self.aes_key is not None})"
        )


def effective_ldap_creds(
    domain: str | None,
    username: str | None,
    password: str | None,
    hashes: str | None,
    ldap_domain: str | None,
    ldap_user: str | None,
    ldap_password: str | None,
    ldap_hashes: str | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    """Return effective LDAP credentials (dedicated overrides falling back to main auth)."""
    return (ldap_domain or domain, ldap_user or username, ldap_password or password, ldap_hashes or hashes)
