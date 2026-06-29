# LAPS LDAP Query Functions
import contextlib

from impacket.ldap import ldapasn1 as ldapasn1_impacket

from ..utils.date_parser import parse_ad_timestamp
from ..utils.ldap import (
    LDAPConnectionError as LAPSConnectionError_Base,
)
from ..utils.ldap import (
    get_ldap_connection,
)
from ..utils.logging import debug, good, info, status, warn
from .decryption import LAPSDecryptionContext
from .exceptions import LAPSConnectionError, LAPSEmptyCacheError, LAPSParseError
from .models import LAPSCache, LAPSCredential
from .parsing import parse_mslaps_password

# =============================================================================
# Main Query Functions
# =============================================================================


def get_laps_passwords(
    dc_ip: str,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    laps_user_override: str | None = None,
    dc_host: str | None = None,
    use_cache: bool = True,
) -> LAPSCache:
    """
    Get LAPS passwords, checking persistent cache first.

    This is the recommended entry point for LAPS queries. It will:
    1. Check the persistent SQLite cache for valid (non-expired) credentials
    2. If cache has valid credentials, return them without querying AD
    3. If cache is empty/expired, query AD
    4. Save new credentials to cache for future use

    Use --clear-cache to force a refresh from AD.

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (FQDN format)
        username: Username for LDAP authentication
        password: Password for authentication
        hashes: NTLM hashes (alternative to password)
        kerberos: Use Kerberos authentication
        laps_user_override: Override username for all LAPS credentials
        dc_host: DC hostname for Kerberos SPN (optional, auto-resolved if not provided)
        use_cache: Whether to check persistent cache first (default: True)

    Returns:
        LAPSCache populated with discovered credentials

    Raises:
        LAPSConnectionError: If LDAP connection fails
        LAPSEmptyCacheError: If no LAPS passwords found
    """
    # Try loading from persistent cache first
    if use_cache:
        cached = LAPSCache.load_from_persistent_cache(domain)
        if cached and len(cached) > 0:
            stats = cached.get_statistics()
            status(f"[LAPS] {stats['total']} credentials from cache (Windows: {stats['mslaps']}, Legacy: {stats['legacy']})")
            return cached
        else:
            debug("LAPS: No valid cached credentials found, querying AD...")

    # Query AD for fresh credentials
    return query_laps_passwords(
        dc_ip=dc_ip,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
        kerberos=kerberos,
        laps_user_override=laps_user_override,
        dc_host=dc_host,
        save_to_cache=use_cache,
    )


def query_laps_passwords(
    dc_ip: str,
    domain: str,
    username: str,
    password: str | None = None,
    hashes: str | None = None,
    kerberos: bool = False,
    laps_user_override: str | None = None,
    dc_host: str | None = None,
    save_to_cache: bool = True,
    decrypt_encrypted: bool = True,
) -> LAPSCache:
    """
    Query all LAPS passwords from Active Directory.

    Queries Windows LAPS (msLAPS-Password, msLAPS-EncryptedPassword) and
    Legacy LAPS (ms-Mcs-AdmPwd) attributes from all computer objects.

    Args:
        dc_ip: Domain controller IP address
        domain: Domain name (FQDN format)
        username: Username for LDAP authentication
        password: Password for authentication
        hashes: NTLM hashes (alternative to password)
        kerberos: Use Kerberos authentication
        laps_user_override: Override username for all LAPS credentials
        dc_host: DC hostname for Kerberos SPN (optional, auto-resolved if not provided)
        save_to_cache: Whether to save results to persistent cache (default: True)
        decrypt_encrypted: Whether to decrypt msLAPS-EncryptedPassword (default: True)

    Returns:
        LAPSCache populated with discovered credentials

    Raises:
        LAPSConnectionError: If LDAP connection fails
        LAPSEmptyCacheError: If no LAPS passwords found
    """
    cache = LAPSCache(domain=domain)

    info("LAPS: Connecting to domain controller via LDAP...")
    debug(f"LAPS: DC={dc_ip}, Domain={domain}, User={username}")

    try:
        ldap_conn = get_ldap_connection(
            dc_ip=dc_ip,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
            dc_host=dc_host,
        )
    except LAPSConnectionError_Base as e:
        # Re-raise with LAPS-specific exception for API consistency
        raise LAPSConnectionError(str(e)) from e
    except Exception as e:
        raise LAPSConnectionError(f"Unexpected LDAP error: {e}") from e

    good("LAPS: LDAP connection established")
    info("LAPS: Querying computer objects for LAPS attributes...")

    # Build base DN
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    # LDAP filter: computers with any LAPS attribute populated
    # Include msLAPS-EncryptedPassword for Windows LAPS encrypted passwords
    ldap_filter = "(&(objectClass=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)))"

    # Attributes to retrieve
    attributes = [
        "sAMAccountName",  # Computer name with $ (e.g., "WS01$")
        "dNSHostName",  # FQDN (e.g., "WS01.domain.local")
        "ms-Mcs-AdmPwd",  # Legacy LAPS password
        "ms-Mcs-AdmPwdExpirationTime",  # Legacy LAPS expiration
        "msLAPS-Password",  # Windows LAPS (JSON, plaintext)
        "msLAPS-EncryptedPassword",  # Windows LAPS (DPAPI-NG encrypted)
        "msLAPS-PasswordExpirationTime",  # Windows LAPS expiration
    ]

    # Create decryption context if we need to decrypt encrypted passwords
    decrypt_ctx = None
    if decrypt_encrypted:
        decrypt_ctx = LAPSDecryptionContext.from_credentials(
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            kerberos=kerberos,
            kdc_host=dc_host,
            dns_server=dc_ip,
        )

    try:
        # Perform paged search to bypass server-side MaxPageSize limit (default 1000)
        paged_controls = [ldapasn1_impacket.SimplePagedResultsControl(size=500)]
        search_result = ldap_conn.search(
            searchBase=base_dn,
            searchFilter=ldap_filter,
            attributes=attributes,
            sizeLimit=0,
            searchControls=paged_controls,
        )

        # Process results
        decrypted_count = 0
        for entry in search_result:
            # Skip search references
            if not isinstance(entry, ldapasn1_impacket.SearchResultEntry):
                continue

            try:
                cred = _parse_ldap_entry(entry, laps_user_override, decrypt_ctx)
                if cred:
                    cache.add(cred)
                    debug(f"LAPS: Found {cred.laps_type} password for {cred.computer_name}")
                    # Count successfully decrypted Windows LAPS (encrypted type but now decrypted)
                    if cred.laps_type == "mslaps-encrypted" and not cred.encrypted:
                        decrypted_count += 1
            except Exception as e:
                debug(f"LAPS: Failed to parse entry: {e}")
                continue

    except Exception as e:
        warn(f"LAPS: LDAP search failed: {e}")
        raise LAPSConnectionError(f"LDAP search failed: {e}") from e
    finally:
        # Close connection
        with contextlib.suppress(Exception):
            ldap_conn.close()

    # Validate we found something
    if len(cache) == 0:
        raise LAPSEmptyCacheError("No LAPS passwords found in Active Directory")

    # Log statistics
    stats = cache.get_statistics()
    status(f"[LAPS] {stats['total']} credentials from LDAP (Windows: {stats['mslaps']}, Legacy: {stats['legacy']})")
    good(f"LAPS: Found {stats['total']} computers with LAPS passwords", verbose_only=True)
    if stats["mslaps"] > 0:
        info(f"LAPS:   - Windows LAPS (plaintext): {stats['mslaps']}")
    if decrypted_count > 0:
        info(f"LAPS:   - Windows LAPS (decrypted): {decrypted_count}")
    if stats["legacy"] > 0:
        info(f"LAPS:   - Legacy LAPS: {stats['legacy']}")
    if stats["encrypted"] > 0:
        warn(f"LAPS:   - Encrypted (failed): {stats['encrypted']}", verbose_only=True)

    return cache


# =============================================================================
# LDAP Entry Parsing
# =============================================================================


def _parse_ldap_entry(
    entry: ldapasn1_impacket.SearchResultEntry,
    laps_user_override: str | None,
    decrypt_ctx: LAPSDecryptionContext | None = None,
) -> LAPSCredential | None:
    """
    Parse a single LDAP search result entry into a LAPSCredential.

    Args:
        entry: LDAP search result entry
        laps_user_override: Override username if specified
        decrypt_ctx: Decryption context for encrypted LAPS passwords

    Returns:
        LAPSCredential or None if parsing fails
    """
    from .decryption import decrypt_laps_password
    from .exceptions import LAPSError

    # Extract attributes from entry
    attrs = {}
    raw_attrs = {}  # Keep raw bytes for binary attributes
    for attr in entry["attributes"]:
        attr_type = str(attr["type"])
        values = attr["vals"]
        if values:
            # Get first value (LAPS attributes are single-valued)
            attrs[attr_type.lower()] = str(values[0])
            # Also keep raw bytes for binary attributes
            raw_attrs[attr_type.lower()] = bytes(values[0])

    # Get computer name (required)
    computer_name = attrs.get("samaccountname")
    if not computer_name:
        return None

    dns_hostname = attrs.get("dnshostname")

    # Parse expiration (shared by all LAPS types)
    expiration = None
    exp_time = attrs.get("mslaps-passwordexpirationtime")
    if exp_time:
        with contextlib.suppress(ValueError, TypeError):
            expiration = parse_ad_timestamp(int(exp_time))

    # Try Windows LAPS plaintext first (msLAPS-Password)
    mslaps_password = attrs.get("mslaps-password")
    if mslaps_password:
        try:
            password, username, is_encrypted = parse_mslaps_password(
                mslaps_password, default_username=laps_user_override
            )

            return LAPSCredential(
                password=password if not is_encrypted else "",
                username=laps_user_override or username,
                laps_type="mslaps",
                computer_name=computer_name,
                dns_hostname=dns_hostname,
                expiration=expiration,
                encrypted=is_encrypted,
            )
        except LAPSParseError as e:
            debug(f"LAPS: Failed to parse msLAPS-Password for {computer_name}: {e}")

    # Try Windows LAPS encrypted (msLAPS-EncryptedPassword)
    mslaps_encrypted = raw_attrs.get("mslaps-encryptedpassword")
    if mslaps_encrypted and len(mslaps_encrypted) > 50:
        if decrypt_ctx:
            try:
                info(f"LAPS: Decrypting password for {computer_name}...")
                password, username = decrypt_laps_password(mslaps_encrypted, decrypt_ctx)
                good(f"LAPS: Successfully decrypted password for {computer_name}")

                return LAPSCredential(
                    password=password,
                    username=laps_user_override or username,
                    laps_type="mslaps-encrypted",
                    computer_name=computer_name,
                    dns_hostname=dns_hostname,
                    expiration=expiration,
                    encrypted=False,  # No longer encrypted after decryption
                )
            except LAPSError as e:
                warn(f"LAPS: Failed to decrypt password for {computer_name}: {e}")
                # Return as encrypted credential (will be counted as failed)
                return LAPSCredential(
                    password="",
                    username=laps_user_override or "Administrator",
                    laps_type="mslaps-encrypted",
                    computer_name=computer_name,
                    dns_hostname=dns_hostname,
                    expiration=expiration,
                    encrypted=True,
                )
        else:
            # No decryption context - mark as encrypted
            debug(f"LAPS: Found encrypted password for {computer_name} but decryption disabled")
            return LAPSCredential(
                password="",
                username=laps_user_override or "Administrator",
                laps_type="mslaps-encrypted",
                computer_name=computer_name,
                dns_hostname=dns_hostname,
                expiration=expiration,
                encrypted=True,
            )

    # Fall back to Legacy LAPS
    legacy_password = attrs.get("ms-mcs-admpwd")
    if legacy_password:
        # Parse legacy expiration if available
        legacy_expiration = None
        exp_time = attrs.get("ms-mcs-admpwdexpirationtime")
        if exp_time:
            with contextlib.suppress(ValueError, TypeError):
                legacy_expiration = parse_ad_timestamp(int(exp_time))

        return LAPSCredential(
            password=legacy_password,
            username=laps_user_override or "Administrator",
            laps_type="legacy",
            computer_name=computer_name,
            dns_hostname=dns_hostname,
            expiration=legacy_expiration,
            encrypted=False,
        )

    return None
