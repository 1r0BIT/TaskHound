# LAPS Data Models
import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

from ..utils.cache_manager import get_cache
from ..utils.logging import debug

# Cache category for LAPS credentials
LAPS_CACHE_CATEGORY = "laps"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class LAPSCredential:
    """Represents a LAPS credential for a single computer"""

    password: str
    username: str  # From msLAPS-Password JSON, --laps-user, or "Administrator"
    laps_type: str  # "legacy" or "mslaps"
    computer_name: str  # sAMAccountName (e.g., "WS01$")
    dns_hostname: Optional[str] = None  # FQDN if available
    expiration: Optional[datetime] = None  # Password expiration time
    encrypted: bool = False  # True if encrypted (not supported yet)

    def is_expired(self) -> bool:
        """Check if the LAPS password has expired"""
        if self.expiration is None:
            return False
        return datetime.now(timezone.utc) > self.expiration

    def to_cache_dict(self) -> Dict:
        """Serialize credential for persistent cache storage"""
        return {
            "password": self.password,
            "username": self.username,
            "laps_type": self.laps_type,
            "computer_name": self.computer_name,
            "dns_hostname": self.dns_hostname,
            "expiration": self.expiration.isoformat() if self.expiration else None,
            "encrypted": self.encrypted,
        }

    @classmethod
    def from_cache_dict(cls, data: Dict) -> "LAPSCredential":
        """Deserialize credential from persistent cache"""
        expiration = None
        if data.get("expiration"):
            with contextlib.suppress(ValueError, TypeError):
                expiration = datetime.fromisoformat(data["expiration"])

        return cls(
            password=data["password"],
            username=data["username"],
            laps_type=data["laps_type"],
            computer_name=data["computer_name"],
            dns_hostname=data.get("dns_hostname"),
            expiration=expiration,
            encrypted=data.get("encrypted", False),
        )


@dataclass
class LAPSCache:
    """In-memory cache for LAPS credentials"""

    _cache: Dict[str, LAPSCredential] = field(default_factory=dict)
    domain: Optional[str] = None  # Domain for scoping cache keys
    legacy_count: int = 0
    mslaps_count: int = 0
    encrypted_count: int = 0  # Skipped due to encryption
    from_persistent_cache: int = 0  # Count loaded from persistent cache

    def add(self, cred: LAPSCredential, persist: bool = True) -> None:
        """
        Add a credential to the cache, indexed by normalized hostname.

        Args:
            cred: LAPS credential to add
            persist: If True, also save to persistent SQLite cache
        """
        # Normalize: uppercase, without trailing $
        normalized_name = cred.computer_name.upper().rstrip("$")

        # Create cache key - include domain for multi-domain support
        # Format: "DOMAIN\COMPUTERNAME" or just "COMPUTERNAME" if no domain
        key = (
            f"{self.domain.upper()}\\{normalized_name}"
            if self.domain
            else normalized_name
        )

        self._cache[key] = cred

        # Update statistics
        if cred.encrypted:
            self.encrypted_count += 1
        elif cred.laps_type == "legacy":
            self.legacy_count += 1
        elif cred.laps_type in ("mslaps", "mslaps-encrypted"):
            # Both plaintext and decrypted-encrypted count as Windows LAPS
            self.mslaps_count += 1

        # Persist to SQLite cache if enabled
        # Don't persist encrypted/failed credentials - they should be retried with fresh auth
        if persist and not cred.encrypted:
            self._persist_credential(key, cred)

    @staticmethod
    def _normalize_key(hostname: str, domain: Optional[str] = None) -> str:
        """Normalize hostname to uppercase cache key, optionally with domain."""
        normalized = hostname.upper().rstrip("$")
        # Strip any existing domain prefix and re-add if domain specified
        if "\\" in normalized:
            normalized = normalized.split("\\")[-1]
        if "." in normalized:
            # Could be FQDN - extract short name
            normalized = normalized.split(".")[0]
        if domain:
            return f"{domain.upper()}\\{normalized}"
        return normalized

    def _persist_credential(self, key: str, cred: LAPSCredential) -> None:
        """Save credential to persistent SQLite cache"""
        cache = get_cache()
        if not cache or not cache.persistent_enabled:
            return

        # Calculate TTL based on LAPS expiration
        # Default to 8 hours if no expiration (typical LAPS rotation is 24h+)
        if cred.expiration:
            # Use actual expiration, but cap at 24 hours
            ttl_seconds = (cred.expiration - datetime.now(timezone.utc)).total_seconds()
            ttl_hours = min(max(ttl_seconds / 3600, 0.1), 24)  # Min 6 minutes, max 24 hours
        else:
            ttl_hours = 8  # Default for legacy LAPS without expiration info

        try:
            cache.set(LAPS_CACHE_CATEGORY, key, cred.to_cache_dict(), ttl_hours=int(ttl_hours))
            debug(f"LAPS: Cached {key} (TTL: {ttl_hours:.1f}h)")
        except Exception as e:
            debug(f"LAPS: Failed to persist {key}: {e}")

    def _load_from_persistent(self, key: str) -> Optional[LAPSCredential]:
        """Try to load credential from persistent SQLite cache"""
        cache = get_cache()
        if not cache or not cache.persistent_enabled:
            return None

        try:
            data = cache.get(LAPS_CACHE_CATEGORY, key)
            if data:
                cred = LAPSCredential.from_cache_dict(data)
                # Double-check expiration
                if not cred.is_expired():
                    debug(f"LAPS: Loaded {key} from persistent cache")
                    return cred
                else:
                    debug(f"LAPS: Cached {key} has expired, will re-query")
                    cache.delete(LAPS_CACHE_CATEGORY, key)
        except Exception as e:
            debug(f"LAPS: Failed to load {key} from cache: {e}")

        return None

    def get(self, hostname: str) -> Optional[LAPSCredential]:
        """
        Lookup LAPS credential by hostname.

        Checks in-memory cache first, then persistent cache.
        Lookups are case-insensitive. Uses self.domain for scoped lookups.

        Args:
            hostname: Computer name, FQDN, or IP-resolved name

        Returns:
            LAPSCredential if found, None otherwise
        """
        # Normalize hostname to uppercase, strip $ suffix
        normalized = hostname.upper().rstrip("$")

        # Extract short name from FQDN if present
        short_name = normalized.split(".")[0] if "." in normalized else normalized

        # Build list of keys to try (most specific to least specific)
        keys_to_try = []

        # If domain is set on cache, try domain-qualified key first
        if self.domain:
            keys_to_try.append(f"{self.domain.upper()}\\{short_name}")

        # Try unqualified short name (for backward compat and single-domain use)
        keys_to_try.append(short_name)

        # Also try the full normalized name if different from short name
        if normalized != short_name:
            if self.domain:
                keys_to_try.append(f"{self.domain.upper()}\\{normalized}")
            keys_to_try.append(normalized)

        # Check in-memory cache first
        for key in keys_to_try:
            if key in self._cache:
                return self._cache[key]

        # Check persistent cache
        for key in keys_to_try:
            cred = self._load_from_persistent(key)
            if cred:
                # Promote to in-memory cache (don't re-persist)
                self._cache[key] = cred
                self.from_persistent_cache += 1
                return cred

        return None

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, hostname: str) -> bool:
        return self.get(hostname) is not None

    @property
    def total_usable(self) -> int:
        """Count of non-encrypted credentials"""
        return self.legacy_count + self.mslaps_count

    def get_statistics(self) -> Dict[str, int]:
        """Return cache statistics for display"""
        return {
            "total": len(self._cache),
            "legacy": self.legacy_count,
            "mslaps": self.mslaps_count,
            "encrypted": self.encrypted_count,
            "usable": self.total_usable,
            "from_cache": self.from_persistent_cache,
        }

    @classmethod
    def load_from_persistent_cache(cls, domain: Optional[str] = None) -> Optional["LAPSCache"]:
        """
        Load all LAPS credentials from persistent SQLite cache.

        Args:
            domain: Domain name for filtering/scoping (optional, if provided only loads
                    credentials for that domain)

        Returns:
            LAPSCache populated with cached credentials, or None if cache is empty/disabled
        """
        sqlite_cache = get_cache()
        if not sqlite_cache or not sqlite_cache.persistent_enabled:
            debug("LAPS: Persistent cache not available")
            return None

        try:
            # Get all entries from LAPS category
            entries = sqlite_cache.get_all(LAPS_CACHE_CATEGORY)
            if not entries:
                debug("LAPS: No cached credentials found")
                return None

            # Create cache with domain set for future lookups
            cache = cls(domain=domain)
            loaded = 0
            expired = 0

            # Normalize domain for comparison
            domain_prefix = f"{domain.upper()}\\" if domain else None

            for key, data in entries.items():
                try:
                    # Normalize key to uppercase for consistent lookup
                    normalized_key = key.upper()

                    # If domain specified, only load entries for that domain
                    # Skip keys from other domains (has domain prefix but wrong domain)
                    # Allow unqualified keys for backward compat
                    if (
                        domain_prefix
                        and not normalized_key.startswith(domain_prefix)
                        and "\\" in normalized_key
                    ):
                        # Key belongs to a different domain, skip
                        continue

                    cred = LAPSCredential.from_cache_dict(data)
                    if cred.is_expired():
                        expired += 1
                        # Clean up expired entry
                        sqlite_cache.delete(LAPS_CACHE_CATEGORY, key)
                        continue

                    # Skip encrypted credentials - they should be retried with fresh auth
                    # (these shouldn't be in the cache anymore, but handle legacy entries)
                    if cred.encrypted:
                        debug(f"LAPS: Skipping encrypted cached credential {key} (requires fresh auth)")
                        sqlite_cache.delete(LAPS_CACHE_CATEGORY, key)
                        continue

                    # Add to cache without re-persisting
                    cache._cache[normalized_key] = cred
                    if cred.laps_type == "legacy":
                        cache.legacy_count += 1
                    elif cred.laps_type in ("mslaps", "mslaps-encrypted"):
                        cache.mslaps_count += 1
                    cache.from_persistent_cache += 1
                    loaded += 1
                except Exception as e:
                    debug(f"LAPS: Failed to load cached credential {key}: {e}")
                    continue

            if loaded > 0:
                debug(f"LAPS: Loaded {loaded} credentials from persistent cache ({expired} expired)")
                return cache
            else:
                debug("LAPS: All cached credentials were expired or invalid")
                return None

        except Exception as e:
            debug(f"LAPS: Failed to load from persistent cache: {e}")
            return None

    def save_to_persistent_cache(self) -> int:
        """
        Save all credentials to persistent cache.

        Returns:
            Number of credentials saved
        """
        sqlite_cache = get_cache()
        if not sqlite_cache or not sqlite_cache.persistent_enabled:
            return 0

        saved = 0
        for key, cred in self._cache.items():
            try:
                self._persist_credential(key, cred)
                saved += 1
            except Exception as e:
                debug(f"LAPS: Failed to save {key} to cache: {e}")

        return saved


@dataclass
class LAPSFailure:
    """Represents a LAPS-related failure for a target"""

    hostname: str
    failure_type: str  # "not_found", "auth_failed", "remote_uac", "encrypted"
    message: str
    laps_user_tried: Optional[str] = None
    laps_type_tried: Optional[str] = None
