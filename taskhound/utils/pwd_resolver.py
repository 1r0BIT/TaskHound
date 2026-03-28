# pwdLastSet resolution utilities for TaskHound
#
# This module provides pwdLastSet (password last changed timestamp) resolution
# for user accounts. It REUSES existing resolver infrastructure:
#
# - SID resolution: resolve_name_to_sid_via_ldap (for NETBIOS\sam → SID)
# - User attributes: batch_get_user_attributes (already gets pwdLastSet + objectSid)
# - BloodHound data: HighValueLoader (hv_sids already has SID → user data)
# - Caching: Leverages existing cache_manager infrastructure
#
# IMPORTANT: Always use SID for lookups to avoid cross-domain ambiguity!
# sAMAccountName is NOT unique across domains - only SIDs are globally unique.

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from .logging import debug, info, warn

if TYPE_CHECKING:
    from ..connectors.bloodhound import BloodHoundConnector
    from ..parsers.highvalue import HighValueLoader


@dataclass
class PwdLastSetResult:
    """Result of pwdLastSet resolution."""

    pwd_last_set: Optional[datetime]
    source: str  # "cache", "bloodhound", "bloodhound_api", "ldap", "unknown"
    sid: Optional[str] = None  # Track the SID for future lookups
    cached: bool = False


class PwdLastSetResolver:
    """
    Resolves pwdLastSet for user accounts using existing resolver infrastructure.

    This class is a thin wrapper that coordinates:
    1. SID resolution (via existing name_to_sid resolvers)
    2. User attribute lookup (via batch_get_user_attributes)
    3. BloodHound data (via HighValueLoader)
    4. BloodHound API (via BloodHoundConnector)

    Resolution order (SID-first approach):
    1. If runas is NETBIOS\\sam, resolve to SID first using existing resolvers
    2. Look up by SID in BloodHound data (hv_sids)
    3. Look up by SID in BloodHound API
    4. LDAP fallback (batch_get_user_attributes already returns SID + pwdLastSet)

    All results are cached by SID for consistency.
    """

    def __init__(
        self,
        hv_loader: Optional["HighValueLoader"] = None,
        bh_connector: Optional["BloodHoundConnector"] = None,
        *,
        # LDAP credentials for fallback queries
        domain: Optional[str] = None,
        dc_ip: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        # LDAP override credentials (for local admin case)
        ldap_domain: Optional[str] = None,
        ldap_user: Optional[str] = None,
        ldap_password: Optional[str] = None,
        ldap_hashes: Optional[str] = None,
        # Behavior flags
        no_ldap: bool = False,
        opsec: bool = False,
    ):
        """Initialize pwdLastSet resolver."""
        self.hv_loader = hv_loader
        self.bh_connector = bh_connector

        # LDAP credentials (for both SID resolution and attribute queries)
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.hashes = hashes
        self.kerberos = kerberos
        self.aes_key = aes_key

        # LDAP overrides
        self.ldap_domain = ldap_domain
        self.ldap_user = ldap_user
        self.ldap_password = ldap_password
        self.ldap_hashes = ldap_hashes

        # Behavior
        self.no_ldap = no_ldap
        self.opsec = opsec

        # Session cache: SID -> PwdLastSetResult (SIDs are globally unique)
        # Note: Persistent caching is handled by existing cache_manager via
        # batch_get_user_attributes which uses "user_attrs" cache namespace
        self._sid_cache: Dict[str, PwdLastSetResult] = {}

        # Track SIDs/users we've already tried to query (avoid repeated lookups)
        self._query_attempted: set[str] = set()

        # Statistics
        self.stats = {
            "cache_hits": 0,
            "bloodhound_hits": 0,
            "bloodhound_api_hits": 0,
            "ldap_hits": 0,
            "misses": 0,
        }

    def _get_ldap_credentials(self) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Get effective LDAP credentials (with override support)."""
        return (
            self.ldap_domain or self.domain,
            self.ldap_user or self.username,
            self.ldap_password or self.password,
            self.ldap_hashes or self.hashes,
        )

    def _resolve_runas_to_sid(self, runas: str) -> Optional[str]:
        """
        Resolve a runas string (NETBIOS\\sam or user@domain) to a SID.

        Uses existing resolver infrastructure:
        1. Check HighValueLoader (hv_users has 'sid' field)
        2. Use resolve_name_to_sid_via_ldap for users

        Args:
            runas: User identifier (DOMAIN\\user, user@domain, or plain user)

        Returns:
            SID string or None if resolution fails
        """
        from ..resolver import is_sid

        if not runas:
            return None

        # Already a SID
        if is_sid(runas):
            return runas.upper()

        # Extract username for lookups
        if "\\" in runas:
            username = runas.split("\\", 1)[1].lower()
        elif "@" in runas:
            username = runas.split("@", 1)[0].lower()
        else:
            username = runas.lower()

        # 1. Check BloodHound high-value data first (already has SID)
        if self.hv_loader and self.hv_loader.loaded:
            user_data = self.hv_loader.hv_users.get(username)
            if user_data:
                sid = user_data.get("sid") or user_data.get("objectid")
                if sid:
                    debug(f"[Name->SID] BloodHound: {username} -> {sid}")
                    return sid.upper()

        # 2. Use existing LDAP resolver (if we have credentials and not in opsec mode)
        ldap_domain, ldap_user, ldap_pass, ldap_hashes = self._get_ldap_credentials()

        if not self.no_ldap and not self.opsec and ldap_domain and ldap_user:
            from ..resolver import resolve_name_to_sid_via_ldap

            sid = resolve_name_to_sid_via_ldap(
                name=username,
                domain=ldap_domain,
                is_computer=False,
                dc_ip=self.dc_ip,
                username=ldap_user,
                password=ldap_pass,
                hashes=ldap_hashes,
                kerberos=self.kerberos,
            )
            if sid:
                debug(f"[Name->SID] LDAP: {username} -> {sid}")
                return sid.upper()

        return None

    def resolve(self, runas: str, sid: Optional[str] = None) -> PwdLastSetResult:
        """
        Resolve pwdLastSet for a user account.

        SID-first resolution approach:
        1. Resolve runas to SID if needed (using existing resolvers)
        2. Check session cache (by SID)
        3. Check BloodHound high-value data (by SID)
        4. Query BloodHound API (by SID)
        5. LDAP fallback (gets both pwdLastSet and SID via batch_get_user_attributes)

        Args:
            runas: The user account (DOMAIN\\user or user@domain or SID)
            sid: Optional SID if already known

        Returns:
            PwdLastSetResult with pwd_last_set datetime, source, and SID
        """
        from ..resolver import is_sid

        if not runas and not sid:
            return PwdLastSetResult(pwd_last_set=None, source="unknown")

        # Step 1: Resolve to SID if we don't have one
        if not sid:
            if is_sid(runas):
                sid = runas.upper()
            else:
                # Try to resolve runas to SID using existing infrastructure
                sid = self._resolve_runas_to_sid(runas)

        # Step 2: Check session cache (by SID)
        if sid:
            sid = sid.upper()
            if sid in self._sid_cache:
                self.stats["cache_hits"] += 1
                result = self._sid_cache[sid]
                return PwdLastSetResult(
                    pwd_last_set=result.pwd_last_set,
                    source=result.source,
                    sid=sid,
                    cached=True,
                )

        # Step 3: Try BloodHound high-value data (by SID)
        result = self._try_bloodhound_data(sid)
        if result.pwd_last_set is not None:
            if result.sid:
                self._sid_cache[result.sid.upper()] = result
            self.stats["bloodhound_hits"] += 1
            return result

        # Determine lookup key for tracking
        lookup_key = sid or runas.upper() if runas else ""

        # Step 4: Try BloodHound API (by SID)
        if not self.opsec and sid and lookup_key not in self._query_attempted:
            result = self._try_bloodhound_api(sid)
            if result.pwd_last_set is not None:
                self._sid_cache[sid] = result
                self.stats["bloodhound_api_hits"] += 1
                return result

        # Step 5: LDAP fallback (uses batch_get_user_attributes which returns SID)
        if not self.no_ldap and not self.opsec and lookup_key not in self._query_attempted:
            result = self._try_ldap(runas, sid)
            self._query_attempted.add(lookup_key)
            if result.pwd_last_set is not None:
                if result.sid:
                    self._sid_cache[result.sid.upper()] = result
                self.stats["ldap_hits"] += 1
                return result

        # Not found - cache the miss
        self.stats["misses"] += 1
        miss_result = PwdLastSetResult(pwd_last_set=None, source="unknown", sid=sid)
        if sid:
            self._sid_cache[sid] = miss_result
        return miss_result

    def _try_bloodhound_data(self, sid: Optional[str]) -> PwdLastSetResult:
        """Try to get pwdLastSet from pre-loaded BloodHound data (by SID)."""
        if not self.hv_loader or not self.hv_loader.loaded:
            return PwdLastSetResult(pwd_last_set=None, source="unknown")

        user_data = None
        found_sid = sid

        # ALWAYS prefer SID lookup (globally unique)
        if sid:
            user_data = self.hv_loader.hv_sids.get(sid.upper())

        if not user_data:
            return PwdLastSetResult(pwd_last_set=None, source="unknown", sid=found_sid)

        pwd_last_set = user_data.get("pwdlastset")
        if pwd_last_set is None:
            return PwdLastSetResult(pwd_last_set=None, source="unknown", sid=found_sid)

        # Parse timestamp if needed
        if isinstance(pwd_last_set, datetime):
            return PwdLastSetResult(pwd_last_set=pwd_last_set, source="bloodhound", sid=found_sid)

        # Handle various timestamp formats
        try:
            from ..parsers.highvalue import parse_timestamp
            parsed = parse_timestamp(pwd_last_set)
            if parsed:
                return PwdLastSetResult(pwd_last_set=parsed, source="bloodhound", sid=found_sid)
        except Exception as e:
            debug(f"Failed to parse pwdLastSet for SID {sid}: {e}")

        return PwdLastSetResult(pwd_last_set=None, source="unknown", sid=found_sid)

    def _try_bloodhound_api(self, sid: str) -> PwdLastSetResult:
        """Try to get pwdLastSet via BloodHound API query (by SID only)."""
        if not self.bh_connector or not sid:
            return PwdLastSetResult(pwd_last_set=None, source="unknown")

        try:
            debug(f"Querying BloodHound API by SID: {sid}")
            user_data = self.bh_connector.get_user_properties(sid)
            if not user_data:
                debug(f"SID {sid} not found in BloodHound API")
                return PwdLastSetResult(pwd_last_set=None, source="unknown", sid=sid)

            pwd_last_set = user_data.get("pwdlastset")
            if pwd_last_set is None:
                return PwdLastSetResult(pwd_last_set=None, source="unknown", sid=sid)

            # Parse timestamp
            if isinstance(pwd_last_set, datetime):
                return PwdLastSetResult(pwd_last_set=pwd_last_set, source="bloodhound_api", sid=sid)

            from ..parsers.highvalue import parse_timestamp
            parsed = parse_timestamp(pwd_last_set)
            if parsed:
                debug(f"Got pwdLastSet for SID {sid} from BloodHound API")
                return PwdLastSetResult(pwd_last_set=parsed, source="bloodhound_api", sid=sid)

        except Exception as e:
            debug(f"BloodHound API query failed for SID {sid}: {e}")

        return PwdLastSetResult(pwd_last_set=None, source="unknown", sid=sid)

    def _try_ldap(self, runas: str, sid: Optional[str]) -> PwdLastSetResult:
        """
        Try to get pwdLastSet via LDAP query.

        Uses existing batch_get_user_attributes which already:
        - Returns objectSid (so we get SID for caching)
        - Returns pwdLastSet
        - Handles caching via cache_manager
        """
        ldap_domain, ldap_user, ldap_pass, ldap_hashes = self._get_ldap_credentials()

        if not ldap_domain or not ldap_user:
            return PwdLastSetResult(pwd_last_set=None, source="unknown", sid=sid)

        # Get the username for LDAP query
        if "\\" in runas:
            username = runas.split("\\", 1)[1].lower()
        elif "@" in runas:
            username = runas.split("@", 1)[0].lower()
        else:
            username = runas.lower()

        if not username:
            return PwdLastSetResult(pwd_last_set=None, source="unknown", sid=sid)

        try:
            from ..resolver import batch_get_user_attributes

            # batch_get_user_attributes already returns objectSid
            results = batch_get_user_attributes(
                usernames=[username],
                domain=ldap_domain,
                dc_ip=self.dc_ip,
                username=ldap_user,
                password=ldap_pass,
                hashes=ldap_hashes,
                kerberos=self.kerberos,
                aes_key=self.aes_key,
                attributes=["pwdLastSet", "sAMAccountName", "objectSid"],
            )

            if username in results:
                user_attrs = results[username]
                pwd_last_set = user_attrs.get("pwdLastSet")
                # batch_get_user_attributes returns 'sid' key for objectSid
                found_sid = user_attrs.get("sid") or sid

                if pwd_last_set:
                    debug(f"Got pwdLastSet for {username} from LDAP (SID: {found_sid})")
                    return PwdLastSetResult(pwd_last_set=pwd_last_set, source="ldap", sid=found_sid)

        except Exception as e:
            debug(f"LDAP query failed for {runas}: {e}")

        return PwdLastSetResult(pwd_last_set=None, source="unknown", sid=sid)

    def get_pwd_last_set(self, runas: str, sid: Optional[str] = None) -> Optional[datetime]:
        """
        Convenience method to just get the pwdLastSet datetime.

        Args:
            runas: The user account
            sid: Optional SID if known (preferred for lookups)

        Returns:
            pwdLastSet datetime or None if not found
        """
        result = self.resolve(runas, sid=sid)
        return result.pwd_last_set

    def prefetch_from_tasks(self, items: List[Tuple[str, bytes]]) -> None:
        """
        Pre-fetch pwdLastSet for all unique users in a list of tasks.

        This is an optimization to batch LDAP queries when BloodHound
        doesn't have the data.

        Uses existing batch_get_user_attributes which handles:
        - Batched LDAP queries
        - objectSid retrieval
        - Caching via cache_manager

        Args:
            items: List of (rel_path, xml_bytes) tuples
        """
        from ..parsers.task_xml import parse_task_xml
        from ..resolver import is_sid

        # Collect unique runas users not already in cache
        users_to_fetch: Dict[str, str] = {}  # norm_user -> original_runas

        for _rel_path, xml_bytes in items:
            meta = parse_task_xml(xml_bytes)
            runas = meta.get("runas")
            if not runas:
                continue

            logon_type = (meta.get("logon_type") or "").strip().lower()
            # Only query users from tasks with stored credentials
            if logon_type != "password" or is_sid(runas):
                continue

            # Extract username
            if "\\" in runas:
                username = runas.split("\\", 1)[1].lower()
            elif "@" in runas:
                username = runas.split("@", 1)[0].lower()
            else:
                username = runas.lower()

            if not username:
                continue

            # Check if already in BloodHound data
            if self.hv_loader and self.hv_loader.loaded:
                user_data = self.hv_loader.hv_users.get(username)
                if user_data:
                    # Already have this user in BH data - extract SID and cache
                    user_sid = user_data.get("sid") or user_data.get("objectid")
                    if user_sid:
                        pwd_last_set = user_data.get("pwdlastset")
                        if isinstance(pwd_last_set, datetime) or pwd_last_set:
                            self._sid_cache[user_sid.upper()] = PwdLastSetResult(
                                pwd_last_set=pwd_last_set if isinstance(pwd_last_set, datetime) else None,
                                source="bloodhound",
                                sid=user_sid.upper(),
                            )
                    continue

            users_to_fetch[username] = runas

        if not users_to_fetch:
            return

        # Batch LDAP query for missing users
        if not self.no_ldap and not self.opsec:
            self._batch_ldap_fetch(users_to_fetch)

    def _batch_ldap_fetch(self, users_to_fetch: Dict[str, str]) -> None:
        """
        Batch fetch pwdLastSet for multiple users via LDAP.

        Uses existing batch_get_user_attributes which already handles batching
        and caching.

        Args:
            users_to_fetch: Dict of norm_user -> original_runas
        """
        ldap_domain, ldap_user, ldap_pass, ldap_hashes = self._get_ldap_credentials()

        if not ldap_domain or not ldap_user:
            return

        try:
            from ..resolver import batch_get_user_attributes

            usernames = list(users_to_fetch.keys())
            info(f"Querying LDAP for password age data ({len(usernames)} users)...")

            # batch_get_user_attributes handles batching and returns objectSid
            results = batch_get_user_attributes(
                usernames=usernames,
                domain=ldap_domain,
                dc_ip=self.dc_ip,
                username=ldap_user,
                password=ldap_pass,
                hashes=ldap_hashes,
                kerberos=self.kerberos,
                aes_key=self.aes_key,
                attributes=["pwdLastSet", "sAMAccountName", "objectSid"],
            )

            # Cache results by SID
            found_count = 0
            for _norm_user, attrs in results.items():
                pwd_last_set = attrs.get("pwdLastSet")
                user_sid = attrs.get("sid")

                if user_sid:
                    result = PwdLastSetResult(
                        pwd_last_set=pwd_last_set,
                        source="ldap" if pwd_last_set else "unknown",
                        sid=user_sid.upper(),
                    )
                    self._sid_cache[user_sid.upper()] = result

                    if pwd_last_set:
                        self.stats["ldap_hits"] += 1
                        found_count += 1

            # Mark all as attempted
            self._query_attempted.update(usernames)

            if found_count:
                from .logging import good
                good(f"Retrieved password age data for {found_count}/{len(usernames)} users from LDAP")

        except Exception as e:
            warn(f"LDAP batch query failed: {e}")
            self._query_attempted.update(users_to_fetch.keys())

    def get_stats_summary(self) -> str:
        """Get a summary of resolution statistics."""
        total = sum(self.stats.values())
        if total == 0:
            return "No pwdLastSet lookups performed"

        parts = []
        if self.stats["cache_hits"]:
            parts.append(f"cache: {self.stats['cache_hits']}")
        if self.stats["bloodhound_hits"]:
            parts.append(f"bloodhound: {self.stats['bloodhound_hits']}")
        if self.stats["bloodhound_api_hits"]:
            parts.append(f"bloodhound_api: {self.stats['bloodhound_api_hits']}")
        if self.stats["ldap_hits"]:
            parts.append(f"ldap: {self.stats['ldap_hits']}")
        if self.stats["misses"]:
            parts.append(f"not_found: {self.stats['misses']}")

        return f"pwdLastSet lookups: {', '.join(parts)}"
