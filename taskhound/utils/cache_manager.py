"""
Session-level and persistent caching for TaskHound using SQLite.

This module provides a three-tier caching system:
1. Session cache (in-memory, single run)
2. Persistent cache (SQLite database, across runs)
3. Live queries (fallback)

Thread-safety:
- Session cache protected by RLock for concurrent access
- SQLite uses per-thread connections via threading.local() for thread safety
- SQLite uses WAL mode for concurrent reads/writes across threads
"""

import atexit
import contextlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from ..utils.logging import debug, info, warn


class CacheManager:
    """
    Manages session and persistent caching for TaskHound using SQLite.

    Thread-safe:
    - Session cache (in-memory dict) protected by RLock
    - SQLite uses per-thread connections (threading.local) for thread affinity
    - SQLite uses WAL mode for concurrent access across threads
    """

    def __init__(self, cache_file: Path | None = None, ttl_hours: int = 24, enabled: bool = True):
        """
        Initialize cache manager.

        Args:
            cache_file: Path to persistent cache DB (default: ~/.taskhound/cache.db)
            ttl_hours: Default TTL for new entries (hours)
            enabled: Enable persistent caching (session cache always active)
        """
        self.ttl_hours = ttl_hours
        self.persistent_enabled = enabled

        # Thread-local storage for per-thread SQLite connections
        self._local = threading.local()

        # Thread-safety: RLock for session cache access
        self._session_lock = threading.RLock()

        # Default cache location
        if cache_file is None:
            cache_dir = Path.home() / ".taskhound"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / "cache.db"

        self.cache_file = cache_file
        self.is_new_db = not cache_file.exists() if cache_file else True

        # Tier 1: Session cache (in-memory, cleared on exit)
        self.session: dict[str, Any] = {}

        # Statistics for reporting (also protected by _session_lock)
        self.stats = {
            "session_hits": 0,
            "session_misses": 0,
            "persistent_hits": 0,
            "persistent_misses": 0,
            "expired": 0,
        }

        # Track all connections for cleanup (protected by _session_lock)
        self._connections: list[sqlite3.Connection] = []

        # Initialize persistent cache if enabled (creates schema)
        if self.persistent_enabled:
            self._init_db()

    def _get_conn(self) -> sqlite3.Connection | None:
        """
        Get thread-local SQLite connection, creating one if needed.

        SQLite connections have thread affinity - they can only be used in the
        thread that created them. This method ensures each thread gets its own
        connection to the shared database file.

        Returns:
            SQLite connection for current thread, or None if disabled/failed
        """
        if not self.persistent_enabled:
            return None

        # Check for existing connection in this thread
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn

        # Create new connection for this thread
        try:
            conn = sqlite3.connect(self.cache_file, timeout=10.0)
            # WAL mode allows concurrent reads while writing
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn

            # Track for cleanup
            with self._session_lock:
                self._connections.append(conn)

            debug(f"Created new cache connection for thread {threading.current_thread().name}")
            return conn
        except Exception as e:
            debug(f"Failed to create cache connection: {e}")
            return None

    def _init_db(self):
        """Initialize SQLite database schema (called once at startup)."""
        try:
            # Get connection for main thread (also creates schema)
            conn = self._get_conn()
            if not conn:
                self.persistent_enabled = False
                return

            # Create table if not exists
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    category TEXT,
                    key TEXT,
                    value TEXT,
                    expires_at REAL,
                    PRIMARY KEY (category, key)
                )
            """)

            # Create index for expiration cleanup
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)
            """)

            conn.commit()

            # Opportunistic cleanup of expired entries
            self._prune_expired()

        except Exception as e:
            warn(f"Failed to initialize cache database: {e}")
            self.persistent_enabled = False

    def _prune_expired(self):
        """Remove expired entries from database."""
        conn = self._get_conn()
        if not conn:
            return

        try:
            now = time.time()
            cursor = conn.execute("DELETE FROM cache WHERE expires_at < ?", (now,))
            if cursor.rowcount > 0:
                debug(f"Pruned {cursor.rowcount} expired cache entries")
                with self._session_lock:
                    self.stats["expired"] += cursor.rowcount
            conn.commit()
        except Exception as e:
            debug(f"Error pruning cache: {e}")

    def get(self, category: str, key: str) -> Any | None:
        """
        Get cached value (checks session first, then persistent).

        Thread-safe: Uses RLock for session cache access.

        Args:
            category: Cache category ("computers", "users", "sids")
            key: Cache key (e.g., "DC.CORP.LOCAL", "S-1-5-21-...", etc.)

        Returns:
            Cached value or None if miss/expired
        """
        session_key = f"{category}:{key}"

        # Tier 1: Check session cache first (fastest, thread-safe)
        with self._session_lock:
            if session_key in self.session:
                self.stats["session_hits"] += 1
                debug(f"Cache hit (session): {category}:{key}")
                return self.session[session_key]
            self.stats["session_misses"] += 1

        # Tier 2: Check persistent cache (thread-local connection)
        conn = self._get_conn()
        if conn:
            try:
                now = time.time()
                cursor = conn.execute(
                    "SELECT value, expires_at FROM cache WHERE category=? AND key=?", (category, key)
                )
                row = cursor.fetchone()

                if row:
                    value_json, expires_at = row

                    # Check expiration
                    if expires_at < now:
                        debug(f"Cache expired: {category}:{key}")
                        with self._session_lock:
                            self.stats["expired"] += 1
                        # Lazy delete
                        conn.execute("DELETE FROM cache WHERE category=? AND key=?", (category, key))
                        conn.commit()
                        return None

                    # Valid hit
                    try:
                        value = json.loads(value_json)
                        with self._session_lock:
                            self.stats["persistent_hits"] += 1
                            # Promote to session cache
                            self.session[session_key] = value
                        debug(f"Cache hit (persistent): {category}:{key}")
                        return value
                    except json.JSONDecodeError:
                        warn(f"Corrupt cache entry: {category}:{key}")
                        return None
            except Exception as e:
                debug(f"Cache read error: {e}")

        with self._session_lock:
            self.stats["persistent_misses"] += 1
        return None

    def set(self, category: str, key: str, value: Any, ttl_hours: int | None = None):
        """
        Store value in both session and persistent caches.

        Thread-safe: Uses RLock for session cache, per-thread SQLite connection.

        Args:
            category: Cache category ("computers", "users", "sids")
            key: Cache key
            value: Value to store (must be JSON serializable)
            ttl_hours: Override default TTL (optional)
        """
        session_key = f"{category}:{key}"

        # Always store in session cache (thread-safe)
        with self._session_lock:
            self.session[session_key] = value

        # Store in persistent cache (thread-local connection)
        conn = self._get_conn()
        if conn:
            try:
                ttl = ttl_hours if ttl_hours is not None else self.ttl_hours
                expires_at = time.time() + (ttl * 3600)
                value_json = json.dumps(value)

                conn.execute(
                    "INSERT OR REPLACE INTO cache (category, key, value, expires_at) VALUES (?, ?, ?, ?)",
                    (category, key, value_json, expires_at),
                )
                conn.commit()
                debug(f"Cache store: {category}:{key}")
            except Exception as e:
                debug(f"Cache write error: {e}")

    def delete(self, category: str, key: str):
        """
        Remove value from both session and persistent caches.

        Thread-safe: Uses RLock for session cache, per-thread SQLite connection.

        Args:
            category: Cache category
            key: Cache key
        """
        session_key = f"{category}:{key}"

        # Remove from session cache (thread-safe)
        with self._session_lock:
            if session_key in self.session:
                del self.session[session_key]

        # Remove from persistent cache (thread-local connection)
        conn = self._get_conn()
        if conn:
            try:
                conn.execute("DELETE FROM cache WHERE category=? AND key=?", (category, key))
                conn.commit()
            except Exception as e:
                debug(f"Cache delete error: {e}")

    def increment(self, category: str, key: str, max_value: int = 3) -> int:
        """
        Atomically increment a counter value, respecting a maximum.

        Thread-safe: Uses RLock to ensure atomic read-check-increment.
        Returns the new value AFTER increment, or max_value+1 if already at/above max.

        This is designed for fail counters where we want to:
        1. Skip if already at max (return value > max)
        2. Increment atomically to prevent race conditions

        Args:
            category: Cache category (e.g., "sid_failures")
            key: Cache key (e.g., SID string)
            max_value: Maximum allowed value (default: 3)

        Returns:
            New value after increment. If > max_value, caller should skip.
        """
        session_key = f"{category}:{key}"

        with self._session_lock:
            # Get current value
            current = self.session.get(session_key, 0)
            if not isinstance(current, int):
                try:
                    current = int(current)
                except (ValueError, TypeError):
                    current = 0

            # If already at or above max, return max+1 to signal "skip"
            if current >= max_value:
                return max_value + 1

            # Increment
            new_value = current + 1
            self.session[session_key] = new_value

        # Also update persistent cache (best effort, session is authoritative)
        conn = self._get_conn()
        if conn:
            try:
                ttl = self.ttl_hours
                expires_at = time.time() + (ttl * 3600)
                conn.execute(
                    "INSERT OR REPLACE INTO cache (category, key, value, expires_at) VALUES (?, ?, ?, ?)",
                    (category, key, json.dumps(new_value), expires_at),
                )
                conn.commit()
            except Exception as e:
                debug(f"Cache increment persist error: {e}")

        return new_value

    def get_all(self, category: str) -> dict[str, Any]:
        """
        Get all non-expired cached values for a category.

        Args:
            category: Cache category (e.g., "laps", "computers", "users")

        Returns:
            Dictionary of key -> value for all valid entries in the category
        """
        result: dict[str, Any] = {}

        conn = self._get_conn()
        if not conn:
            return result

        try:
            now = time.time()
            cursor = conn.execute(
                "SELECT key, value, expires_at FROM cache WHERE category=?", (category,)
            )

            expired_keys = []
            for row in cursor.fetchall():
                key, value_json, expires_at = row

                # Check expiration
                if expires_at < now:
                    expired_keys.append(key)
                    continue

                try:
                    value = json.loads(value_json)
                    result[key] = value
                except json.JSONDecodeError:
                    debug(f"Corrupt cache entry: {category}:{key}")
                    continue

            # Clean up expired entries
            if expired_keys:
                for key in expired_keys:
                    conn.execute(
                        "DELETE FROM cache WHERE category=? AND key=?", (category, key)
                    )
                conn.commit()
                debug(f"Cleaned up {len(expired_keys)} expired {category} cache entries")

        except Exception as e:
            debug(f"Cache get_all error: {e}")

        return result

    def invalidate(self, category: str | None = None, key: str | None = None):
        """
        Invalidate cache entries.

        Args:
            category: If provided, invalidate entire category
            key: If provided (with category), invalidate specific entry
                 If category is None, invalidates from all categories
        """
        # Clear session cache
        if category is None and key is None:
            self.session.clear()
        elif category is not None and key is None:
            self.session = {k: v for k, v in self.session.items() if not k.startswith(f"{category}:")}
        elif category is not None and key is not None:
            session_key = f"{category}:{key}"
            self.session.pop(session_key, None)

        # Clear persistent cache (thread-local connection)
        conn = self._get_conn()
        if conn:
            try:
                if category is None and key is None:
                    conn.execute("DELETE FROM cache")
                    info("Cache cleared (all entries)")
                elif category is not None and key is None:
                    conn.execute("DELETE FROM cache WHERE category=?", (category,))
                    info(f"Cache cleared (category: {category})")
                elif category is not None and key is not None:
                    conn.execute("DELETE FROM cache WHERE category=? AND key=?", (category, key))
                    debug(f"Cache invalidated: {category}:{key}")

                conn.commit()
            except Exception as e:
                warn(f"Cache invalidation error: {e}")

    def close_thread_connection(self):
        """
        Close the SQLite connection for the current thread.

        Call this when a worker thread finishes to properly clean up
        its thread-local connection and avoid ResourceWarning.
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()
            self._local.conn = None
            # Remove from tracked connections
            with self._session_lock:
                if conn in self._connections:
                    self._connections.remove(conn)

    def close(self):
        """Close all database connections (one per thread)."""
        with self._session_lock:
            for conn in self._connections:
                with contextlib.suppress(Exception):
                    conn.close()
            self._connections.clear()
        # Clear thread-local connection reference for this thread
        self._local.conn = None

    def __del__(self):
        """Destructor to ensure connections are closed."""
        with contextlib.suppress(Exception):
            self.close()

    # ==========================================
    # Host Deduplication (Session-only)
    # ==========================================
    # Used to prevent processing dual-homed hosts twice when
    # multiple IPs resolve to the same FQDN

    def try_mark_host_processed(self, fqdn: str, target: str) -> tuple[bool, str | None]:
        """
        Atomically check if host is processed and mark it if not.

        This is the thread-safe way to handle dual-homed host deduplication.
        Combines check + mark in a single atomic operation to prevent TOCTOU
        race conditions where two threads both pass the check before either marks.

        Args:
            fqdn: Fully qualified domain name (e.g., "DC.domain.lab")
            target: The target (IP or hostname) trying to claim this host

        Returns:
            (True, None) if this thread successfully marked the host (proceed with scan)
            (False, original_target) if already marked (skip, return who marked it first)
        """
        session_key = f"_processed_hosts:{fqdn.upper()}"
        with self._session_lock:
            if session_key in self.session:
                # Already marked by another target
                return (False, self.session[session_key])
            # Mark it
            self.session[session_key] = target
            return (True, None)

    def print_stats(self):
        """Print cache performance statistics."""
        total_requests = self.stats["session_hits"] + self.stats["session_misses"]

        if total_requests == 0:
            info("Cache: No requests made")
            return

        session_hit_rate = (self.stats["session_hits"] / total_requests) * 100
        persistent_hit_rate = (self.stats["persistent_hits"] / total_requests) * 100

        info("Cache Statistics:")
        info(f"  Session hits: {self.stats['session_hits']} ({session_hit_rate:.1f}%)")
        info(f"  Persistent hits: {self.stats['persistent_hits']} ({persistent_hit_rate:.1f}%)")
        info(f"  Misses: {self.stats['persistent_misses']}")
        info(f"  Expired: {self.stats['expired']}")

        conn = self._get_conn()
        if conn:
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM cache")
                total_cached = cursor.fetchone()[0]
                info(f"  Persistent cache size: {total_cached} entries")
            except (sqlite3.Error, TypeError):
                pass  # Database query failed


# Global cache instance
_cache: CacheManager | None = None


def _cleanup_cache():
    """Cleanup function called at program exit."""
    global _cache
    if _cache is not None:
        with contextlib.suppress(Exception):
            _cache.close()
        _cache = None


# Register cleanup at module import time
atexit.register(_cleanup_cache)


def get_cache() -> CacheManager | None:
    """Get global cache instance."""
    return _cache


def init_cache(ttl_hours: int = 24, enabled: bool = True, cache_file: Path | None = None):
    """Initialize global cache instance."""
    global _cache
    _cache = CacheManager(cache_file=cache_file, ttl_hours=ttl_hours, enabled=enabled)
    return _cache
