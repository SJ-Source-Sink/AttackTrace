"""Caching layer for crawler results."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class CrawlerCache:
    """SQLite-based cache for crawler results."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        default_ttl: timedelta = timedelta(days=7)
    ):
        self.cache_dir = cache_dir or Path.home() / ".apkanalyzer" / "cache"
        self.default_ttl = default_ttl
        self.db_path = self.cache_dir / "crawler_cache.db"

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    source TEXT,
                    created_at TEXT,
                    expires_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON cache(expires_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON cache(source)")

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?",
                (key,)
            )
            row = cursor.fetchone()

            if row is None:
                return None

            expires_at = datetime.fromisoformat(row[1])
            if datetime.utcnow() > expires_at:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                return None

            try:
                return json.loads(row[0])
            except json.JSONDecodeError:
                return row[0]

    def set(
        self,
        key: str,
        value: Any,
        source: str = "",
        ttl: Optional[timedelta] = None
    ) -> None:
        """Cache a value."""
        ttl = ttl or self.default_ttl
        expires_at = datetime.utcnow() + ttl

        if isinstance(value, (dict, list)):
            value_str = json.dumps(value)
        else:
            value_str = str(value)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cache (key, value, source, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (key, value_str, source, datetime.utcnow().isoformat(), expires_at.isoformat())
            )

    def delete(self, key: str) -> bool:
        """Delete a cached value."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            return cursor.rowcount > 0

    def exists(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        return self.get(key) is not None

    def url_key(self, url: str) -> str:
        """Generate cache key from URL."""
        return hashlib.sha256(url.encode()).hexdigest()

    def cleanup_expired(self) -> int:
        """Remove expired entries."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM cache WHERE expires_at < ?",
                (datetime.utcnow().isoformat(),)
            )
            deleted = cursor.rowcount
            logger.info(f"Cleaned up {deleted} expired cache entries")
            return deleted

    def clear_source(self, source: str) -> int:
        """Clear all cache entries from a specific source."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM cache WHERE source = ?",
                (source,)
            )
            return cursor.rowcount

    def clear_all(self) -> int:
        """Clear entire cache."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM cache")
            return cursor.rowcount

    def stats(self) -> dict:
        """Get cache statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM cache WHERE expires_at < ?",
                (datetime.utcnow().isoformat(),)
            ).fetchone()[0]

            sources = {}
            for row in conn.execute("SELECT source, COUNT(*) FROM cache GROUP BY source"):
                sources[row[0] or "unknown"] = row[1]

            return {
                "total_entries": total,
                "expired_entries": expired,
                "valid_entries": total - expired,
                "by_source": sources,
                "db_path": str(self.db_path),
            }
