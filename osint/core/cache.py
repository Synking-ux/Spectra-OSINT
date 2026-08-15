from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path


class Cache:
    """SQLite-backed response cache. Prevents hammering rate-limited free APIs."""

    def __init__(self, path: str | Path, ttl: int = 86400, enabled: bool = True):
        self.enabled = enabled
        self.ttl = ttl
        self._conn: sqlite3.Connection | None = None
        if not enabled:
            return
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS cache "
            "(key TEXT PRIMARY KEY, created REAL, data TEXT)"
        )
        self._conn.commit()

    @staticmethod
    def _key(namespace: str, url: str, params: dict | None) -> str:
        raw = json.dumps({"ns": namespace, "url": url, "params": params or {}}, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, namespace: str, url: str, params: dict | None = None):
        if not self.enabled or self._conn is None:
            return None
        row = self._conn.execute(
            "SELECT created, data FROM cache WHERE key=?", (self._key(namespace, url, params),)
        ).fetchone()
        if not row:
            return None
        created, data = row
        if time.time() - created > self.ttl:
            return None
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return None

    def set(self, namespace: str, url: str, params: dict | None, data) -> None:
        if not self.enabled or self._conn is None:
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO cache (key, created, data) VALUES (?,?,?)",
            (self._key(namespace, url, params), time.time(), json.dumps(data)),
        )
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None