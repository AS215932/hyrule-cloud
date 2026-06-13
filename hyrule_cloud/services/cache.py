"""Small in-process TTL cache for network intelligence lookups.

This is intentionally simple: it avoids hammering public DNS/RDAP/WHOIS
providers in the first implementation. Durable DB caches land with the storage
step of the accepted plan.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")


@dataclass
class _Entry[T]:
    value: T
    expires_at: float


class TTLCache[T]:
    def __init__(self, *, max_entries: int = 4096) -> None:
        self.max_entries = max_entries
        self._values: dict[str, _Entry[T]] = {}

    def get(self, key: str) -> T | None:
        entry = self._values.get(key)
        if entry is None:
            return None
        if entry.expires_at < time.time():
            self._values.pop(key, None)
            return None
        return entry.value

    def set(self, key: str, value: T, ttl_seconds: int) -> None:
        if len(self._values) >= self.max_entries:
            # Drop a few expired entries first; if still full, evict an arbitrary
            # oldest-by-expiry entry. Good enough for bounded in-process caching.
            now = time.time()
            for k, entry in list(self._values.items()):
                if entry.expires_at < now:
                    self._values.pop(k, None)
            if len(self._values) >= self.max_entries and self._values:
                oldest = min(self._values, key=lambda k: self._values[k].expires_at)
                self._values.pop(oldest, None)
        self._values[key] = _Entry(value=value, expires_at=time.time() + ttl_seconds)

    def clear(self) -> None:
        self._values.clear()
