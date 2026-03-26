"""Pattern caching and performance utilities."""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any


class PatternCache:
    """Cache for compiled regex patterns with hit/miss tracking."""

    def __init__(self, max_size: int = 1000) -> None:
        self._cache: dict[str, re.Pattern] = {}
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def get(self, pattern: str) -> re.Pattern | None:
        """Get a compiled pattern from cache."""
        compiled = self._cache.get(pattern)
        if compiled is not None:
            self._hits += 1
        else:
            self._misses += 1
        return compiled

    def compile(self, pattern: str) -> re.Pattern | None:
        """Get or compile a pattern."""
        compiled = self._cache.get(pattern)
        if compiled is not None:
            self._hits += 1
            return compiled

        self._misses += 1
        try:
            compiled = re.compile(pattern)
        except re.error:
            return None

        if len(self._cache) >= self._max_size:
            # Evict oldest entry
            oldest = next(iter(self._cache))
            del self._cache[oldest]

        self._cache[pattern] = compiled
        return compiled

    def clear(self) -> None:
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "size": self.size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self.hit_rate, 3),
            "max_size": self._max_size,
        }


@dataclass
class ScanTimer:
    """Timer for tracking scan performance."""
    _start: float = 0.0
    _end: float = 0.0
    _checkpoints: dict[str, float] = field(default_factory=dict)

    def start(self) -> None:
        self._start = time.monotonic()

    def stop(self) -> None:
        self._end = time.monotonic()

    def checkpoint(self, name: str) -> None:
        self._checkpoints[name] = time.monotonic()

    @property
    def elapsed_ms(self) -> float:
        end = self._end if self._end > 0 else time.monotonic()
        return (end - self._start) * 1000

    @property
    def checkpoints(self) -> dict[str, float]:
        result: dict[str, float] = {}
        prev = self._start
        for name, ts in self._checkpoints.items():
            result[name] = round((ts - prev) * 1000, 2)
            prev = ts
        return result


def content_hash(content: str) -> str:
    """Generate a hash for content to enable caching."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
