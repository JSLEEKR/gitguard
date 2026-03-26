"""Tests for pattern caching and performance utilities."""

import pytest

from gitguard.cache import PatternCache, ScanTimer, content_hash


class TestPatternCache:
    def test_empty_cache(self):
        cache = PatternCache()
        assert cache.size == 0
        assert cache.get("pattern") is None

    def test_compile_and_get(self):
        cache = PatternCache()
        p = cache.compile(r"\w+")
        assert p is not None
        assert cache.size == 1
        # Should hit cache
        p2 = cache.compile(r"\w+")
        assert p2 is p

    def test_invalid_pattern(self):
        cache = PatternCache()
        p = cache.compile("[invalid")
        assert p is None

    def test_hit_miss_tracking(self):
        cache = PatternCache()
        cache.compile(r"\w+")  # miss
        cache.compile(r"\w+")  # hit
        cache.compile(r"\d+")  # miss
        assert cache._hits == 1
        assert cache._misses == 2

    def test_hit_rate(self):
        cache = PatternCache()
        cache.compile(r"\w+")
        cache.compile(r"\w+")
        assert cache.hit_rate == 0.5

    def test_hit_rate_empty(self):
        cache = PatternCache()
        assert cache.hit_rate == 0.0

    def test_max_size_eviction(self):
        cache = PatternCache(max_size=2)
        cache.compile(r"a")
        cache.compile(r"b")
        cache.compile(r"c")  # Should evict 'a'
        assert cache.size == 2
        assert cache.get(r"a") is None

    def test_clear(self):
        cache = PatternCache()
        cache.compile(r"\w+")
        cache.clear()
        assert cache.size == 0
        assert cache._hits == 0
        assert cache._misses == 0

    def test_stats(self):
        cache = PatternCache(max_size=100)
        cache.compile(r"\w+")
        cache.compile(r"\w+")
        stats = cache.stats
        assert stats["size"] == 1
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["max_size"] == 100

    def test_get_hit_tracking(self):
        cache = PatternCache()
        cache.compile(r"\w+")  # miss (first compile)
        cache.get(r"\w+")  # hit
        cache.get(r"nope")  # miss
        assert cache._hits == 1
        assert cache._misses == 2


class TestScanTimer:
    def test_basic_timing(self):
        timer = ScanTimer()
        timer.start()
        timer.stop()
        assert timer.elapsed_ms >= 0

    def test_checkpoint(self):
        timer = ScanTimer()
        timer.start()
        timer.checkpoint("phase1")
        timer.checkpoint("phase2")
        timer.stop()
        cps = timer.checkpoints
        assert "phase1" in cps
        assert "phase2" in cps

    def test_elapsed_without_stop(self):
        timer = ScanTimer()
        timer.start()
        # No stop - should still return elapsed
        assert timer.elapsed_ms >= 0


class TestContentHash:
    def test_deterministic(self):
        h1 = content_hash("hello")
        h2 = content_hash("hello")
        assert h1 == h2

    def test_different_content(self):
        h1 = content_hash("hello")
        h2 = content_hash("world")
        assert h1 != h2

    def test_length(self):
        h = content_hash("test")
        assert len(h) == 16

    def test_empty_string(self):
        h = content_hash("")
        assert len(h) == 16
