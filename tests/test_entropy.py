"""Tests for entropy calculation."""

import pytest

from gitguard.entropy import (
    base64_entropy,
    extract_high_entropy_strings,
    hex_entropy,
    is_high_entropy,
    shannon_entropy,
)


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("a") == 0.0

    def test_repeated_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self):
        e = shannon_entropy("ab")
        assert abs(e - 1.0) < 0.01

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        e = shannon_entropy("aB3$xY9@kL7!")
        assert e > 3.0

    def test_low_entropy(self):
        e = shannon_entropy("aaaaabbbbb")
        assert e < 2.0

    def test_all_unique(self):
        e = shannon_entropy("abcdefghij")
        assert e > 3.0


class TestHexEntropy:
    def test_no_hex(self):
        assert hex_entropy("hello world") == 0.0

    def test_short_hex(self):
        assert hex_entropy("abc123") == 0.0  # Too short

    def test_long_hex(self):
        e = hex_entropy("a1b2c3d4e5f6a7b8c9d0")
        assert e > 0.0

    def test_hex_in_context(self):
        e = hex_entropy("key = a1b2c3d4e5f6a7b8c9d0e1f2a3b4")
        assert e > 0.0


class TestBase64Entropy:
    def test_no_base64(self):
        assert base64_entropy("short") == 0.0

    def test_base64_string(self):
        e = base64_entropy("token = SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q=")
        assert e > 0.0


class TestIsHighEntropy:
    def test_short_string(self):
        assert is_high_entropy("abc") is False

    def test_low_entropy(self):
        assert is_high_entropy("aaaaaaaaaa") is False

    def test_high_entropy(self):
        # Use a truly random-looking string with more character variety
        assert is_high_entropy("aB3$xY9@kL7!mN2#pQ5%rS8&tU") is True

    def test_custom_threshold(self):
        s = "abcdefghij"
        assert is_high_entropy(s, threshold=2.0) is True
        assert is_high_entropy(s, threshold=5.0) is False


class TestExtractHighEntropyStrings:
    def test_empty_line(self):
        assert extract_high_entropy_strings("") == []

    def test_no_high_entropy(self):
        assert extract_high_entropy_strings("normal text here") == []

    def test_with_high_entropy(self):
        line = "key = aB3xY9kL7mN2pQ5rS"
        results = extract_high_entropy_strings(line, min_length=16, threshold=3.5)
        assert len(results) >= 1

    def test_custom_min_length(self):
        line = "x = aB3xY9kL7"
        # With default min_length=16, this shouldn't match
        results = extract_high_entropy_strings(line, min_length=16)
        assert len(results) == 0
