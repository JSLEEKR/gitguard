"""Tests for inline suppression comments."""

import pytest

from gitguard.suppression import SuppressionMap, parse_suppressions


class TestSuppressionMap:
    def test_empty_map(self):
        smap = SuppressionMap()
        assert not smap.is_suppressed(1, "any-rule")
        assert smap.total_suppressions == 0

    def test_suppress_all_rules(self):
        smap = SuppressionMap(suppressed_lines={5: set()})
        assert smap.is_suppressed(5, "any-rule")
        assert smap.is_suppressed(5, "other-rule")

    def test_suppress_specific_rule(self):
        smap = SuppressionMap(suppressed_lines={5: {"rule-a"}})
        assert smap.is_suppressed(5, "rule-a")
        assert not smap.is_suppressed(5, "rule-b")

    def test_suppress_multiple_rules(self):
        smap = SuppressionMap(suppressed_lines={5: {"rule-a", "rule-b"}})
        assert smap.is_suppressed(5, "rule-a")
        assert smap.is_suppressed(5, "rule-b")
        assert not smap.is_suppressed(5, "rule-c")

    def test_unsuppressed_line(self):
        smap = SuppressionMap(suppressed_lines={5: set()})
        assert not smap.is_suppressed(6, "any-rule")

    def test_total_suppressions(self):
        smap = SuppressionMap(suppressed_lines={1: set(), 5: {"r1"}, 10: {"r2"}})
        assert smap.total_suppressions == 3


class TestParseSuppression:
    def test_disable_all(self):
        content = 'SECRET_KEY = "abc"  # gitguard:disable'
        smap = parse_suppressions(content)
        assert smap.is_suppressed(1, "generic-secret")
        assert smap.is_suppressed(1, "any-rule")

    def test_disable_specific(self):
        content = 'SECRET_KEY = "abc"  # gitguard:disable=generic-secret'
        smap = parse_suppressions(content)
        assert smap.is_suppressed(1, "generic-secret")
        assert not smap.is_suppressed(1, "other-rule")

    def test_disable_multiple_rules(self):
        content = 'x = "abc"  # gitguard:disable=rule-a,rule-b'
        smap = parse_suppressions(content)
        assert smap.is_suppressed(1, "rule-a")
        assert smap.is_suppressed(1, "rule-b")
        assert not smap.is_suppressed(1, "rule-c")

    def test_disable_next_line(self):
        content = "# gitguard:disable-next-line\nSECRET_KEY = 'abc'"
        smap = parse_suppressions(content)
        assert not smap.is_suppressed(1, "any")
        assert smap.is_suppressed(2, "any")

    def test_disable_next_line_specific(self):
        content = "# gitguard:disable-next-line=generic-secret\nSECRET = 'abc'"
        smap = parse_suppressions(content)
        assert smap.is_suppressed(2, "generic-secret")
        assert not smap.is_suppressed(2, "other")

    def test_no_suppression(self):
        content = "# Normal comment\nx = 1"
        smap = parse_suppressions(content)
        assert smap.total_suppressions == 0

    def test_multiple_suppressions(self):
        content = "line1  # gitguard:disable\nline2\nline3  # gitguard:disable=rule-x"
        smap = parse_suppressions(content)
        assert smap.is_suppressed(1, "any")
        assert not smap.is_suppressed(2, "any")
        assert smap.is_suppressed(3, "rule-x")

    def test_whitespace_variations(self):
        content = 'x = 1  #  gitguard:disable  '
        smap = parse_suppressions(content)
        assert smap.is_suppressed(1, "any")

    def test_disable_next_line_at_end_of_file(self):
        content = "# gitguard:disable-next-line"
        smap = parse_suppressions(content)
        # No next line, so no suppression
        assert smap.total_suppressions == 0

    def test_empty_content(self):
        smap = parse_suppressions("")
        assert smap.total_suppressions == 0

    def test_complex_file(self):
        content = """import os

# gitguard:disable-next-line=generic-password
PASSWORD = "test_password_123"

API_KEY = "sk_test_1234"  # gitguard:disable=generic-secret

CLEAN_VAR = "hello"
"""
        smap = parse_suppressions(content)
        assert smap.is_suppressed(4, "generic-password")
        assert not smap.is_suppressed(4, "other-rule")
        assert smap.is_suppressed(6, "generic-secret")
        assert not smap.is_suppressed(8, "any")
