"""Tests for content scanner."""

import pytest

from gitguard.models import Rule, ScanConfig, Severity
from gitguard.scanners.content_scanner import ContentScanner


def _make_config(rules=None, allowlist_patterns=None, allowlist_paths=None, min_severity=Severity.LOW):
    config = ScanConfig(
        rules=rules or [],
        allowlist_patterns=allowlist_patterns or [],
        allowlist_paths=allowlist_paths or [],
        min_severity=min_severity,
    )
    return config


def _make_rule(**kwargs):
    defaults = {
        "id": "test-rule",
        "name": "Test Rule",
        "pattern": r"SECRET_\w+",
        "severity": Severity.HIGH,
    }
    defaults.update(kwargs)
    return Rule(**defaults)


class TestContentScanner:
    def test_basic_detection(self):
        rule = _make_rule(pattern=r"SECRET_\w+")
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_text("my SECRET_KEY_123 here")
        assert result.has_findings
        assert result.findings[0].match_text == "SECRET_KEY_123"

    def test_no_match(self):
        rule = _make_rule(pattern=r"SECRET_\w+")
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_text("nothing special here")
        assert not result.has_findings

    def test_multiple_matches_same_line(self):
        rule = _make_rule(pattern=r"KEY_\w+")
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_text("KEY_ONE and KEY_TWO")
        assert len(result.findings) == 2

    def test_multiple_lines(self):
        rule = _make_rule(pattern=r"SECRET_\w+")
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        content = "line 1\nSECRET_A\nline 3\nSECRET_B"
        result = scanner.scan_text(content)
        assert len(result.findings) == 2
        assert result.findings[0].line_number == 2
        assert result.findings[1].line_number == 4

    def test_disabled_rule_skipped(self):
        rule = _make_rule(enabled=False)
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_text("SECRET_KEY")
        assert not result.has_findings

    def test_allowlist_pattern(self):
        rule = _make_rule(pattern=r"SECRET_\w+")
        config = _make_config(rules=[rule], allowlist_patterns=["EXAMPLE"])
        scanner = ContentScanner(config)
        result = scanner.scan_text("SECRET_EXAMPLE_KEY")
        assert not result.has_findings

    def test_rule_specific_allowlist(self):
        rule = _make_rule(pattern=r"KEY_\w+", allowlist=["TEST"])
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_text("KEY_TEST_123")
        assert not result.has_findings

    def test_file_pattern_matching(self):
        rule = _make_rule(pattern=r".*", file_patterns=["*.env"])
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)

        result1 = scanner.scan_text("content", ".env")
        assert result1.has_findings

        result2 = scanner.scan_text("content", "app.py")
        assert not result2.has_findings

    def test_file_pattern_basename_match(self):
        rule = _make_rule(pattern=r"secret", file_patterns=["*.py"])
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_text("secret", "src/app.py")
        assert result.has_findings

    def test_severity_filter(self):
        low_rule = _make_rule(id="low", severity=Severity.LOW)
        high_rule = _make_rule(id="high", severity=Severity.HIGH)
        config = _make_config(rules=[low_rule, high_rule], min_severity=Severity.HIGH)
        scanner = ContentScanner(config)
        result = scanner.scan_text("SECRET_VALUE")
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "high"

    def test_entropy_threshold(self):
        rule = _make_rule(
            pattern=r"[a-f0-9]{32}",
            entropy_threshold=4.0,
        )
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)

        # Low entropy (repeated pattern)
        result1 = scanner.scan_text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert not result1.has_findings

    def test_scan_lines(self):
        rule = _make_rule(pattern=r"SECRET_\w+")
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_lines(["line 1", "SECRET_ABC", "line 3"])
        assert result.has_findings

    def test_scan_result_metadata(self):
        rule = _make_rule(pattern=r"SECRET_\w+")
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_text("line1\nSECRET_X\nline3")
        assert result.files_scanned == 1
        assert result.lines_scanned == 3
        assert result.rules_applied == 1
        assert result.scan_time_ms >= 0

    def test_empty_content(self):
        rule = _make_rule()
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_text("")
        assert not result.has_findings

    def test_invalid_regex_pattern_skipped(self):
        rule = _make_rule(pattern="[invalid")
        config = _make_config(rules=[rule])
        scanner = ContentScanner(config)
        result = scanner.scan_text("anything")
        assert not result.has_findings

    def test_path_allowlist(self):
        rule = _make_rule(pattern=r"secret")
        config = _make_config(rules=[rule], allowlist_paths=["*.test.py"])
        scanner = ContentScanner(config)
        assert scanner._is_path_allowlisted("app.test.py")
        assert not scanner._is_path_allowlisted("app.py")
