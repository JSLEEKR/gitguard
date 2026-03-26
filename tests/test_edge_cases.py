"""Edge case tests for various components."""

import pytest

from gitguard.models import Finding, Rule, ScanConfig, ScanResult, Severity
from gitguard.scanners.content_scanner import ContentScanner
from gitguard.scanners.diff_scanner import DiffParser, DiffScanner
from gitguard.entropy import shannon_entropy
from gitguard.formatters.text import TextFormatter
from gitguard.formatters.json_fmt import JsonFormatter


class TestContentScannerEdgeCases:
    def test_unicode_content(self):
        rule = Rule(id="t", name="T", pattern=r"SECRET_\w+", severity=Severity.HIGH)
        scanner = ContentScanner(ScanConfig(rules=[rule]))
        result = scanner.scan_text("unicode: \u00e9\u00e0\u00fc\nSECRET_KEY = 1\n\u4e16\u754c")
        assert result.has_findings

    def test_very_long_line(self):
        rule = Rule(id="t", name="T", pattern=r"SECRET_\w+", severity=Severity.HIGH)
        scanner = ContentScanner(ScanConfig(rules=[rule]))
        long_line = "x" * 10000 + " SECRET_KEY " + "y" * 10000
        result = scanner.scan_text(long_line)
        assert result.has_findings

    def test_binary_like_content(self):
        rule = Rule(id="t", name="T", pattern=r"SECRET_\w+", severity=Severity.HIGH)
        scanner = ContentScanner(ScanConfig(rules=[rule]))
        # Content with null-like characters
        result = scanner.scan_text("some\x00binary\x00content")
        assert not result.has_findings

    def test_empty_pattern_rule(self):
        rule = Rule(id="t", name="T", pattern="", severity=Severity.HIGH)
        scanner = ContentScanner(ScanConfig(rules=[rule]))
        result = scanner.scan_text("anything")
        # Empty pattern matches everything
        assert result.has_findings

    def test_multiple_rules_same_line(self):
        rules = [
            Rule(id="r1", name="R1", pattern=r"KEY_\w+", severity=Severity.HIGH),
            Rule(id="r2", name="R2", pattern=r"SECRET_\w+", severity=Severity.CRITICAL),
        ]
        scanner = ContentScanner(ScanConfig(rules=rules))
        result = scanner.scan_text("KEY_ABC SECRET_XYZ")
        assert len(result.findings) >= 2

    def test_overlapping_matches(self):
        rule = Rule(id="t", name="T", pattern=r"\w{5}", severity=Severity.HIGH)
        scanner = ContentScanner(ScanConfig(rules=[rule]))
        result = scanner.scan_text("abcdefghij")
        assert result.has_findings

    def test_windows_line_endings(self):
        rule = Rule(id="t", name="T", pattern=r"SECRET_\w+", severity=Severity.HIGH)
        scanner = ContentScanner(ScanConfig(rules=[rule]))
        result = scanner.scan_text("line1\r\nSECRET_KEY\r\nline3")
        assert result.has_findings


class TestDiffParserEdgeCases:
    def test_no_newline_at_eof(self):
        diff = """\
diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1 +1,2 @@
 existing
+new_line
\\ No newline at end of file"""
        hunks = DiffParser.parse(diff)
        assert len(hunks) == 1

    def test_renamed_file(self):
        diff = """\
diff --git a/old.py b/new.py
similarity index 90%
rename from old.py
rename to new.py
--- a/old.py
+++ b/new.py
@@ -1,2 +1,3 @@
 existing
+added_line
 other"""
        hunks = DiffParser.parse(diff)
        assert hunks[0].file_path == "new.py"

    def test_empty_hunk(self):
        diff = """\
diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1,3 +1,3 @@
 line1
 line2
 line3"""
        hunks = DiffParser.parse(diff)
        assert len(hunks) == 1
        assert len(hunks[0].added_lines) == 0

    def test_multiple_hunks_same_file(self):
        diff = """\
diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1,2 +1,3 @@
 line1
+added1
 line2
@@ -10,2 +11,3 @@
 line10
+added2
 line11"""
        hunks = DiffParser.parse(diff)
        assert len(hunks) == 2
        assert hunks[0].file_path == "test.py"
        assert hunks[1].file_path == "test.py"


class TestEntropyEdgeCases:
    def test_single_character_types(self):
        # All same character
        assert shannon_entropy("0000000000") == 0.0

    def test_maximum_entropy(self):
        # Each character unique
        import string
        chars = string.printable[:16]
        e = shannon_entropy(chars)
        assert e == 4.0  # log2(16) = 4.0

    def test_very_long_string(self):
        s = "abcdefghij" * 1000
        e = shannon_entropy(s)
        assert e > 0


class TestFormatterEdgeCases:
    def test_text_formatter_empty_description(self):
        fmt = TextFormatter(use_color=False, verbose=True)
        f = Finding(
            rule_id="t", rule_name="T", severity=Severity.HIGH,
            file_path="f", line_number=1, line_content="x",
            match_text="y", description="",
        )
        result = ScanResult(findings=[f])
        output = fmt.format(result)
        # Should not crash with empty description
        assert "T" in output

    def test_json_formatter_special_chars(self):
        fmt = JsonFormatter()
        f = Finding(
            rule_id="t", rule_name='Test "Rule"', severity=Severity.HIGH,
            file_path="path/with spaces/file.py", line_number=1,
            line_content='content "with" quotes', match_text="secret",
        )
        result = ScanResult(findings=[f])
        output = fmt.format(result)
        import json
        data = json.loads(output)  # Should not raise
        assert len(data["findings"]) == 1

    def test_text_many_findings(self):
        fmt = TextFormatter(use_color=False)
        findings = [
            Finding(
                rule_id=f"r{i}", rule_name=f"Rule {i}", severity=Severity.HIGH,
                file_path=f"file{i}.py", line_number=i, line_content="x",
                match_text="secret",
            )
            for i in range(50)
        ]
        result = ScanResult(findings=findings)
        output = fmt.format(result)
        assert "50 potential secret" in output


class TestScanResultEdgeCases:
    def test_summary_no_findings(self):
        r = ScanResult()
        s = r.summary()
        assert s["total_findings"] == 0
        assert s["by_severity"] == {}

    def test_risk_score_mixed(self):
        findings = [
            Finding(rule_id="a", rule_name="A", severity=Severity.CRITICAL,
                    file_path="f", line_number=1, line_content="x", match_text="y"),
            Finding(rule_id="b", rule_name="B", severity=Severity.INFO,
                    file_path="f", line_number=2, line_content="x", match_text="y"),
        ]
        r = ScanResult(findings=findings)
        assert r.risk_score == 11  # 10 + 1


class TestFindingEdgeCases:
    def test_mask_exactly_8_chars(self):
        f = Finding(
            rule_id="t", rule_name="T", severity=Severity.LOW,
            file_path="f", line_number=1, line_content="x",
            match_text="12345678",
        )
        assert f.masked_match == "********"

    def test_mask_9_chars(self):
        f = Finding(
            rule_id="t", rule_name="T", severity=Severity.LOW,
            file_path="f", line_number=1, line_content="x",
            match_text="123456789",
        )
        assert f.masked_match.startswith("1234")
        assert f.masked_match.endswith("6789")

    def test_custom_masked_match(self):
        f = Finding(
            rule_id="t", rule_name="T", severity=Severity.LOW,
            file_path="f", line_number=1, line_content="x",
            match_text="secret", masked_match="[REDACTED]",
        )
        assert f.masked_match == "[REDACTED]"
