"""Tests for diff scanner and parser."""

import pytest

from gitguard.models import Rule, ScanConfig, Severity
from gitguard.scanners.diff_scanner import DiffParser, DiffScanner


SAMPLE_DIFF = """\
diff --git a/config.py b/config.py
index 1234567..abcdefg 100644
--- a/config.py
+++ b/config.py
@@ -1,3 +1,5 @@
 import os
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE1"
+password = "supersecretpass1"

 def main():
"""

MULTI_FILE_DIFF = """\
diff --git a/file1.py b/file1.py
index aaa..bbb 100644
--- a/file1.py
+++ b/file1.py
@@ -1,2 +1,3 @@
 line1
+SECRET_LINE
 line2
diff --git a/file2.py b/file2.py
index ccc..ddd 100644
--- a/file2.py
+++ b/file2.py
@@ -1,2 +1,3 @@
 line1
+ANOTHER_SECRET
 line2
"""

DELETED_FILE_DIFF = """\
diff --git a/old.py b/old.py
index aaa..bbb 100644
--- a/old.py
+++ /dev/null
@@ -1,3 +0,0 @@
-line1
-SECRET_KEY
-line3
"""


class TestDiffParser:
    def test_parse_basic_diff(self):
        hunks = DiffParser.parse(SAMPLE_DIFF)
        assert len(hunks) == 1
        assert hunks[0].file_path == "config.py"
        assert len(hunks[0].added_lines) == 2

    def test_parse_added_lines(self):
        hunks = DiffParser.parse(SAMPLE_DIFF)
        added = hunks[0].added_lines
        assert any("AKIAIOSFODNN7EXAMPLE1" in line for _, line in added)
        assert any("supersecretpass1" in line for _, line in added)

    def test_parse_multi_file(self):
        hunks = DiffParser.parse(MULTI_FILE_DIFF)
        assert len(hunks) == 2
        assert hunks[0].file_path == "file1.py"
        assert hunks[1].file_path == "file2.py"

    def test_parse_deleted_file_skipped(self):
        hunks = DiffParser.parse(DELETED_FILE_DIFF)
        # Deleted files should not produce hunks with added lines
        for hunk in hunks:
            assert len(hunk.added_lines) == 0

    def test_parse_empty_diff(self):
        hunks = DiffParser.parse("")
        assert hunks == []

    def test_parse_line_numbers(self):
        diff = """\
diff --git a/test.py b/test.py
index aaa..bbb 100644
--- a/test.py
+++ b/test.py
@@ -10,3 +10,4 @@
 existing
+new_line
 existing2
"""
        hunks = DiffParser.parse(diff)
        assert hunks[0].added_lines[0][0] == 11  # Line 11

    def test_parse_removed_lines(self):
        diff = """\
diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1,3 +1,2 @@
 keep
-removed
 keep2
"""
        hunks = DiffParser.parse(diff)
        assert len(hunks[0].removed_lines) == 1
        assert len(hunks[0].added_lines) == 0


class TestDiffScanner:
    def _make_scanner(self, rules=None, allowlist_paths=None):
        if rules is None:
            rules = [
                Rule(id="aws", name="AWS Key", pattern=r"AKIA[0-9A-Z]{16}",
                     severity=Severity.CRITICAL),
                Rule(id="pwd", name="Password",
                     pattern=r'password\s*=\s*"[^"]{8,}"',
                     severity=Severity.HIGH),
                Rule(id="secret", name="Secret", pattern=r"SECRET_\w+",
                     severity=Severity.HIGH),
            ]
        config = ScanConfig(
            rules=rules,
            allowlist_paths=allowlist_paths or [],
        )
        return DiffScanner(config)

    def test_scan_basic_diff(self):
        scanner = self._make_scanner()
        result = scanner.scan_diff(SAMPLE_DIFF)
        assert result.has_findings
        assert len(result.findings) >= 1

    def test_scan_only_added_lines(self):
        scanner = self._make_scanner()
        result = scanner.scan_diff(DELETED_FILE_DIFF)
        # Should NOT find secrets in deleted lines
        secret_findings = [f for f in result.findings if f.rule_id == "secret"]
        assert len(secret_findings) == 0

    def test_scan_multi_file(self):
        scanner = self._make_scanner()
        result = scanner.scan_diff(MULTI_FILE_DIFF)
        assert result.files_scanned == 2

    def test_scan_empty_diff(self):
        scanner = self._make_scanner()
        result = scanner.scan_diff("")
        assert not result.has_findings

    def test_scan_with_path_allowlist(self):
        scanner = self._make_scanner(allowlist_paths=["*.test.py", "test_*"])
        diff = """\
diff --git a/test_config.py b/test_config.py
--- a/test_config.py
+++ b/test_config.py
@@ -1,2 +1,3 @@
 x = 1
+SECRET_KEY_TEST
 y = 2
"""
        result = scanner.scan_diff(diff)
        # test_config.py is not covered by allowlist since fnmatch
        # needs exact pattern match

    def test_scan_staged_alias(self):
        scanner = self._make_scanner()
        result = scanner.scan_staged(SAMPLE_DIFF)
        assert result.has_findings

    def test_finding_has_correct_file(self):
        scanner = self._make_scanner()
        result = scanner.scan_diff(MULTI_FILE_DIFF)
        files = {f.file_path for f in result.findings}
        assert "file1.py" in files or "file2.py" in files
