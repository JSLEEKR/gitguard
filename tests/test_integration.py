"""Integration tests for end-to-end scanning workflows."""

import subprocess

import pytest

from gitguard.config import load_config
from gitguard.models import ScanConfig, Severity
from gitguard.rules.builtin import get_builtin_rules
from gitguard.scanners.content_scanner import ContentScanner
from gitguard.scanners.diff_scanner import DiffScanner
from gitguard.scanners.file_scanner import FileScanner
from gitguard.filters import apply_filters
from gitguard.escalation import escalate_findings, calculate_risk_level
from gitguard.suggestions import suggest_fix
from gitguard.report import ScanReport


class TestEndToEndContentScan:
    """Full scan pipeline: content -> filter -> escalate -> suggest -> report."""

    def _get_config(self):
        config = ScanConfig(rules=get_builtin_rules())
        return config

    def test_full_pipeline_with_secrets(self):
        config = self._get_config()
        scanner = ContentScanner(config)

        content = '''
import os

AWS_KEY = "AKIA1234567890ABCDEF"
password = "supersecretpassword1"
DATABASE_URL = "postgres://user:pass@host:5432/db"
clean_var = "hello world"
'''
        result = scanner.scan_text(content, "config.py")

        # Should find secrets
        assert result.has_findings
        assert len(result.findings) >= 2

        # Apply filters
        filtered = apply_filters(result, min_severity=Severity.HIGH)
        assert filtered.has_findings

        # Escalate
        escalate_findings(filtered.findings)

        # Calculate risk
        risk = calculate_risk_level(filtered.findings)
        assert risk in ("critical", "high", "medium")

        # Generate suggestions
        for finding in filtered.findings:
            s = suggest_fix(finding)
            assert s.action in ("use_env_var", "use_aws_config", "review", "add_to_gitignore", "remove")

        # Generate report
        report = ScanReport(project_name="test")
        report.add_result(filtered)
        assert report.pass_fail == "FAIL"
        assert report.total_findings >= 2

        # Export formats
        md = report.to_markdown()
        assert "FAIL" in md

        j = report.to_json()
        assert "test" in j

    def test_full_pipeline_clean_file(self):
        config = self._get_config()
        scanner = ContentScanner(config)
        content = "x = 1\ny = 2\ndef hello(): pass\n"
        result = scanner.scan_text(content)
        assert not result.has_findings

        report = ScanReport()
        report.add_result(result)
        assert report.pass_fail == "PASS"

    def test_scan_with_suppression(self):
        config = self._get_config()
        scanner = ContentScanner(config)

        # Content with suppression comment
        content = 'password = "test_fake_password"  # gitguard:disable\n'
        result = scanner.scan_text(content)

        # Scanner doesn't check suppressions; that's handled by a wrapper
        # But let's verify the finding exists
        # (In a full pipeline, suppression would filter it out)
        from gitguard.suppression import parse_suppressions
        smap = parse_suppressions(content)
        assert smap.is_suppressed(1, "generic-password")


class TestEndToEndDiffScan:
    def test_diff_with_mixed_content(self):
        config = ScanConfig(rules=get_builtin_rules())
        scanner = DiffScanner(config)

        diff = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,6 @@
 import os
+password = "mysupersecretpwd"
+clean_line = "hello"
+-----BEGIN RSA PRIVATE KEY-----
+JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
 def main():
"""
        result = scanner.scan_diff(diff)
        assert result.has_findings
        assert len(result.findings) >= 2

        # Check severity distribution
        severities = {f.severity for f in result.findings}
        assert Severity.CRITICAL in severities or Severity.HIGH in severities


class TestEndToEndFileScan:
    def test_scan_project_structure(self, tmp_path):
        # Create a realistic project structure
        src = tmp_path / "src"
        src.mkdir()
        tests = tmp_path / "tests"
        tests.mkdir()

        (src / "app.py").write_text('API_KEY = "sk_test_1234567890abcdefghij"\n')
        (src / "utils.py").write_text("def helper(): pass\n")
        (tests / "test_app.py").write_text("def test_it(): assert True\n")
        (tmp_path / ".env").write_text("SECRET=abc\n")

        config = ScanConfig(rules=get_builtin_rules())
        scanner = FileScanner(config)
        result = scanner.scan_directory(tmp_path)

        assert result.files_scanned >= 3
        # Should find at least the stripe key and .env file
        assert result.has_findings

    def test_scan_empty_project(self, tmp_path):
        config = ScanConfig(rules=get_builtin_rules())
        scanner = FileScanner(config)
        result = scanner.scan_directory(tmp_path)
        assert not result.has_findings


class TestEndToEndGitScan:
    def test_full_git_workflow(self, tmp_path):
        # Initialize repo
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t.com"], capture_output=True)
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "T"], capture_output=True)

        # Create initial commit
        (tmp_path / "init.py").write_text("x = 1\n")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], capture_output=True)
        subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "init"], capture_output=True)

        # Stage a file with secrets
        (tmp_path / "config.py").write_text('password = "supersecretpassword1"\n')
        subprocess.run(["git", "-C", str(tmp_path), "add", "config.py"], capture_output=True)

        # Scan staged changes
        from gitguard.git import Git
        git = Git(tmp_path)
        diff = git.staged_diff()

        config = ScanConfig(rules=get_builtin_rules())
        scanner = DiffScanner(config)
        result = scanner.scan_diff(diff)

        assert result.has_findings
        assert any(f.rule_id == "generic-password" for f in result.findings)


class TestRuleCategories:
    """Verify all rule categories are covered."""

    def test_aws_category(self):
        rules = get_builtin_rules()
        aws = [r for r in rules if r.category == "aws"]
        assert len(aws) >= 2

    def test_credentials_category(self):
        rules = get_builtin_rules()
        creds = [r for r in rules if r.category == "credentials"]
        assert len(creds) >= 1

    def test_tokens_category(self):
        rules = get_builtin_rules()
        tokens = [r for r in rules if r.category == "tokens"]
        assert len(tokens) >= 3

    def test_keys_category(self):
        rules = get_builtin_rules()
        keys = [r for r in rules if r.category == "keys"]
        assert len(keys) >= 2

    def test_database_category(self):
        rules = get_builtin_rules()
        db = [r for r in rules if r.category == "database"]
        assert len(db) >= 1

    def test_files_category(self):
        rules = get_builtin_rules()
        files = [r for r in rules if r.category == "files"]
        assert len(files) >= 1

    def test_total_builtin_rules(self):
        rules = get_builtin_rules()
        assert len(rules) >= 20
