"""Tests for baseline scanner."""

import subprocess

import pytest
from pathlib import Path

from gitguard.models import Rule, ScanConfig, Severity
from gitguard.scanners.baseline_scanner import BaselineScanner


def _init_git_repo(tmp_path):
    """Initialize a git repo with some files."""
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@test.com"], capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Test"], capture_output=True)
    return tmp_path


def _commit_file(repo_path, filename, content):
    """Create and commit a file."""
    (repo_path / filename).write_text(content)
    subprocess.run(["git", "-C", str(repo_path), "add", filename], capture_output=True)
    subprocess.run(["git", "-C", str(repo_path), "commit", "-m", f"add {filename}"], capture_output=True)


def _make_scanner(rules=None):
    if rules is None:
        rules = [
            Rule(id="secret", name="Secret", pattern=r"SECRET_\w+",
                 severity=Severity.HIGH),
        ]
    config = ScanConfig(rules=rules)
    return BaselineScanner(config)


class TestBaselineScanner:
    def test_scan_clean_repo(self, tmp_path):
        repo = _init_git_repo(tmp_path)
        _commit_file(repo, "clean.py", "x = 1\n")
        scanner = _make_scanner()
        result = scanner.scan_repo(repo)
        assert not result.has_findings

    def test_scan_repo_with_secret(self, tmp_path):
        repo = _init_git_repo(tmp_path)
        _commit_file(repo, "config.py", "SECRET_KEY = 'abc'\n")
        scanner = _make_scanner()
        result = scanner.scan_repo(repo)
        assert result.has_findings
        assert result.findings[0].file_path == "config.py"

    def test_scan_multiple_files(self, tmp_path):
        repo = _init_git_repo(tmp_path)
        _commit_file(repo, "a.py", "SECRET_A = 1\n")
        _commit_file(repo, "b.py", "clean = 1\n")
        _commit_file(repo, "c.py", "SECRET_C = 3\n")
        scanner = _make_scanner()
        result = scanner.scan_repo(repo)
        assert len(result.findings) == 2
        files = {f.file_path for f in result.findings}
        assert "a.py" in files
        assert "c.py" in files

    def test_scan_not_git_repo(self, tmp_path):
        scanner = _make_scanner()
        result = scanner.scan_repo(tmp_path)
        assert not result.has_findings

    def test_scan_timing(self, tmp_path):
        repo = _init_git_repo(tmp_path)
        _commit_file(repo, "test.py", "x = 1\n")
        scanner = _make_scanner()
        result = scanner.scan_repo(repo)
        assert result.scan_time_ms >= 0

    def test_scan_subdirectory(self, tmp_path):
        repo = _init_git_repo(tmp_path)
        sub = repo / "sub"
        sub.mkdir()
        _commit_file(repo, "sub/deep.py", "SECRET_DEEP = 1\n")
        scanner = _make_scanner()
        result = scanner.scan_repo(repo)
        assert result.has_findings
