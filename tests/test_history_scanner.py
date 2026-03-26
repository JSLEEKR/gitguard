"""Tests for history scanner."""

import subprocess

import pytest

from gitguard.models import Rule, ScanConfig, Severity
from gitguard.scanners.history_scanner import HistoryScanner, CommitFinding


def _init_repo(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t.com"], capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "T"], capture_output=True)
    return tmp_path


def _commit(repo, filename, content, msg="add"):
    (repo / filename).write_text(content)
    subprocess.run(["git", "-C", str(repo), "add", filename], capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", msg], capture_output=True)


def _make_scanner(rules=None):
    if rules is None:
        rules = [Rule(id="secret", name="Secret", pattern=r"SECRET_\w+", severity=Severity.HIGH)]
    return HistoryScanner(ScanConfig(rules=rules))


class TestHistoryScanner:
    def test_scan_clean_history(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "a.py", "x = 1\n", "init")
        _commit(repo, "b.py", "y = 2\n", "add b")
        scanner = _make_scanner()
        result, cfindings = scanner.scan_history(str(repo), max_commits=10)
        assert not result.has_findings
        assert len(cfindings) == 0

    def test_scan_history_with_secret(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "a.py", "x = 1\n", "init")
        _commit(repo, "config.py", "SECRET_KEY = 'abc'\n", "add config")
        scanner = _make_scanner()
        result, cfindings = scanner.scan_history(str(repo), max_commits=10)
        assert result.has_findings
        assert len(cfindings) >= 1
        assert cfindings[0].commit_message == "add config"

    def test_scan_limit_commits(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "a.py", "x = 1\n", "c1")
        _commit(repo, "b.py", "SECRET_B = 1\n", "c2")
        _commit(repo, "c.py", "SECRET_C = 1\n", "c3")
        _commit(repo, "d.py", "SECRET_D = 1\n", "c4")
        scanner = _make_scanner()
        # Only scan last 2 commits
        result, _ = scanner.scan_history(str(repo), max_commits=2)
        assert result.has_findings

    def test_scan_not_git_repo(self, tmp_path):
        scanner = _make_scanner()
        result, cfindings = scanner.scan_history(str(tmp_path))
        assert not result.has_findings
        assert len(cfindings) == 0

    def test_commit_finding_has_context(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "a.py", "x = 1\n", "init")
        _commit(repo, "secret.py", "SECRET_API = 'val'\n", "add secret")
        scanner = _make_scanner()
        _, cfindings = scanner.scan_history(str(repo), max_commits=10)
        assert len(cfindings) >= 1
        cf = cfindings[0]
        assert cf.author == "T"
        assert len(cf.commit_hash) == 40

    def test_scan_timing(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "a.py", "x = 1\n", "init")
        scanner = _make_scanner()
        result, _ = scanner.scan_history(str(repo))
        assert result.scan_time_ms >= 0
