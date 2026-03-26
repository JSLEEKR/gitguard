"""Tests for parallel scanning."""

import pytest
from pathlib import Path

from gitguard.models import Rule, ScanConfig, Severity
from gitguard.parallel import ParallelScanner


def _make_scanner(rules=None, workers=2):
    if rules is None:
        rules = [Rule(id="secret", name="Secret", pattern=r"SECRET_\w+", severity=Severity.HIGH)]
    return ParallelScanner(ScanConfig(rules=rules), max_workers=workers)


class TestParallelScanner:
    def test_scan_single_file(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("SECRET_KEY = 1\n")
        scanner = _make_scanner()
        result = scanner.scan_files([f])
        assert result.has_findings

    def test_scan_multiple_files(self, tmp_path):
        for i in range(5):
            (tmp_path / f"file{i}.py").write_text(f"SECRET_{i} = {i}\n")
        scanner = _make_scanner()
        files = list(tmp_path.glob("*.py"))
        result = scanner.scan_files(files)
        assert len(result.findings) == 5

    def test_scan_clean_files(self, tmp_path):
        for i in range(3):
            (tmp_path / f"clean{i}.py").write_text(f"x = {i}\n")
        scanner = _make_scanner()
        files = list(tmp_path.glob("*.py"))
        result = scanner.scan_files(files)
        assert not result.has_findings

    def test_scan_directory(self, tmp_path):
        (tmp_path / "a.py").write_text("SECRET_A = 1\n")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "b.py").write_text("SECRET_B = 2\n")
        scanner = _make_scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 2

    def test_scan_empty_list(self):
        scanner = _make_scanner()
        result = scanner.scan_files([])
        assert not result.has_findings

    def test_scan_nonexistent_dir(self):
        scanner = _make_scanner()
        result = scanner.scan_directory("/nonexistent")
        assert not result.has_findings

    def test_timing(self, tmp_path):
        (tmp_path / "test.py").write_text("x = 1\n")
        scanner = _make_scanner()
        result = scanner.scan_files([tmp_path / "test.py"])
        assert result.scan_time_ms >= 0

    def test_mixed_files(self, tmp_path):
        (tmp_path / "secret.py").write_text("SECRET_KEY = 1\n")
        (tmp_path / "clean.py").write_text("x = 1\n")
        (tmp_path / "image.png").write_bytes(b"\x89PNG")
        scanner = _make_scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1

    def test_workers_parameter(self, tmp_path):
        (tmp_path / "test.py").write_text("SECRET_A = 1\n")
        scanner = _make_scanner(workers=1)
        result = scanner.scan_directory(tmp_path)
        assert result.has_findings

    def test_skips_git_directory(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("SECRET_GIT = 1\n")
        (tmp_path / "app.py").write_text("x = 1\n")
        scanner = _make_scanner()
        result = scanner.scan_directory(tmp_path)
        assert not result.has_findings
