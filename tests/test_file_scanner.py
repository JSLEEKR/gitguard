"""Tests for file scanner."""

import pytest
from pathlib import Path

from gitguard.models import Rule, ScanConfig, Severity
from gitguard.scanners.file_scanner import FileScanner, BINARY_EXTENSIONS, SKIP_DIRS


def _make_scanner(rules=None, allowlist_paths=None, max_file_size_kb=500):
    if rules is None:
        rules = [
            Rule(id="secret", name="Secret", pattern=r"SECRET_\w+",
                 severity=Severity.HIGH),
            Rule(id="key", name="Key", pattern=r"-----BEGIN.*PRIVATE KEY-----",
                 severity=Severity.CRITICAL),
        ]
    config = ScanConfig(
        rules=rules,
        allowlist_paths=allowlist_paths or [],
        max_file_size_kb=max_file_size_kb,
    )
    return FileScanner(config)


class TestFileScanner:
    def test_scan_file_with_secret(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text('SECRET_KEY = "abc123"')
        scanner = _make_scanner()
        result = scanner.scan_file(f)
        assert result.has_findings

    def test_scan_file_no_secret(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("x = 1\ny = 2")
        scanner = _make_scanner()
        result = scanner.scan_file(f)
        assert not result.has_findings

    def test_scan_nonexistent_file(self):
        scanner = _make_scanner()
        result = scanner.scan_file("/nonexistent/file.py")
        assert not result.has_findings

    def test_scan_binary_file_skipped(self, tmp_path):
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG SECRET_KEY")
        scanner = _make_scanner()
        result = scanner.scan_file(f)
        assert result.files_scanned == 0

    def test_scan_large_file_skipped(self, tmp_path):
        f = tmp_path / "big.py"
        f.write_text("SECRET_KEY\n" * 100000)
        scanner = _make_scanner(max_file_size_kb=1)
        result = scanner.scan_file(f)
        assert result.files_scanned == 0

    def test_scan_directory(self, tmp_path):
        (tmp_path / "a.py").write_text("SECRET_A = 1")
        (tmp_path / "b.py").write_text("SECRET_B = 2")
        (tmp_path / "clean.py").write_text("x = 1")
        scanner = _make_scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.files_scanned == 3
        assert len(result.findings) == 2

    def test_scan_directory_recursive(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "deep.py").write_text("SECRET_DEEP = 1")
        scanner = _make_scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.has_findings

    def test_scan_directory_skips_git(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("SECRET_GIT = 1")
        scanner = _make_scanner()
        result = scanner.scan_directory(tmp_path)
        assert not result.has_findings

    def test_scan_directory_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "pkg.js").write_text("SECRET_PKG = 1")
        scanner = _make_scanner()
        result = scanner.scan_directory(tmp_path)
        assert not result.has_findings

    def test_scan_nonexistent_directory(self):
        scanner = _make_scanner()
        result = scanner.scan_directory("/nonexistent/dir")
        assert not result.has_findings

    def test_allowlisted_path(self, tmp_path):
        f = tmp_path / "test_config.py"
        f.write_text("SECRET_KEY = 1")
        scanner = _make_scanner(allowlist_paths=["test_*"])
        result = scanner.scan_file(f)
        assert result.files_scanned == 0

    def test_scan_not_a_file(self, tmp_path):
        scanner = _make_scanner()
        result = scanner.scan_file(tmp_path)  # Directory, not file
        assert not result.has_findings


class TestBinaryExtensions:
    def test_common_image_formats(self):
        assert ".png" in BINARY_EXTENSIONS
        assert ".jpg" in BINARY_EXTENSIONS
        assert ".gif" in BINARY_EXTENSIONS

    def test_common_archive_formats(self):
        assert ".zip" in BINARY_EXTENSIONS
        assert ".gz" in BINARY_EXTENSIONS
        assert ".tar" in BINARY_EXTENSIONS

    def test_executable_formats(self):
        assert ".exe" in BINARY_EXTENSIONS
        assert ".dll" in BINARY_EXTENSIONS


class TestSkipDirs:
    def test_git_dir(self):
        assert ".git" in SKIP_DIRS

    def test_node_modules(self):
        assert "node_modules" in SKIP_DIRS

    def test_pycache(self):
        assert "__pycache__" in SKIP_DIRS

    def test_venv(self):
        assert ".venv" in SKIP_DIRS
        assert "venv" in SKIP_DIRS
