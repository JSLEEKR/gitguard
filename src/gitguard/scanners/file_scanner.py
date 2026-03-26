"""File scanner - scans individual files and directories for secrets."""

from __future__ import annotations

import fnmatch
import time
from pathlib import Path

from gitguard.models import Finding, ScanConfig, ScanResult
from gitguard.scanners.content_scanner import ContentScanner


# Binary file extensions to skip
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".gz", ".tar", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class", ".o", ".obj",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".sqlite", ".db",
}

# Directories to always skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".eggs", "*.egg-info", ".next", ".nuxt",
}


class FileScanner:
    """Scans files and directories for secrets."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.content_scanner = ContentScanner(self.config)

    def scan_file(self, file_path: str | Path) -> ScanResult:
        """Scan a single file for secrets."""
        start = time.monotonic()
        path = Path(file_path)

        if not path.exists():
            return ScanResult()

        if not path.is_file():
            return ScanResult()

        if self._should_skip_file(path):
            return ScanResult(files_scanned=0)

        # Check file size
        size_kb = path.stat().st_size / 1024
        if size_kb > self.config.max_file_size_kb:
            return ScanResult(files_scanned=0)

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return ScanResult(files_scanned=0)

        result = self.content_scanner.scan_text(content, str(path))
        result.scan_time_ms = (time.monotonic() - start) * 1000
        return result

    def scan_directory(self, dir_path: str | Path) -> ScanResult:
        """Scan all files in a directory recursively."""
        start = time.monotonic()
        path = Path(dir_path)

        if not path.exists() or not path.is_dir():
            return ScanResult()

        all_findings: list[Finding] = []
        files_scanned = 0
        lines_scanned = 0
        rules_applied = 0

        for file_path in self._walk_directory(path):
            result = self.scan_file(file_path)
            all_findings.extend(result.findings)
            files_scanned += result.files_scanned
            lines_scanned += result.lines_scanned
            rules_applied = max(rules_applied, result.rules_applied)

        elapsed = (time.monotonic() - start) * 1000

        return ScanResult(
            findings=all_findings,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            rules_applied=rules_applied,
            scan_time_ms=elapsed,
        )

    def _walk_directory(self, root: Path):
        """Walk directory, skipping ignored dirs and binary files."""
        try:
            entries = sorted(root.iterdir())
        except PermissionError:
            return

        for entry in entries:
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    yield from self._walk_directory(entry)
            elif entry.is_file():
                if not self._should_skip_file(entry):
                    yield entry

    def _should_skip_file(self, path: Path) -> bool:
        """Check if a file should be skipped."""
        # Skip binary files
        if path.suffix.lower() in BINARY_EXTENSIONS:
            return True

        # Check allowlisted paths
        str_path = str(path)
        for pattern in self.config.allowlist_paths:
            if fnmatch.fnmatch(str_path, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True

        return False
