"""Parallel file scanning for large codebases."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from gitguard.models import Finding, ScanConfig, ScanResult
from gitguard.scanners.file_scanner import FileScanner


class ParallelScanner:
    """Scans files in parallel using thread pool."""

    def __init__(
        self, config: ScanConfig | None = None, max_workers: int = 4
    ) -> None:
        self.config = config or ScanConfig()
        self.max_workers = max_workers
        self._file_scanner = FileScanner(self.config)

    def scan_files(self, file_paths: list[str | Path]) -> ScanResult:
        """Scan multiple files in parallel."""
        start = time.monotonic()
        all_findings: list[Finding] = []
        files_scanned = 0
        lines_scanned = 0
        rules_applied = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._file_scanner.scan_file, p): p
                for p in file_paths
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    all_findings.extend(result.findings)
                    files_scanned += result.files_scanned
                    lines_scanned += result.lines_scanned
                    rules_applied = max(rules_applied, result.rules_applied)
                except Exception:
                    pass  # Skip files that fail

        elapsed = (time.monotonic() - start) * 1000
        return ScanResult(
            findings=all_findings,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            rules_applied=rules_applied,
            scan_time_ms=elapsed,
        )

    def scan_directory(self, dir_path: str | Path) -> ScanResult:
        """Scan a directory using parallel file scanning."""
        path = Path(dir_path)
        if not path.exists() or not path.is_dir():
            return ScanResult()

        files = list(self._collect_files(path))
        return self.scan_files(files)

    def _collect_files(self, root: Path):
        """Collect scannable files from a directory."""
        from gitguard.scanners.file_scanner import BINARY_EXTENSIONS, SKIP_DIRS

        try:
            entries = sorted(root.iterdir())
        except PermissionError:
            return

        for entry in entries:
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    yield from self._collect_files(entry)
            elif entry.is_file():
                if entry.suffix.lower() not in BINARY_EXTENSIONS:
                    yield entry
