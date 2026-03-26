"""Baseline scanner - scans all tracked files in a git repository."""

from __future__ import annotations

import time
from pathlib import Path

from gitguard.git import Git, GitError
from gitguard.models import Finding, ScanConfig, ScanResult
from gitguard.scanners.file_scanner import FileScanner


class BaselineScanner:
    """Scans all tracked files in a git repository for secrets.

    Unlike DiffScanner (which only checks new/modified lines),
    BaselineScanner examines every tracked file to establish
    a security baseline for the repository.
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.file_scanner = FileScanner(self.config)

    def scan_repo(self, repo_path: str | Path | None = None) -> ScanResult:
        """Scan all tracked files in a git repository."""
        start = time.monotonic()
        path = Path(repo_path) if repo_path else Path.cwd()

        try:
            git = Git(path)
            if not git.is_repo():
                return ScanResult()
            tracked_files = self._get_tracked_files(git)
        except GitError:
            return ScanResult()

        root = git.repo_root()
        all_findings: list[Finding] = []
        files_scanned = 0
        lines_scanned = 0
        rules_applied = 0

        for rel_path in tracked_files:
            full_path = root / rel_path
            if not full_path.exists() or not full_path.is_file():
                continue

            result = self.file_scanner.scan_file(full_path)
            # Normalize file paths to relative
            for finding in result.findings:
                finding.file_path = rel_path
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

    def _get_tracked_files(self, git: Git) -> list[str]:
        """Get list of all tracked files."""
        output = git._run("ls-files")
        return [f for f in output.strip().splitlines() if f]
