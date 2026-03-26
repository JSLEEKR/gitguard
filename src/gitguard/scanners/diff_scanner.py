"""Diff scanner - parses and scans git diffs for secrets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from gitguard.models import Finding, ScanConfig, ScanResult
from gitguard.scanners.content_scanner import ContentScanner


@dataclass
class DiffHunk:
    """A hunk from a unified diff."""
    file_path: str
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    removed_lines: list[tuple[int, str]] = field(default_factory=list)


class DiffParser:
    """Parses unified diff format."""

    FILE_HEADER = re.compile(r"^diff --git a/(.+) b/(.+)$")
    HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    NEW_FILE = re.compile(r"^--- /dev/null$")
    OLD_FILE = re.compile(r"^\+\+\+ /dev/null$")

    @staticmethod
    def parse(diff_text: str) -> list[DiffHunk]:
        """Parse a unified diff into DiffHunks."""
        hunks: list[DiffHunk] = []
        current_file: str | None = None
        current_hunk: DiffHunk | None = None
        line_number = 0
        is_deleted = False

        for line in diff_text.splitlines():
            file_match = DiffParser.FILE_HEADER.match(line)
            if file_match:
                current_file = file_match.group(2)
                is_deleted = False
                continue

            if DiffParser.OLD_FILE.match(line):
                is_deleted = True
                continue

            if is_deleted:
                continue

            hunk_match = DiffParser.HUNK_HEADER.match(line)
            if hunk_match and current_file:
                line_number = int(hunk_match.group(1))
                current_hunk = DiffHunk(file_path=current_file)
                hunks.append(current_hunk)
                continue

            if current_hunk is None:
                continue

            if line.startswith("+") and not line.startswith("+++"):
                current_hunk.added_lines.append((line_number, line[1:]))
                line_number += 1
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk.removed_lines.append((line_number, line[1:]))
            else:
                line_number += 1

        return hunks


class DiffScanner:
    """Scans git diffs for secrets (only added lines)."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.content_scanner = ContentScanner(self.config)
        self.parser = DiffParser()

    def scan_diff(self, diff_text: str) -> ScanResult:
        """Scan a unified diff for secrets in added lines."""
        hunks = self.parser.parse(diff_text)
        all_findings: list[Finding] = []
        files_scanned: set[str] = set()
        total_lines = 0

        for hunk in hunks:
            files_scanned.add(hunk.file_path)

            # Check if file path is allowlisted
            if self.content_scanner._is_path_allowlisted(hunk.file_path):
                continue

            for line_num, line_content in hunk.added_lines:
                total_lines += 1
                result = self.content_scanner.scan_text(
                    line_content, hunk.file_path
                )
                for finding in result.findings:
                    finding.line_number = line_num
                    all_findings.append(finding)

        return ScanResult(
            findings=all_findings,
            files_scanned=len(files_scanned),
            lines_scanned=total_lines,
            rules_applied=len([r for r in self.config.rules if r.enabled]),
        )

    def scan_staged(self, diff_text: str) -> ScanResult:
        """Scan staged changes (alias for scan_diff)."""
        return self.scan_diff(diff_text)
