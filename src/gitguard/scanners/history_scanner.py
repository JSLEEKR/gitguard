"""History scanner - scans git commit history for secrets."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from gitguard.git import Git, GitError
from gitguard.models import Finding, ScanConfig, ScanResult
from gitguard.scanners.diff_scanner import DiffScanner


@dataclass
class CommitFinding:
    """A finding associated with a specific commit."""
    commit_hash: str
    commit_message: str
    author: str
    finding: Finding


class HistoryScanner:
    """Scans git commit history for secrets.

    Useful for auditing whether secrets were ever committed,
    even if they were later removed.
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.diff_scanner = DiffScanner(self.config)

    def scan_history(
        self,
        repo_path: str | None = None,
        max_commits: int = 50,
        branch: str | None = None,
    ) -> tuple[ScanResult, list[CommitFinding]]:
        """Scan commit history for secrets.

        Returns a ScanResult and a list of CommitFindings with commit context.
        """
        start = time.monotonic()

        try:
            git = Git(repo_path)
            if not git.is_repo():
                return ScanResult(), []
            commits = self._get_commits(git, max_commits, branch)
        except GitError:
            return ScanResult(), []

        all_findings: list[Finding] = []
        commit_findings: list[CommitFinding] = []
        files_scanned: set[str] = set()
        total_lines = 0

        for commit_hash, message, author in commits:
            try:
                diff = git._run("diff", f"{commit_hash}~1", commit_hash, "--unified=0", check=False)
            except GitError:
                continue

            result = self.diff_scanner.scan_diff(diff)

            for finding in result.findings:
                all_findings.append(finding)
                commit_findings.append(CommitFinding(
                    commit_hash=commit_hash,
                    commit_message=message,
                    author=author,
                    finding=finding,
                ))
                files_scanned.add(finding.file_path)

            total_lines += result.lines_scanned

        elapsed = (time.monotonic() - start) * 1000

        scan_result = ScanResult(
            findings=all_findings,
            files_scanned=len(files_scanned),
            lines_scanned=total_lines,
            rules_applied=len([r for r in self.config.rules if r.enabled]),
            scan_time_ms=elapsed,
        )

        return scan_result, commit_findings

    def _get_commits(
        self, git: Git, max_commits: int, branch: str | None
    ) -> list[tuple[str, str, str]]:
        """Get list of (hash, message, author) tuples."""
        args = ["log", f"--max-count={max_commits}", "--format=%H\t%s\t%an"]
        if branch:
            args.append(branch)

        output = git._run(*args)
        commits: list[tuple[str, str, str]] = []

        for line in output.strip().splitlines():
            if not line:
                continue
            parts = line.split("\t", 2)
            if len(parts) == 3:
                commits.append((parts[0], parts[1], parts[2]))

        return commits
