"""Git integration utilities."""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(Exception):
    """Error running git command."""
    pass


class Git:
    """Git command wrapper."""

    def __init__(self, repo_path: str | Path | None = None) -> None:
        self.repo_path = Path(repo_path) if repo_path else Path.cwd()

    def _run(self, *args: str, check: bool = True) -> str:
        """Run a git command and return stdout."""
        cmd = ["git", "-C", str(self.repo_path)] + list(args)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if check and result.returncode != 0:
                raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
            return result.stdout
        except FileNotFoundError:
            raise GitError("git is not installed or not in PATH")
        except subprocess.TimeoutExpired:
            raise GitError(f"git {' '.join(args)} timed out")

    def is_repo(self) -> bool:
        """Check if path is a git repository."""
        try:
            self._run("rev-parse", "--git-dir")
            return True
        except GitError:
            return False

    def staged_diff(self) -> str:
        """Get diff of staged changes."""
        return self._run("diff", "--cached", "--unified=0")

    def unstaged_diff(self) -> str:
        """Get diff of unstaged changes."""
        return self._run("diff", "--unified=0")

    def all_diff(self) -> str:
        """Get diff of all changes (staged + unstaged)."""
        return self._run("diff", "HEAD", "--unified=0", check=False)

    def staged_files(self) -> list[str]:
        """Get list of staged file paths."""
        output = self._run("diff", "--cached", "--name-only")
        return [f for f in output.strip().splitlines() if f]

    def untracked_files(self) -> list[str]:
        """Get list of untracked files."""
        output = self._run("ls-files", "--others", "--exclude-standard")
        return [f for f in output.strip().splitlines() if f]

    def get_file_content(self, file_path: str, staged: bool = False) -> str:
        """Get file content (staged or working copy)."""
        if staged:
            try:
                return self._run("show", f":{file_path}")
            except GitError:
                return ""
        else:
            full_path = self.repo_path / file_path
            if full_path.exists():
                return full_path.read_text(encoding="utf-8", errors="ignore")
            return ""

    def current_branch(self) -> str:
        """Get current branch name."""
        return self._run("rev-parse", "--abbrev-ref", "HEAD").strip()

    def repo_root(self) -> Path:
        """Get repository root path."""
        return Path(self._run("rev-parse", "--show-toplevel").strip())
