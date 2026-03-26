"""Git hook installer - installs/uninstalls gitguard as a pre-commit hook."""

from __future__ import annotations

import os
import stat
from pathlib import Path

HOOK_SCRIPT = """\
#!/bin/sh
# gitguard pre-commit hook
# Scans staged changes for secrets before committing

gitguard scan --staged
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo ""
    echo "Commit blocked by gitguard: secrets detected in staged changes."
    echo "Fix the issues above or use 'git commit --no-verify' to bypass."
    exit 1
fi
"""

HOOK_MARKER = "# gitguard pre-commit hook"


class HookInstaller:
    """Manages git pre-commit hook installation."""

    def __init__(self, repo_path: str | Path | None = None) -> None:
        self.repo_path = Path(repo_path) if repo_path else Path.cwd()

    @property
    def git_dir(self) -> Path:
        """Find the .git directory."""
        git_dir = self.repo_path / ".git"
        if git_dir.is_file():
            # Handle git worktrees
            content = git_dir.read_text().strip()
            if content.startswith("gitdir:"):
                git_dir = Path(content.split(":", 1)[1].strip())
                if not git_dir.is_absolute():
                    git_dir = self.repo_path / git_dir
        return git_dir

    @property
    def hooks_dir(self) -> Path:
        return self.git_dir / "hooks"

    @property
    def hook_path(self) -> Path:
        return self.hooks_dir / "pre-commit"

    def is_git_repo(self) -> bool:
        """Check if the path is a git repository."""
        return (self.repo_path / ".git").exists()

    def is_installed(self) -> bool:
        """Check if gitguard hook is already installed."""
        if not self.hook_path.exists():
            return False
        content = self.hook_path.read_text()
        return HOOK_MARKER in content

    def install(self, force: bool = False) -> str:
        """Install the pre-commit hook."""
        if not self.is_git_repo():
            return "Error: Not a git repository"

        self.hooks_dir.mkdir(parents=True, exist_ok=True)

        if self.hook_path.exists() and not force:
            if self.is_installed():
                return "gitguard hook is already installed"
            # Existing hook, append
            existing = self.hook_path.read_text()
            new_content = existing.rstrip() + "\n\n" + HOOK_SCRIPT
            self.hook_path.write_text(new_content)
            self._make_executable()
            return "gitguard hook appended to existing pre-commit hook"

        self.hook_path.write_text(HOOK_SCRIPT)
        self._make_executable()
        return "gitguard pre-commit hook installed successfully"

    def uninstall(self) -> str:
        """Remove the gitguard hook."""
        if not self.hook_path.exists():
            return "No pre-commit hook found"

        if not self.is_installed():
            return "gitguard hook is not installed"

        content = self.hook_path.read_text()
        lines = content.splitlines()

        # Remove gitguard section
        new_lines: list[str] = []
        skip = False
        for line in lines:
            if HOOK_MARKER in line:
                skip = True
                # Remove the shebang if it's the only content
                if new_lines and new_lines[-1].startswith("#!/"):
                    if len(new_lines) == 1:
                        new_lines.clear()
                continue
            if skip and line.strip() == "":
                skip = False
                continue
            if skip:
                if line.startswith("gitguard ") or line.startswith("exit_code=") or \
                   line.startswith("if [") or line.startswith("    echo") or \
                   line.startswith("    exit") or line.startswith("fi"):
                    continue
                skip = False
            new_lines.append(line)

        remaining = "\n".join(new_lines).strip()
        if not remaining:
            self.hook_path.unlink()
            return "gitguard pre-commit hook removed"
        else:
            self.hook_path.write_text(remaining + "\n")
            return "gitguard hook removed from pre-commit hook"

    def _make_executable(self) -> None:
        """Make the hook file executable."""
        current = self.hook_path.stat().st_mode
        self.hook_path.chmod(current | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
