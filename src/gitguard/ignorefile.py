"""Support for .gitguardignore files (similar to .gitignore)."""

from __future__ import annotations

import fnmatch
from pathlib import Path


IGNORE_FILENAMES = [".gitguardignore", ".gitguard-ignore"]


class IgnoreFile:
    """Parses and matches against .gitguardignore patterns.

    Supports:
    - Glob patterns (*.test.py, fixtures/**)
    - Comments (lines starting with #)
    - Negation (lines starting with !)
    - Inline comments (# after pattern, with space before)
    """

    def __init__(self, patterns: list[str] | None = None) -> None:
        self._include_patterns: list[str] = []
        self._exclude_patterns: list[str] = []
        if patterns:
            self._parse_patterns(patterns)

    @classmethod
    def from_file(cls, path: str | Path) -> "IgnoreFile":
        """Load patterns from a file."""
        path = Path(path)
        if not path.exists():
            return cls()
        content = path.read_text(encoding="utf-8")
        lines = content.splitlines()
        return cls(lines)

    @classmethod
    def find_and_load(cls, start_path: str | Path | None = None) -> "IgnoreFile":
        """Find and load a .gitguardignore file by walking up directories."""
        path = Path(start_path) if start_path else Path.cwd()

        for _ in range(20):
            for name in IGNORE_FILENAMES:
                candidate = path / name
                if candidate.exists():
                    return cls.from_file(candidate)
            parent = path.parent
            if parent == path:
                break
            path = parent

        return cls()

    def _parse_patterns(self, lines: list[str]) -> None:
        """Parse pattern lines."""
        for line in lines:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Handle inline comments
            comment_idx = line.find(" #")
            if comment_idx >= 0:
                line = line[:comment_idx].strip()

            if not line:
                continue

            # Negation pattern
            if line.startswith("!"):
                pattern = line[1:].strip()
                if pattern:
                    self._exclude_patterns.append(pattern)
            else:
                self._include_patterns.append(line)

    def is_ignored(self, file_path: str) -> bool:
        """Check if a file path should be ignored."""
        if not self._include_patterns:
            return False

        # Normalize path separators
        normalized = file_path.replace("\\", "/")
        basename = normalized.rsplit("/", 1)[-1] if "/" in normalized else normalized

        # Check include patterns
        matched = False
        for pattern in self._include_patterns:
            if self._matches(normalized, basename, pattern):
                matched = True
                break

        if not matched:
            return False

        # Check exclude (negation) patterns
        for pattern in self._exclude_patterns:
            if self._matches(normalized, basename, pattern):
                return False

        return True

    def _matches(self, path: str, basename: str, pattern: str) -> bool:
        """Check if a path matches a pattern."""
        # Handle ** patterns by converting to simpler forms
        simple_pattern = pattern.replace("**/", "")

        # Try full path match
        if fnmatch.fnmatch(path, pattern):
            return True
        # Try basename match against simplified pattern
        if fnmatch.fnmatch(basename, simple_pattern):
            return True
        # Try basename match against original pattern
        if fnmatch.fnmatch(basename, pattern):
            return True
        # Try matching path components
        if "/" in pattern:
            if fnmatch.fnmatch(path, pattern):
                return True
        # Try as suffix match for ** patterns
        if "**" in pattern:
            # Match basename against the part after **/
            if fnmatch.fnmatch(path, simple_pattern):
                return True
        return False

    @property
    def patterns(self) -> list[str]:
        """Return all include patterns."""
        return list(self._include_patterns)

    @property
    def negated_patterns(self) -> list[str]:
        """Return all negation patterns."""
        return list(self._exclude_patterns)

    def __len__(self) -> int:
        return len(self._include_patterns) + len(self._exclude_patterns)
