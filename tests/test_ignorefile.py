"""Tests for .gitguardignore file support."""

import pytest
from pathlib import Path

from gitguard.ignorefile import IgnoreFile


class TestIgnoreFile:
    def test_empty(self):
        ig = IgnoreFile()
        assert not ig.is_ignored("any/file.py")
        assert len(ig) == 0

    def test_basic_pattern(self):
        ig = IgnoreFile(["*.test.py"])
        assert ig.is_ignored("app.test.py")
        assert not ig.is_ignored("app.py")

    def test_directory_pattern(self):
        ig = IgnoreFile(["fixtures/*"])
        assert ig.is_ignored("fixtures/data.json")

    def test_glob_star_star(self):
        ig = IgnoreFile(["**/test_*.py"])
        assert ig.is_ignored("test_app.py")
        assert ig.is_ignored("src/test_app.py")

    def test_comments_ignored(self):
        ig = IgnoreFile([
            "# This is a comment",
            "*.test.py",
            "  # Another comment",
        ])
        assert len(ig.patterns) == 1

    def test_empty_lines_ignored(self):
        ig = IgnoreFile(["", "*.py", "", "  "])
        assert len(ig.patterns) == 1

    def test_inline_comments(self):
        ig = IgnoreFile(["*.test.py # test files"])
        assert ig.is_ignored("app.test.py")

    def test_negation(self):
        ig = IgnoreFile(["*.py", "!important.py"])
        assert ig.is_ignored("app.py")
        assert not ig.is_ignored("important.py")

    def test_negation_patterns_property(self):
        ig = IgnoreFile(["*.py", "!keep.py"])
        assert len(ig.negated_patterns) == 1
        assert "keep.py" in ig.negated_patterns

    def test_patterns_property(self):
        ig = IgnoreFile(["*.py", "*.js"])
        assert len(ig.patterns) == 2

    def test_path_normalization(self):
        ig = IgnoreFile(["*.py"])
        assert ig.is_ignored("src\\app.py")  # Backslash path

    def test_from_file(self, tmp_path):
        f = tmp_path / ".gitguardignore"
        f.write_text("*.test.py\n# comment\nfixtures/*\n")
        ig = IgnoreFile.from_file(f)
        assert ig.is_ignored("app.test.py")
        assert len(ig.patterns) == 2

    def test_from_file_nonexistent(self):
        ig = IgnoreFile.from_file("/nonexistent/.gitguardignore")
        assert not ig.is_ignored("anything")

    def test_find_and_load(self, tmp_path):
        f = tmp_path / ".gitguardignore"
        f.write_text("*.test.py\n")
        ig = IgnoreFile.find_and_load(tmp_path)
        assert ig.is_ignored("app.test.py")

    def test_find_and_load_parent(self, tmp_path):
        f = tmp_path / ".gitguardignore"
        f.write_text("*.test.py\n")
        sub = tmp_path / "sub" / "deep"
        sub.mkdir(parents=True)
        ig = IgnoreFile.find_and_load(sub)
        assert ig.is_ignored("app.test.py")

    def test_find_and_load_not_found(self, tmp_path):
        ig = IgnoreFile.find_and_load(tmp_path)
        assert not ig.is_ignored("anything")
        assert len(ig) == 0

    def test_multiple_patterns(self):
        ig = IgnoreFile([
            "*.env",
            "*.key",
            "*.pem",
            "test_*",
            "fixtures/**",
        ])
        assert ig.is_ignored("app.env")
        assert ig.is_ignored("server.key")
        assert ig.is_ignored("test_config.py")

    def test_basename_matching(self):
        ig = IgnoreFile(["*.py"])
        assert ig.is_ignored("src/lib/deep/module.py")
