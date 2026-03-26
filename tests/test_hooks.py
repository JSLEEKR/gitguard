"""Tests for git hook installer."""

import pytest
from pathlib import Path

from gitguard.hooks.installer import HookInstaller, HOOK_MARKER, HOOK_SCRIPT


class TestHookInstaller:
    def _make_repo(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir()
        return tmp_path

    def test_is_git_repo(self, tmp_path):
        repo = self._make_repo(tmp_path)
        installer = HookInstaller(repo)
        assert installer.is_git_repo() is True

    def test_not_git_repo(self, tmp_path):
        installer = HookInstaller(tmp_path)
        assert installer.is_git_repo() is False

    def test_install_new(self, tmp_path):
        repo = self._make_repo(tmp_path)
        installer = HookInstaller(repo)
        result = installer.install()
        assert "installed successfully" in result
        assert installer.hook_path.exists()
        assert HOOK_MARKER in installer.hook_path.read_text()

    def test_install_already_installed(self, tmp_path):
        repo = self._make_repo(tmp_path)
        installer = HookInstaller(repo)
        installer.install()
        result = installer.install()
        assert "already installed" in result

    def test_install_force(self, tmp_path):
        repo = self._make_repo(tmp_path)
        installer = HookInstaller(repo)
        installer.install()
        result = installer.install(force=True)
        assert "installed successfully" in result

    def test_install_not_git_repo(self, tmp_path):
        installer = HookInstaller(tmp_path)
        result = installer.install()
        assert "Error" in result

    def test_install_append_to_existing(self, tmp_path):
        repo = self._make_repo(tmp_path)
        hook_path = repo / ".git" / "hooks" / "pre-commit"
        hook_path.write_text("#!/bin/sh\necho 'existing hook'\n")
        installer = HookInstaller(repo)
        result = installer.install()
        assert "appended" in result
        content = hook_path.read_text()
        assert "existing hook" in content
        assert HOOK_MARKER in content

    def test_is_installed(self, tmp_path):
        repo = self._make_repo(tmp_path)
        installer = HookInstaller(repo)
        assert installer.is_installed() is False
        installer.install()
        assert installer.is_installed() is True

    def test_uninstall(self, tmp_path):
        repo = self._make_repo(tmp_path)
        installer = HookInstaller(repo)
        installer.install()
        result = installer.uninstall()
        assert "removed" in result

    def test_uninstall_no_hook(self, tmp_path):
        repo = self._make_repo(tmp_path)
        installer = HookInstaller(repo)
        result = installer.uninstall()
        assert "No pre-commit hook found" in result

    def test_uninstall_not_our_hook(self, tmp_path):
        repo = self._make_repo(tmp_path)
        hook_path = repo / ".git" / "hooks" / "pre-commit"
        hook_path.write_text("#!/bin/sh\necho 'other hook'\n")
        installer = HookInstaller(repo)
        result = installer.uninstall()
        assert "not installed" in result

    def test_hook_path(self, tmp_path):
        repo = self._make_repo(tmp_path)
        installer = HookInstaller(repo)
        assert installer.hook_path == repo / ".git" / "hooks" / "pre-commit"

    def test_hooks_dir_created(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        # No hooks dir yet
        installer = HookInstaller(tmp_path)
        installer.install()
        assert (git_dir / "hooks").exists()

    def test_git_worktree(self, tmp_path):
        # Simulate a worktree where .git is a file
        real_git = tmp_path / "real_repo" / ".git"
        real_git.mkdir(parents=True)
        hooks = real_git / "hooks"
        hooks.mkdir()

        worktree = tmp_path / "worktree"
        worktree.mkdir()
        (worktree / ".git").write_text(f"gitdir: {real_git}")

        installer = HookInstaller(worktree)
        assert installer.is_git_repo() is True
