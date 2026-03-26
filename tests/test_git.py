"""Tests for git integration utilities."""

import subprocess

import pytest

from gitguard.git import Git, GitError


def _init_repo(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t.com"], capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "T"], capture_output=True)
    return tmp_path


def _commit(repo, filename, content, msg="add"):
    (repo / filename).write_text(content)
    subprocess.run(["git", "-C", str(repo), "add", filename], capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", msg], capture_output=True)


class TestGit:
    def test_is_repo(self, tmp_path):
        repo = _init_repo(tmp_path)
        git = Git(repo)
        assert git.is_repo()

    def test_is_not_repo(self, tmp_path):
        git = Git(tmp_path)
        assert not git.is_repo()

    def test_current_branch(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "init.py", "x = 1\n", "init")
        git = Git(repo)
        branch = git.current_branch()
        assert branch in ("master", "main")

    def test_repo_root(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "init.py", "x = 1\n", "init")
        git = Git(repo)
        root = git.repo_root()
        assert root.exists()

    def test_staged_files(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "init.py", "x = 1\n", "init")
        (repo / "new.py").write_text("y = 2\n")
        subprocess.run(["git", "-C", str(repo), "add", "new.py"], capture_output=True)
        git = Git(repo)
        staged = git.staged_files()
        assert "new.py" in staged

    def test_untracked_files(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "init.py", "x = 1\n", "init")
        (repo / "untracked.py").write_text("z = 3\n")
        git = Git(repo)
        untracked = git.untracked_files()
        assert "untracked.py" in untracked

    def test_staged_diff(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "init.py", "x = 1\n", "init")
        (repo / "init.py").write_text("x = 2\n")
        subprocess.run(["git", "-C", str(repo), "add", "init.py"], capture_output=True)
        git = Git(repo)
        diff = git.staged_diff()
        assert "x = 2" in diff

    def test_unstaged_diff(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "init.py", "x = 1\n", "init")
        (repo / "init.py").write_text("x = 2\n")
        git = Git(repo)
        diff = git.unstaged_diff()
        assert "x = 2" in diff

    def test_get_file_content_working(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "test.py", "content = 'hello'\n", "init")
        git = Git(repo)
        content = git.get_file_content("test.py")
        assert "hello" in content

    def test_get_file_content_staged(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "test.py", "old\n", "init")
        (repo / "test.py").write_text("new\n")
        subprocess.run(["git", "-C", str(repo), "add", "test.py"], capture_output=True)
        git = Git(repo)
        content = git.get_file_content("test.py", staged=True)
        assert "new" in content

    def test_get_file_content_nonexistent(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "init.py", "x\n", "init")
        git = Git(repo)
        content = git.get_file_content("nope.py")
        assert content == ""

    def test_get_file_content_staged_nonexistent(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "init.py", "x\n", "init")
        git = Git(repo)
        content = git.get_file_content("nope.py", staged=True)
        assert content == ""

    def test_all_diff(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "init.py", "x = 1\n", "init")
        (repo / "init.py").write_text("x = 2\n")
        git = Git(repo)
        diff = git.all_diff()
        assert "x = 2" in diff
