"""Tests for CLI commands."""

import json

import pytest
from click.testing import CliRunner

from gitguard.cli import main


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "gitguard" in result.output

    def test_scan_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--staged" in result.output
        assert "--format" in result.output

    def test_scan_file_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", "--help"])
        assert result.exit_code == 0

    def test_install_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["install", "--help"])
        assert result.exit_code == 0

    def test_uninstall_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["uninstall", "--help"])
        assert result.exit_code == 0

    def test_init_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--help"])
        assert result.exit_code == 0

    def test_list_rules_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["list-rules", "--help"])
        assert result.exit_code == 0

    def test_status_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["status", "--help"])
        assert result.exit_code == 0


class TestScanFileCommand:
    def test_scan_file_clean(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("x = 1\ny = 2\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", str(f)])
        assert result.exit_code == 0

    def test_scan_file_with_secret(self, tmp_path):
        f = tmp_path / "bad.py"
        f.write_text('password = "mysupersecretpwd"\n')
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", str(f)])
        assert result.exit_code == 1

    def test_scan_file_json_format(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", str(f), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "summary" in data

    def test_scan_file_sarif_format(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", str(f), "--format", "sarif"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"

    def test_scan_file_nonexistent(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", str(tmp_path / "nope.py")])
        # Should warn and exit
        assert result.exit_code == 0  # No findings from nonexistent file

    def test_scan_directory(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_multiple_files(self, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("x = 1\n")
        f2.write_text("y = 2\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", str(f1), str(f2)])
        assert result.exit_code == 0

    def test_scan_file_verbose(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('password = "mysupersecretpwd"\n')
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", str(f), "-v"])
        assert result.exit_code == 1
        assert "Match:" in result.output

    def test_scan_file_no_color(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('password = "mysupersecretpwd"\n')
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", str(f), "--no-color"])
        assert result.exit_code == 1
        assert "\033[" not in result.output


class TestListRulesCommand:
    def test_list_rules_text(self):
        runner = CliRunner()
        result = runner.invoke(main, ["list-rules"])
        assert result.exit_code == 0
        assert "aws-access-key" in result.output

    def test_list_rules_json(self):
        runner = CliRunner()
        result = runner.invoke(main, ["list-rules", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0


class TestInitCommand:
    def test_init_creates_config(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["init"])
            assert result.exit_code == 0
            assert "Created .gitguard.yml" in result.output

    def test_init_existing_config(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            from pathlib import Path
            Path(".gitguard.yml").write_text("existing")
            result = runner.invoke(main, ["init"])
            assert result.exit_code == 1
            assert "already exists" in result.output
