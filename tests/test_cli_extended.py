"""Tests for extended CLI commands."""

import pytest
from click.testing import CliRunner

from gitguard.cli import main


class TestScanHistoryCommand:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan-history", "--help"])
        assert result.exit_code == 0
        assert "--max-commits" in result.output
        assert "--branch" in result.output

    def test_format_option(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan-history", "--help"])
        assert "--format" in result.output


class TestScanBaselineCommand:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan-baseline", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--verbose" in result.output

    def test_format_option(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan-baseline", "--help"])
        assert "sarif" in result.output


class TestAllCommandsExist:
    def test_all_commands_available(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "scan " in result.output or "scan" in result.output
        assert "scan-file" in result.output
        assert "scan-history" in result.output
        assert "scan-baseline" in result.output
        assert "install" in result.output
        assert "uninstall" in result.output
        assert "init" in result.output
        assert "list-rules" in result.output
        assert "status" in result.output
