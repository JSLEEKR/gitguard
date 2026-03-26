"""Tests for output formatters."""

import json

import pytest

from gitguard.models import Finding, ScanResult, Severity
from gitguard.formatters.text import TextFormatter
from gitguard.formatters.json_fmt import JsonFormatter
from gitguard.formatters.sarif import SarifFormatter


def _make_result(findings=None, **kwargs):
    if findings is None:
        findings = []
    return ScanResult(findings=findings, **kwargs)


def _make_finding(**kwargs):
    defaults = {
        "rule_id": "test",
        "rule_name": "Test Rule",
        "severity": Severity.HIGH,
        "file_path": "app.py",
        "line_number": 10,
        "line_content": "secret = 'abc'",
        "match_text": "abc123456789",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


class TestTextFormatter:
    def test_no_findings(self):
        fmt = TextFormatter(use_color=False)
        result = _make_result()
        output = fmt.format(result)
        assert "No secrets detected" in output

    def test_with_findings(self):
        fmt = TextFormatter(use_color=False)
        result = _make_result(findings=[_make_finding()])
        output = fmt.format(result)
        assert "Found 1 potential secret" in output
        assert "app.py" in output
        assert "Test Rule" in output

    def test_verbose_shows_match(self):
        fmt = TextFormatter(use_color=False, verbose=True)
        result = _make_result(findings=[_make_finding()])
        output = fmt.format(result)
        assert "Match:" in output

    def test_non_verbose_hides_match(self):
        fmt = TextFormatter(use_color=False, verbose=False)
        result = _make_result(findings=[_make_finding()])
        output = fmt.format(result)
        assert "Match:" not in output

    def test_color_output(self):
        fmt = TextFormatter(use_color=True)
        result = _make_result(findings=[_make_finding()])
        output = fmt.format(result)
        assert "\033[" in output  # ANSI escape codes

    def test_no_color_output(self):
        fmt = TextFormatter(use_color=False)
        result = _make_result(findings=[_make_finding()])
        output = fmt.format(result)
        assert "\033[" not in output

    def test_stats_line(self):
        fmt = TextFormatter(use_color=False)
        result = _make_result(
            findings=[_make_finding()],
            files_scanned=5,
            lines_scanned=100,
            rules_applied=20,
        )
        output = fmt.format(result)
        assert "Files: 5" in output
        assert "Lines: 100" in output
        assert "Rules: 20" in output

    def test_multiple_files(self):
        fmt = TextFormatter(use_color=False)
        findings = [
            _make_finding(file_path="a.py", line_number=1),
            _make_finding(file_path="b.py", line_number=5),
        ]
        result = _make_result(findings=findings)
        output = fmt.format(result)
        assert "a.py" in output
        assert "b.py" in output

    def test_severity_tag(self):
        fmt = TextFormatter(use_color=False)
        result = _make_result(findings=[
            _make_finding(severity=Severity.CRITICAL),
        ])
        output = fmt.format(result)
        assert "[CRITICAL]" in output

    def test_verbose_with_description(self):
        fmt = TextFormatter(use_color=False, verbose=True)
        result = _make_result(findings=[
            _make_finding(description="Test description"),
        ])
        output = fmt.format(result)
        assert "Info:" in output
        assert "Test description" in output


class TestJsonFormatter:
    def test_empty_result(self):
        fmt = JsonFormatter()
        result = _make_result()
        output = fmt.format(result)
        data = json.loads(output)
        assert data["summary"]["total_findings"] == 0
        assert data["findings"] == []

    def test_with_findings(self):
        fmt = JsonFormatter()
        result = _make_result(findings=[_make_finding()])
        output = fmt.format(result)
        data = json.loads(output)
        assert data["summary"]["total_findings"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "test"

    def test_pretty_format(self):
        fmt = JsonFormatter(pretty=True)
        output = fmt.format(_make_result())
        assert "\n" in output

    def test_compact_format(self):
        fmt = JsonFormatter(pretty=False)
        output = fmt.format(_make_result())
        assert "\n" not in output

    def test_summary_only(self):
        fmt = JsonFormatter()
        result = _make_result(findings=[_make_finding()], files_scanned=3)
        output = fmt.format_summary_only(result)
        data = json.loads(output)
        assert "total_findings" in data
        assert "findings" not in data

    def test_summary_only_compact(self):
        fmt = JsonFormatter(pretty=False)
        output = fmt.format_summary_only(_make_result())
        assert "\n" not in output


class TestSarifFormatter:
    def test_empty_result(self):
        fmt = SarifFormatter()
        result = _make_result()
        output = fmt.format(result)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"] == []

    def test_with_findings(self):
        fmt = SarifFormatter()
        result = _make_result(findings=[_make_finding()])
        output = fmt.format(result)
        data = json.loads(output)
        assert len(data["runs"][0]["results"]) == 1

    def test_sarif_rule_dedup(self):
        fmt = SarifFormatter()
        findings = [
            _make_finding(rule_id="r1", line_number=1),
            _make_finding(rule_id="r1", line_number=5),
        ]
        result = _make_result(findings=findings)
        output = fmt.format(result)
        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1  # Deduped

    def test_sarif_severity_mapping(self):
        fmt = SarifFormatter()
        result = _make_result(findings=[
            _make_finding(severity=Severity.CRITICAL),
        ])
        output = fmt.format(result)
        data = json.loads(output)
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_location(self):
        fmt = SarifFormatter()
        result = _make_result(findings=[
            _make_finding(file_path="src/main.py", line_number=42),
        ])
        output = fmt.format(result)
        data = json.loads(output)
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/main.py"
        assert loc["region"]["startLine"] == 42

    def test_sarif_schema(self):
        fmt = SarifFormatter()
        output = fmt.format(_make_result())
        data = json.loads(output)
        assert "$schema" in data
        assert "sarif" in data["$schema"]

    def test_sarif_tool_info(self):
        fmt = SarifFormatter()
        output = fmt.format(_make_result())
        data = json.loads(output)
        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "gitguard"
        assert "version" in tool
