"""Tests for report generation."""

import json

import pytest

from gitguard.models import Finding, ScanResult, Severity
from gitguard.report import ScanReport


def _f(rule_id="test", severity=Severity.HIGH, file_path="app.py", line=1):
    return Finding(
        rule_id=rule_id, rule_name=rule_id, severity=severity,
        file_path=file_path, line_number=line, line_content="x",
        match_text="secret",
    )


class TestScanReport:
    def test_empty_report(self):
        report = ScanReport(project_name="test")
        assert report.total_findings == 0
        assert report.pass_fail == "PASS"
        assert report.total_risk_score == 0

    def test_add_result(self):
        report = ScanReport()
        report.add_result(ScanResult(findings=[_f()]))
        assert report.total_findings == 1

    def test_multiple_results(self):
        report = ScanReport()
        report.add_result(ScanResult(findings=[_f()], files_scanned=2, lines_scanned=50))
        report.add_result(ScanResult(findings=[_f(), _f()], files_scanned=3, lines_scanned=75))
        assert report.total_findings == 3
        assert report.total_files_scanned == 5
        assert report.total_lines_scanned == 125

    def test_severity_counts(self):
        report = ScanReport()
        report.add_result(ScanResult(findings=[
            _f(severity=Severity.CRITICAL),
            _f(severity=Severity.HIGH),
            _f(severity=Severity.HIGH),
        ]))
        counts = report.severity_counts
        assert counts["critical"] == 1
        assert counts["high"] == 2

    def test_top_rules(self):
        report = ScanReport()
        report.add_result(ScanResult(findings=[
            _f(rule_id="aws-key"),
            _f(rule_id="aws-key"),
            _f(rule_id="password"),
        ]))
        top = report.top_rules
        assert top[0] == ("aws-key", 2)

    def test_affected_files(self):
        report = ScanReport()
        report.add_result(ScanResult(findings=[
            _f(file_path="a.py"),
            _f(file_path="b.py"),
            _f(file_path="a.py"),
        ]))
        files = report.affected_files
        assert files == ["a.py", "b.py"]

    def test_pass_fail(self):
        report = ScanReport()
        assert report.pass_fail == "PASS"
        report.add_result(ScanResult(findings=[_f()]))
        assert report.pass_fail == "FAIL"

    def test_risk_score(self):
        report = ScanReport()
        report.add_result(ScanResult(findings=[
            _f(severity=Severity.CRITICAL),  # 10
            _f(severity=Severity.LOW),       # 2
        ]))
        assert report.total_risk_score == 12

    def test_to_dict(self):
        report = ScanReport(project_name="myproj")
        report.add_result(ScanResult(findings=[_f()], files_scanned=1))
        d = report.to_dict()
        assert d["project"] == "myproj"
        assert d["status"] == "FAIL"
        assert d["summary"]["total_findings"] == 1

    def test_to_json(self):
        report = ScanReport()
        j = report.to_json()
        data = json.loads(j)
        assert data["status"] == "PASS"

    def test_to_json_compact(self):
        report = ScanReport()
        j = report.to_json(pretty=False)
        assert "\n" not in j

    def test_to_markdown(self):
        report = ScanReport(project_name="proj")
        report.add_result(ScanResult(findings=[
            _f(severity=Severity.CRITICAL, file_path="secret.py"),
        ], files_scanned=5, lines_scanned=200))
        md = report.to_markdown()
        assert "# Security Scan Report" in md
        assert "proj" in md
        assert "FAIL" in md
        assert "CRITICAL" in md
        assert "secret.py" in md

    def test_to_markdown_clean(self):
        report = ScanReport()
        md = report.to_markdown()
        assert "PASS" in md

    def test_generated_at(self):
        report = ScanReport()
        assert report.generated_at != ""
        assert "T" in report.generated_at  # ISO format

    def test_category_counts(self):
        report = ScanReport()
        report.add_result(ScanResult(findings=[
            _f(rule_id="aws-key"),
            _f(rule_id="aws-secret"),
            _f(rule_id="generic-password"),
        ]))
        cats = report.category_counts
        assert cats["aws"] == 2
        assert cats["generic"] == 1
