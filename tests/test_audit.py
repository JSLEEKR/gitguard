"""Tests for audit logging and finding export."""

import csv
import io
import json

import pytest

from gitguard.models import Finding, ScanResult, Severity
from gitguard.audit import AuditEntry, AuditLog, export_findings_csv, export_findings_jsonl


def _f(rule_id="test", severity=Severity.HIGH, file_path="app.py", line=1):
    return Finding(
        rule_id=rule_id, rule_name=rule_id, severity=severity,
        file_path=file_path, line_number=line, line_content="x",
        match_text="secret123",
    )


class TestAuditLog:
    def test_empty_log(self):
        log = AuditLog()
        assert log.total_scans == 0
        assert log.failed_scans == 0
        assert log.passed_scans == 0

    def test_record_pass(self):
        log = AuditLog()
        result = ScanResult(files_scanned=5)
        entry = log.record(result, scan_type="diff")
        assert entry.status == "PASS"
        assert log.total_scans == 1
        assert log.passed_scans == 1

    def test_record_fail(self):
        log = AuditLog()
        result = ScanResult(findings=[_f()])
        entry = log.record(result)
        assert entry.status == "FAIL"
        assert log.failed_scans == 1

    def test_record_details(self):
        log = AuditLog()
        result = ScanResult()
        entry = log.record(result, scan_type="baseline", branch="main")
        assert entry.details["branch"] == "main"
        assert entry.scan_type == "baseline"

    def test_entries_list(self):
        log = AuditLog()
        log.record(ScanResult())
        log.record(ScanResult())
        assert len(log.entries) == 2

    def test_to_json(self):
        log = AuditLog()
        log.record(ScanResult(findings=[_f()]))
        j = log.to_json()
        data = json.loads(j)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["status"] == "FAIL"

    def test_to_json_compact(self):
        log = AuditLog()
        log.record(ScanResult())
        j = log.to_json(pretty=False)
        assert "\n" not in j

    def test_clear(self):
        log = AuditLog()
        log.record(ScanResult())
        log.clear()
        assert log.total_scans == 0

    def test_entry_timestamp(self):
        log = AuditLog()
        entry = log.record(ScanResult())
        assert "T" in entry.timestamp


class TestAuditEntry:
    def test_to_dict(self):
        entry = AuditEntry(
            timestamp="2024-01-01T00:00:00Z",
            scan_type="diff",
            status="PASS",
            findings_count=0,
            risk_score=0,
            files_scanned=5,
            scan_time_ms=10.123,
        )
        d = entry.to_dict()
        assert d["timestamp"] == "2024-01-01T00:00:00Z"
        assert d["scan_time_ms"] == 10.12

    def test_to_dict_with_details(self):
        entry = AuditEntry(
            timestamp="now", scan_type="x", status="PASS",
            findings_count=0, risk_score=0, files_scanned=0,
            scan_time_ms=0, details={"branch": "main"},
        )
        d = entry.to_dict()
        assert d["branch"] == "main"


class TestExportCSV:
    def test_empty(self):
        output = export_findings_csv([])
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 1  # Header only

    def test_with_findings(self):
        findings = [_f(rule_id="aws-key"), _f(rule_id="password")]
        output = export_findings_csv(findings)
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 3  # Header + 2 rows
        assert rows[1][0] == "aws-key"

    def test_csv_header(self):
        output = export_findings_csv([])
        reader = csv.reader(io.StringIO(output))
        header = next(reader)
        assert "rule_id" in header
        assert "severity" in header
        assert "file_path" in header


class TestExportJSONL:
    def test_empty(self):
        output = export_findings_jsonl([])
        assert output == ""

    def test_with_findings(self):
        findings = [_f(), _f(line=2)]
        output = export_findings_jsonl(findings)
        lines = output.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            data = json.loads(line)
            assert "rule_id" in data

    def test_single_finding(self):
        output = export_findings_jsonl([_f()])
        data = json.loads(output)
        assert data["rule_id"] == "test"
