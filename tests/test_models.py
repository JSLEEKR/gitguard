"""Tests for core data models."""

import pytest

from gitguard.models import Finding, Rule, ScanConfig, ScanResult, Severity


class TestSeverity:
    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_weights(self):
        assert Severity.CRITICAL.weight == 10
        assert Severity.HIGH.weight == 7
        assert Severity.MEDIUM.weight == 4
        assert Severity.LOW.weight == 2
        assert Severity.INFO.weight == 1

    def test_ordering(self):
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_ordering_le(self):
        assert Severity.INFO <= Severity.LOW
        assert Severity.INFO <= Severity.INFO

    def test_ordering_gt(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM

    def test_ordering_ge(self):
        assert Severity.CRITICAL >= Severity.HIGH
        assert Severity.CRITICAL >= Severity.CRITICAL

    def test_ordering_not_implemented(self):
        assert Severity.CRITICAL.__lt__("other") is NotImplemented
        assert Severity.CRITICAL.__le__("other") is NotImplemented
        assert Severity.CRITICAL.__gt__("other") is NotImplemented
        assert Severity.CRITICAL.__ge__("other") is NotImplemented


class TestRule:
    def test_basic_creation(self):
        rule = Rule(
            id="test-rule",
            name="Test Rule",
            pattern=r"SECRET_\w+",
            severity=Severity.HIGH,
        )
        assert rule.id == "test-rule"
        assert rule.name == "Test Rule"
        assert rule.enabled is True

    def test_defaults(self):
        rule = Rule(id="r", name="R", pattern="p", severity=Severity.LOW)
        assert rule.description == ""
        assert rule.category == "general"
        assert rule.entropy_threshold is None
        assert rule.allowlist == []
        assert rule.file_patterns == []

    def test_to_dict(self):
        rule = Rule(
            id="test",
            name="Test",
            pattern="p",
            severity=Severity.HIGH,
            category="aws",
        )
        d = rule.to_dict()
        assert d["id"] == "test"
        assert d["severity"] == "high"
        assert d["category"] == "aws"
        assert d["enabled"] is True


class TestFinding:
    def test_basic_creation(self):
        f = Finding(
            rule_id="test",
            rule_name="Test",
            severity=Severity.HIGH,
            file_path="app.py",
            line_number=10,
            line_content="secret = 'abc123'",
            match_text="abc123",
        )
        assert f.rule_id == "test"
        assert f.file_path == "app.py"

    def test_masking_short(self):
        f = Finding(
            rule_id="t", rule_name="T", severity=Severity.LOW,
            file_path="f", line_number=1, line_content="x",
            match_text="short",
        )
        assert f.masked_match == "*****"

    def test_masking_long(self):
        f = Finding(
            rule_id="t", rule_name="T", severity=Severity.LOW,
            file_path="f", line_number=1, line_content="x",
            match_text="AKIA1234567890ABCDEF",
        )
        assert f.masked_match.startswith("AKIA")
        assert f.masked_match.endswith("CDEF")
        assert "****" in f.masked_match

    def test_masking_empty(self):
        f = Finding(
            rule_id="t", rule_name="T", severity=Severity.LOW,
            file_path="f", line_number=1, line_content="x",
            match_text="",
        )
        assert f.masked_match == ""

    def test_to_dict(self):
        f = Finding(
            rule_id="test", rule_name="Test", severity=Severity.CRITICAL,
            file_path="main.py", line_number=5, line_content="secret=abc",
            match_text="abc123456789",
        )
        d = f.to_dict()
        assert d["rule_id"] == "test"
        assert d["severity"] == "critical"
        assert d["file_path"] == "main.py"

    def test_line_content_truncation(self):
        long_line = "x" * 300
        f = Finding(
            rule_id="t", rule_name="T", severity=Severity.LOW,
            file_path="f", line_number=1, line_content=long_line,
            match_text="x",
        )
        d = f.to_dict()
        assert len(d["line_content"]) == 200


class TestScanResult:
    def test_empty_result(self):
        r = ScanResult()
        assert r.has_findings is False
        assert r.max_severity is None
        assert r.risk_score == 0

    def test_with_findings(self):
        findings = [
            Finding(rule_id="a", rule_name="A", severity=Severity.HIGH,
                    file_path="f1", line_number=1, line_content="x", match_text="y"),
            Finding(rule_id="b", rule_name="B", severity=Severity.CRITICAL,
                    file_path="f2", line_number=2, line_content="x", match_text="y"),
        ]
        r = ScanResult(findings=findings)
        assert r.has_findings is True
        assert r.max_severity == Severity.CRITICAL
        assert r.risk_score == 17  # 7 + 10

    def test_findings_by_severity(self):
        findings = [
            Finding(rule_id="a", rule_name="A", severity=Severity.HIGH,
                    file_path="f", line_number=1, line_content="x", match_text="y"),
            Finding(rule_id="b", rule_name="B", severity=Severity.HIGH,
                    file_path="f", line_number=2, line_content="x", match_text="y"),
            Finding(rule_id="c", rule_name="C", severity=Severity.LOW,
                    file_path="f", line_number=3, line_content="x", match_text="y"),
        ]
        r = ScanResult(findings=findings)
        assert len(r.findings_by_severity(Severity.HIGH)) == 2
        assert len(r.findings_by_severity(Severity.LOW)) == 1
        assert len(r.findings_by_severity(Severity.CRITICAL)) == 0

    def test_findings_by_file(self):
        findings = [
            Finding(rule_id="a", rule_name="A", severity=Severity.HIGH,
                    file_path="f1.py", line_number=1, line_content="x", match_text="y"),
            Finding(rule_id="b", rule_name="B", severity=Severity.HIGH,
                    file_path="f1.py", line_number=2, line_content="x", match_text="y"),
            Finding(rule_id="c", rule_name="C", severity=Severity.LOW,
                    file_path="f2.py", line_number=1, line_content="x", match_text="y"),
        ]
        r = ScanResult(findings=findings)
        by_file = r.findings_by_file()
        assert len(by_file["f1.py"]) == 2
        assert len(by_file["f2.py"]) == 1

    def test_summary(self):
        findings = [
            Finding(rule_id="a", rule_name="A", severity=Severity.HIGH,
                    file_path="f", line_number=1, line_content="x", match_text="y"),
        ]
        r = ScanResult(findings=findings, files_scanned=5, lines_scanned=100, rules_applied=20)
        s = r.summary()
        assert s["total_findings"] == 1
        assert s["files_scanned"] == 5
        assert s["by_severity"]["high"] == 1


class TestScanConfig:
    def test_defaults(self):
        c = ScanConfig()
        assert c.max_file_size_kb == 500
        assert c.scan_all_files is False
        assert c.min_severity == Severity.LOW
        assert c.entropy_enabled is True
        assert c.custom_rules_path is None
