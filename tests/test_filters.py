"""Tests for finding filters and deduplication."""

import pytest

from gitguard.models import Finding, ScanResult, Severity
from gitguard.filters import (
    apply_filters,
    deduplicate_findings,
    filter_by_files,
    filter_by_rules,
    filter_by_severity,
    group_findings,
    sort_findings,
)


def _f(rule_id="test", severity=Severity.HIGH, file_path="app.py", line=1):
    return Finding(
        rule_id=rule_id, rule_name=rule_id, severity=severity,
        file_path=file_path, line_number=line, line_content="x",
        match_text="secret",
    )


class TestDeduplicate:
    def test_no_duplicates(self):
        findings = [_f(line=1), _f(line=2)]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_remove_duplicates(self):
        findings = [_f(line=1), _f(line=1), _f(line=1)]
        result = deduplicate_findings(findings)
        assert len(result) == 1

    def test_different_rules_not_deduped(self):
        findings = [_f(rule_id="a", line=1), _f(rule_id="b", line=1)]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_different_files_not_deduped(self):
        findings = [_f(file_path="a.py"), _f(file_path="b.py")]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_empty_list(self):
        assert deduplicate_findings([]) == []


class TestFilterBySeverity:
    def test_filter_high(self):
        findings = [
            _f(severity=Severity.CRITICAL),
            _f(severity=Severity.HIGH),
            _f(severity=Severity.LOW),
        ]
        result = filter_by_severity(findings, Severity.HIGH)
        assert len(result) == 2

    def test_filter_critical_only(self):
        findings = [_f(severity=Severity.HIGH), _f(severity=Severity.LOW)]
        result = filter_by_severity(findings, Severity.CRITICAL)
        assert len(result) == 0

    def test_filter_all(self):
        findings = [_f(severity=Severity.INFO)]
        result = filter_by_severity(findings, Severity.INFO)
        assert len(result) == 1


class TestFilterByRules:
    def test_include_rules(self):
        findings = [_f(rule_id="a"), _f(rule_id="b"), _f(rule_id="c")]
        result = filter_by_rules(findings, {"a", "b"})
        assert len(result) == 2

    def test_exclude_rules(self):
        findings = [_f(rule_id="a"), _f(rule_id="b"), _f(rule_id="c")]
        result = filter_by_rules(findings, {"a"}, exclude=True)
        assert len(result) == 2
        assert all(f.rule_id != "a" for f in result)


class TestFilterByFiles:
    def test_include_files(self):
        findings = [_f(file_path="a.py"), _f(file_path="b.js")]
        result = filter_by_files(findings, ["*.py"])
        assert len(result) == 1

    def test_exclude_files(self):
        findings = [_f(file_path="a.py"), _f(file_path="test_a.py")]
        result = filter_by_files(findings, ["test_*"], exclude=True)
        assert len(result) == 1
        assert result[0].file_path == "a.py"


class TestSortFindings:
    def test_sort_by_severity(self):
        findings = [_f(severity=Severity.LOW), _f(severity=Severity.CRITICAL)]
        result = sort_findings(findings, by="severity")
        assert result[0].severity == Severity.CRITICAL

    def test_sort_by_file(self):
        findings = [_f(file_path="b.py"), _f(file_path="a.py")]
        result = sort_findings(findings, by="file")
        assert result[0].file_path == "a.py"

    def test_sort_by_line(self):
        findings = [_f(line=10), _f(line=1)]
        result = sort_findings(findings, by="line")
        assert result[0].line_number == 1

    def test_sort_by_rule(self):
        findings = [_f(rule_id="z"), _f(rule_id="a")]
        result = sort_findings(findings, by="rule")
        assert result[0].rule_id == "a"

    def test_sort_unknown_key(self):
        findings = [_f()]
        result = sort_findings(findings, by="unknown")
        assert len(result) == 1


class TestGroupFindings:
    def test_group_by_file(self):
        findings = [_f(file_path="a.py"), _f(file_path="a.py"), _f(file_path="b.py")]
        groups = group_findings(findings, by="file")
        assert len(groups["a.py"]) == 2
        assert len(groups["b.py"]) == 1

    def test_group_by_rule(self):
        findings = [_f(rule_id="r1"), _f(rule_id="r2"), _f(rule_id="r1")]
        groups = group_findings(findings, by="rule")
        assert len(groups["r1"]) == 2

    def test_group_by_severity(self):
        findings = [_f(severity=Severity.HIGH), _f(severity=Severity.LOW)]
        groups = group_findings(findings, by="severity")
        assert "high" in groups
        assert "low" in groups

    def test_group_by_unknown(self):
        findings = [_f()]
        groups = group_findings(findings, by="unknown")
        assert "all" in groups


class TestApplyFilters:
    def test_apply_all_filters(self):
        findings = [
            _f(rule_id="a", severity=Severity.HIGH, file_path="src/app.py", line=1),
            _f(rule_id="a", severity=Severity.HIGH, file_path="src/app.py", line=1),  # dup
            _f(rule_id="b", severity=Severity.LOW, file_path="test_app.py", line=1),
            _f(rule_id="c", severity=Severity.CRITICAL, file_path="src/main.py", line=5),
        ]
        result = ScanResult(findings=findings, files_scanned=3)
        filtered = apply_filters(
            result,
            min_severity=Severity.HIGH,
            exclude_files=["test_*"],
            deduplicate=True,
        )
        assert len(filtered.findings) == 2
        assert filtered.files_scanned == 3  # Preserved

    def test_apply_no_filters(self):
        result = ScanResult(findings=[_f()])
        filtered = apply_filters(result, deduplicate=False)
        assert len(filtered.findings) == 1

    def test_apply_include_rules(self):
        result = ScanResult(findings=[_f(rule_id="a"), _f(rule_id="b")])
        filtered = apply_filters(result, include_rules={"a"})
        assert len(filtered.findings) == 1

    def test_apply_include_files(self):
        result = ScanResult(findings=[_f(file_path="src/a.py"), _f(file_path="lib/b.py")])
        filtered = apply_filters(result, include_files=["src/*"])
        assert len(filtered.findings) == 1
