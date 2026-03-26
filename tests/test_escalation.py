"""Tests for severity escalation."""

import pytest

from gitguard.models import Finding, Severity
from gitguard.escalation import (
    DEFAULT_ESCALATION_RULES,
    EscalationRule,
    calculate_risk_level,
    escalate_findings,
)


def _f(severity=Severity.HIGH, file_path="app.py", **kwargs):
    defaults = {
        "rule_id": "test", "rule_name": "Test", "line_number": 1,
        "line_content": "x", "match_text": "s", "description": "",
    }
    defaults.update(kwargs)
    return Finding(severity=severity, file_path=file_path, **defaults)


class TestEscalateFindings:
    def test_no_escalation(self):
        findings = [_f(severity=Severity.HIGH, file_path="app.py")]
        result = escalate_findings(findings)
        assert result[0].severity == Severity.HIGH

    def test_production_file_escalation(self):
        findings = [_f(severity=Severity.MEDIUM, file_path="production.env")]
        result = escalate_findings(findings)
        assert result[0].severity == Severity.CRITICAL

    def test_dockerfile_escalation(self):
        findings = [_f(severity=Severity.MEDIUM, file_path="Dockerfile")]
        result = escalate_findings(findings)
        assert result[0].severity == Severity.CRITICAL

    def test_ci_config_escalation(self):
        findings = [_f(severity=Severity.MEDIUM, file_path=".github/workflows/deploy.yml")]
        result = escalate_findings(findings)
        assert result[0].severity == Severity.CRITICAL

    def test_deploy_script_escalation(self):
        findings = [_f(severity=Severity.MEDIUM, file_path="scripts/deploy.sh")]
        result = escalate_findings(findings)
        assert result[0].severity == Severity.CRITICAL

    def test_no_downgrade(self):
        # Already CRITICAL, should stay CRITICAL
        findings = [_f(severity=Severity.CRITICAL, file_path="production.env")]
        result = escalate_findings(findings)
        assert result[0].severity == Severity.CRITICAL

    def test_escalation_adds_note(self):
        findings = [_f(severity=Severity.LOW, file_path="Dockerfile")]
        result = escalate_findings(findings)
        assert "escalated" in result[0].description

    def test_custom_rules(self):
        custom = [
            EscalationRule(
                name="sensitive_dir",
                condition="file_pattern",
                value="secrets/*",
                target_severity=Severity.CRITICAL,
            )
        ]
        findings = [_f(severity=Severity.LOW, file_path="secrets/config.py")]
        result = escalate_findings(findings, rules=custom)
        assert result[0].severity == Severity.CRITICAL

    def test_empty_findings(self):
        result = escalate_findings([])
        assert result == []


class TestCalculateRiskLevel:
    def test_no_findings(self):
        assert calculate_risk_level([]) == "none"

    def test_critical_finding(self):
        assert calculate_risk_level([_f(severity=Severity.CRITICAL)]) == "critical"

    def test_multiple_high(self):
        findings = [_f(severity=Severity.HIGH) for _ in range(3)]
        assert calculate_risk_level(findings) == "high"

    def test_medium_score(self):
        findings = [_f(severity=Severity.MEDIUM) for _ in range(3)]
        assert calculate_risk_level(findings) == "medium"

    def test_low_score(self):
        findings = [_f(severity=Severity.LOW)]
        assert calculate_risk_level(findings) == "low"

    def test_high_total_score(self):
        # 5 high = 35 score -> critical
        findings = [_f(severity=Severity.HIGH) for _ in range(5)]
        assert calculate_risk_level(findings) == "critical"


class TestDefaultRules:
    def test_default_rules_exist(self):
        assert len(DEFAULT_ESCALATION_RULES) > 0

    def test_all_default_rules_valid(self):
        for rule in DEFAULT_ESCALATION_RULES:
            assert rule.name
            assert rule.condition == "file_pattern"
            assert isinstance(rule.target_severity, Severity)
