"""Severity escalation based on context."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from gitguard.models import Finding, Severity


@dataclass
class EscalationRule:
    """A rule for escalating or de-escalating severity."""
    name: str
    condition: str  # "file_pattern", "multiple_findings", "high_entropy_count"
    value: str | int
    target_severity: Severity


# Default escalation rules
DEFAULT_ESCALATION_RULES = [
    EscalationRule(
        name="production_config",
        condition="file_pattern",
        value="**/production*",
        target_severity=Severity.CRITICAL,
    ),
    EscalationRule(
        name="dockerfile_secrets",
        condition="file_pattern",
        value="Dockerfile*",
        target_severity=Severity.CRITICAL,
    ),
    EscalationRule(
        name="ci_config_secrets",
        condition="file_pattern",
        value=".github/**",
        target_severity=Severity.CRITICAL,
    ),
    EscalationRule(
        name="deploy_scripts",
        condition="file_pattern",
        value="**/deploy*",
        target_severity=Severity.CRITICAL,
    ),
]


def escalate_findings(
    findings: list[Finding],
    rules: list[EscalationRule] | None = None,
) -> list[Finding]:
    """Apply escalation rules to findings."""
    if rules is None:
        rules = DEFAULT_ESCALATION_RULES

    for finding in findings:
        for rule in rules:
            if _matches_condition(finding, rule):
                if rule.target_severity > finding.severity:
                    finding.severity = rule.target_severity
                    finding.description = (
                        f"{finding.description} [escalated by {rule.name}]"
                        if finding.description
                        else f"[escalated by {rule.name}]"
                    )

    return findings


def _matches_condition(finding: Finding, rule: EscalationRule) -> bool:
    """Check if a finding matches an escalation condition."""
    if rule.condition == "file_pattern":
        pattern = str(rule.value)
        path = finding.file_path.replace("\\", "/")
        basename = path.rsplit("/", 1)[-1] if "/" in path else path
        return (
            fnmatch.fnmatch(path, pattern)
            or fnmatch.fnmatch(basename, pattern)
            or fnmatch.fnmatch(path, pattern.replace("**/", ""))
        )
    return False


def calculate_risk_level(findings: list[Finding]) -> str:
    """Calculate overall risk level from findings."""
    if not findings:
        return "none"

    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    total_score = sum(f.severity.weight for f in findings)

    if critical > 0 or total_score >= 30:
        return "critical"
    if high >= 3 or total_score >= 20:
        return "high"
    if total_score >= 10:
        return "medium"
    return "low"
