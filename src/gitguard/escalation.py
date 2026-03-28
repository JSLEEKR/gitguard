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
    """Apply escalation rules to findings.

    Returns a new list with escalated copies; original findings are not mutated.
    """
    if rules is None:
        rules = DEFAULT_ESCALATION_RULES

    result: list[Finding] = []
    for finding in findings:
        escalated = False
        for rule in rules:
            if _matches_condition(finding, rule):
                if rule.target_severity > finding.severity:
                    # Create a new Finding with escalated severity to avoid mutating the original
                    new_desc = (
                        f"{finding.description} [escalated by {rule.name}]"
                        if finding.description
                        else f"[escalated by {rule.name}]"
                    )
                    finding = Finding(
                        rule_id=finding.rule_id,
                        rule_name=finding.rule_name,
                        severity=rule.target_severity,
                        file_path=finding.file_path,
                        line_number=finding.line_number,
                        line_content=finding.line_content,
                        match_text=finding.match_text,
                        description=new_desc,
                        masked_match=finding.masked_match,
                    )
                    escalated = True
        result.append(finding)

    return result


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
