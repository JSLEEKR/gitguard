"""Rule testing utility for validating custom rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from gitguard.models import Rule, Severity


@dataclass
class RuleTestCase:
    """A test case for a rule."""
    input_text: str
    should_match: bool
    description: str = ""


@dataclass
class RuleTestResult:
    """Result of testing a rule."""
    rule_id: str
    passed: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.passed + self.failed

    @property
    def success(self) -> bool:
        return self.failed == 0 and self.passed > 0


class RuleTester:
    """Tests rules against sample inputs."""

    @staticmethod
    def test_rule(rule: Rule, test_cases: list[RuleTestCase]) -> RuleTestResult:
        """Test a rule against a list of test cases."""
        result = RuleTestResult(rule_id=rule.id)

        try:
            pattern = re.compile(rule.pattern)
        except re.error as e:
            result.errors.append(f"Invalid pattern: {e}")
            return result

        for tc in test_cases:
            match = pattern.search(tc.input_text)
            matched = match is not None

            if matched == tc.should_match:
                result.passed += 1
            else:
                result.failed += 1
                expected = "match" if tc.should_match else "no match"
                actual = "matched" if matched else "no match"
                desc = f" ({tc.description})" if tc.description else ""
                result.errors.append(
                    f"Expected {expected}, got {actual} for: "
                    f"{tc.input_text[:50]!r}{desc}"
                )

        return result

    @staticmethod
    def validate_rule(rule: Rule) -> list[str]:
        """Validate a rule's configuration."""
        errors: list[str] = []

        if not rule.id:
            errors.append("Rule ID is empty")

        if not rule.name:
            errors.append("Rule name is empty")

        if not rule.pattern:
            errors.append("Rule pattern is empty")
        else:
            try:
                compiled = re.compile(rule.pattern)
                # Check for catastrophic backtracking risk
                if ".*.*" in rule.pattern or ".+.+" in rule.pattern:
                    errors.append("Pattern may cause catastrophic backtracking")
            except re.error as e:
                errors.append(f"Invalid regex: {e}")

        if rule.entropy_threshold is not None:
            if rule.entropy_threshold < 0 or rule.entropy_threshold > 8:
                errors.append("Entropy threshold should be between 0 and 8")

        return errors

    @staticmethod
    def benchmark_rule(rule: Rule, sample_lines: list[str]) -> dict:
        """Benchmark a rule's performance."""
        import time

        try:
            pattern = re.compile(rule.pattern)
        except re.error:
            return {"error": "Invalid pattern"}

        start = time.monotonic()
        matches = 0
        for line in sample_lines:
            if pattern.search(line):
                matches += 1
        elapsed = (time.monotonic() - start) * 1000

        return {
            "rule_id": rule.id,
            "lines_tested": len(sample_lines),
            "matches": matches,
            "time_ms": round(elapsed, 3),
            "lines_per_ms": round(len(sample_lines) / max(elapsed, 0.001), 1),
        }
