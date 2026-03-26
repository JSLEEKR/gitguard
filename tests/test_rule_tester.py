"""Tests for rule testing utility."""

import pytest

from gitguard.models import Rule, Severity
from gitguard.rules.tester import RuleTestCase, RuleTester


def _r(pattern=r"SECRET_\w+", **kwargs):
    defaults = {"id": "test", "name": "Test", "severity": Severity.HIGH}
    defaults.update(kwargs)
    return Rule(pattern=pattern, **defaults)


class TestRuleTester:
    def test_all_pass(self):
        rule = _r(pattern=r"SECRET_\w+")
        cases = [
            RuleTestCase("SECRET_KEY", should_match=True),
            RuleTestCase("normal text", should_match=False),
        ]
        result = RuleTester.test_rule(rule, cases)
        assert result.success
        assert result.passed == 2
        assert result.failed == 0

    def test_failure(self):
        rule = _r(pattern=r"SECRET_\w+")
        cases = [
            RuleTestCase("SECRET_KEY", should_match=False),  # Wrong expectation
        ]
        result = RuleTester.test_rule(rule, cases)
        assert not result.success
        assert result.failed == 1
        assert len(result.errors) == 1

    def test_invalid_pattern(self):
        rule = _r(pattern="[invalid")
        cases = [RuleTestCase("anything", should_match=True)]
        result = RuleTester.test_rule(rule, cases)
        assert not result.success
        assert "Invalid pattern" in result.errors[0]

    def test_empty_test_cases(self):
        rule = _r()
        result = RuleTester.test_rule(rule, [])
        assert result.total == 0
        assert not result.success  # No passes

    def test_description_in_error(self):
        rule = _r(pattern=r"MATCH")
        cases = [
            RuleTestCase("no match", should_match=True, description="should find MATCH"),
        ]
        result = RuleTester.test_rule(rule, cases)
        assert "should find MATCH" in result.errors[0]

    def test_total_count(self):
        rule = _r()
        cases = [
            RuleTestCase("SECRET_A", should_match=True),
            RuleTestCase("SECRET_B", should_match=True),
            RuleTestCase("clean", should_match=False),
        ]
        result = RuleTester.test_rule(rule, cases)
        assert result.total == 3


class TestRuleValidation:
    def test_valid_rule(self):
        rule = _r()
        errors = RuleTester.validate_rule(rule)
        assert errors == []

    def test_empty_id(self):
        rule = _r(id="")
        errors = RuleTester.validate_rule(rule)
        assert any("ID" in e for e in errors)

    def test_empty_name(self):
        rule = _r(name="")
        errors = RuleTester.validate_rule(rule)
        assert any("name" in e for e in errors)

    def test_empty_pattern(self):
        rule = _r(pattern="")
        errors = RuleTester.validate_rule(rule)
        assert any("pattern" in e for e in errors)

    def test_invalid_pattern(self):
        rule = _r(pattern="[invalid")
        errors = RuleTester.validate_rule(rule)
        assert any("regex" in e.lower() for e in errors)

    def test_backtracking_warning(self):
        rule = _r(pattern=r".*.*secret")
        errors = RuleTester.validate_rule(rule)
        assert any("backtracking" in e for e in errors)

    def test_invalid_entropy_threshold(self):
        rule = _r(entropy_threshold=10.0)
        errors = RuleTester.validate_rule(rule)
        assert any("entropy" in e.lower() for e in errors)

    def test_negative_entropy_threshold(self):
        rule = _r(entropy_threshold=-1.0)
        errors = RuleTester.validate_rule(rule)
        assert any("entropy" in e.lower() for e in errors)

    def test_valid_entropy_threshold(self):
        rule = _r(entropy_threshold=4.5)
        errors = RuleTester.validate_rule(rule)
        assert errors == []


class TestRuleBenchmark:
    def test_basic_benchmark(self):
        rule = _r(pattern=r"SECRET_\w+")
        lines = ["SECRET_KEY = 1", "clean line", "another line"]
        result = RuleTester.benchmark_rule(rule, lines)
        assert result["lines_tested"] == 3
        assert result["matches"] == 1
        assert result["time_ms"] >= 0

    def test_benchmark_invalid_pattern(self):
        rule = _r(pattern="[invalid")
        result = RuleTester.benchmark_rule(rule, ["test"])
        assert "error" in result

    def test_benchmark_empty_lines(self):
        rule = _r()
        result = RuleTester.benchmark_rule(rule, [])
        assert result["lines_tested"] == 0
        assert result["matches"] == 0

    def test_benchmark_many_lines(self):
        rule = _r()
        lines = ["SECRET_KEY = 1" if i % 10 == 0 else f"line {i}" for i in range(1000)]
        result = RuleTester.benchmark_rule(rule, lines)
        assert result["matches"] == 100
        assert result["lines_per_ms"] > 0
