"""Tests for rule manager."""

import pytest

from gitguard.models import Rule, Severity
from gitguard.rules.manager import RuleManager


def _r(id="test", severity=Severity.HIGH, category="general", enabled=True):
    return Rule(id=id, name=id, pattern="p", severity=severity,
                category=category, enabled=enabled)


class TestRuleManager:
    def test_empty_manager(self):
        rm = RuleManager()
        assert len(rm) == 0

    def test_init_with_rules(self):
        rm = RuleManager([_r("a"), _r("b")])
        assert len(rm) == 2

    def test_add_rule(self):
        rm = RuleManager()
        rm.add_rule(_r("new"))
        assert rm.get_rule("new") is not None

    def test_remove_rule(self):
        rm = RuleManager([_r("a")])
        assert rm.remove_rule("a") is True
        assert rm.get_rule("a") is None

    def test_remove_nonexistent(self):
        rm = RuleManager()
        assert rm.remove_rule("nope") is False

    def test_override_severity(self):
        rm = RuleManager([_r("a", severity=Severity.LOW)])
        assert rm.override_severity("a", Severity.CRITICAL)
        assert rm.get_rule("a").severity == Severity.CRITICAL

    def test_override_severity_nonexistent(self):
        rm = RuleManager()
        assert rm.override_severity("nope", Severity.HIGH) is False

    def test_enable_disable_rule(self):
        rm = RuleManager([_r("a")])
        rm.disable_rule("a")
        assert not rm.get_rule("a").enabled
        rm.enable_rule("a")
        assert rm.get_rule("a").enabled

    def test_enable_disable_nonexistent(self):
        rm = RuleManager()
        assert rm.enable_rule("nope") is False
        assert rm.disable_rule("nope") is False

    def test_enable_disable_category(self):
        rm = RuleManager([_r("a", category="aws"), _r("b", category="aws"), _r("c", category="gcp")])
        count = rm.disable_category("aws")
        assert count == 2
        assert not rm.get_rule("a").enabled
        assert rm.get_rule("c").enabled
        count = rm.enable_category("aws")
        assert count == 2

    def test_merge_rules(self):
        rm = RuleManager([_r("a")])
        rm.merge_rules([_r("b"), _r("c")])
        assert len(rm) == 3

    def test_merge_no_override(self):
        rm = RuleManager([_r("a", severity=Severity.HIGH)])
        rm.merge_rules([_r("a", severity=Severity.LOW)], override=False)
        assert rm.get_rule("a").severity == Severity.HIGH

    def test_merge_with_override(self):
        rm = RuleManager([_r("a", severity=Severity.HIGH)])
        rm.merge_rules([_r("a", severity=Severity.LOW)], override=True)
        assert rm.get_rule("a").severity == Severity.LOW

    def test_filter_by_severity(self):
        rm = RuleManager([
            _r("a", severity=Severity.CRITICAL),
            _r("b", severity=Severity.HIGH),
            _r("c", severity=Severity.LOW),
        ])
        filtered = rm.filter_by_severity(Severity.HIGH)
        ids = {r.id for r in filtered}
        assert "a" in ids
        assert "b" in ids
        assert "c" not in ids

    def test_filter_by_category(self):
        rm = RuleManager([_r("a", category="aws"), _r("b", category="gcp")])
        filtered = rm.filter_by_category("aws")
        assert len(filtered) == 1

    def test_enabled_disabled_rules(self):
        rm = RuleManager([_r("a", enabled=True), _r("b", enabled=False)])
        assert len(rm.enabled_rules) == 1
        assert len(rm.disabled_rules) == 1

    def test_categories(self):
        rm = RuleManager([_r("a", category="aws"), _r("b", category="gcp"), _r("c", category="aws")])
        assert rm.categories == ["aws", "gcp"]

    def test_stats(self):
        rm = RuleManager([_r("a"), _r("b", enabled=False)])
        s = rm.stats()
        assert s["total"] == 2
        assert s["enabled"] == 1
        assert s["disabled"] == 1
