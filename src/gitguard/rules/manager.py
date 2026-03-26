"""Rule manager for merging, overriding, and filtering rules."""

from __future__ import annotations

from gitguard.models import Rule, Severity


class RuleManager:
    """Manages rules: merge, override, filter, and group."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules: dict[str, Rule] = {}
        if rules:
            for rule in rules:
                self._rules[rule.id] = rule

    def add_rule(self, rule: Rule) -> None:
        """Add or replace a rule."""
        self._rules[rule.id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Returns True if found."""
        return self._rules.pop(rule_id, None) is not None

    def get_rule(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def override_severity(self, rule_id: str, severity: Severity) -> bool:
        """Override the severity of a rule."""
        rule = self._rules.get(rule_id)
        if rule is None:
            return False
        rule.severity = severity
        return True

    def enable_rule(self, rule_id: str) -> bool:
        rule = self._rules.get(rule_id)
        if rule is None:
            return False
        rule.enabled = True
        return True

    def disable_rule(self, rule_id: str) -> bool:
        rule = self._rules.get(rule_id)
        if rule is None:
            return False
        rule.enabled = False
        return True

    def enable_category(self, category: str) -> int:
        count = 0
        for rule in self._rules.values():
            if rule.category == category:
                rule.enabled = True
                count += 1
        return count

    def disable_category(self, category: str) -> int:
        count = 0
        for rule in self._rules.values():
            if rule.category == category:
                rule.enabled = False
                count += 1
        return count

    def merge_rules(self, rules: list[Rule], override: bool = False) -> None:
        """Merge rules. If override is True, replace existing rules."""
        for rule in rules:
            if override or rule.id not in self._rules:
                self._rules[rule.id] = rule

    def filter_by_severity(self, min_severity: Severity) -> list[Rule]:
        """Get rules at or above a minimum severity."""
        return [r for r in self._rules.values() if r.severity >= min_severity]

    def filter_by_category(self, category: str) -> list[Rule]:
        return [r for r in self._rules.values() if r.category == category]

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules.values())

    @property
    def enabled_rules(self) -> list[Rule]:
        return [r for r in self._rules.values() if r.enabled]

    @property
    def disabled_rules(self) -> list[Rule]:
        return [r for r in self._rules.values() if not r.enabled]

    @property
    def categories(self) -> list[str]:
        return sorted(set(r.category for r in self._rules.values()))

    def __len__(self) -> int:
        return len(self._rules)

    def stats(self) -> dict:
        return {
            "total": len(self._rules),
            "enabled": len(self.enabled_rules),
            "disabled": len(self.disabled_rules),
            "categories": len(self.categories),
        }
