"""Rule loading from YAML configuration files."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from gitguard.models import Rule, Severity


class RuleLoader:
    """Loads custom rules from YAML configuration files."""

    VALID_SEVERITIES = {s.value for s in Severity}

    @staticmethod
    def load_from_file(path: str | Path) -> list[Rule]:
        """Load rules from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Rule file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data is None:
            return []

        return RuleLoader._parse_rules(data)

    @staticmethod
    def load_from_string(content: str) -> list[Rule]:
        """Load rules from a YAML string."""
        data = yaml.safe_load(content)
        if data is None:
            return []
        return RuleLoader._parse_rules(data)

    @staticmethod
    def _parse_rules(data: dict | list) -> list[Rule]:
        """Parse rules from loaded YAML data."""
        rules_data: list[dict] = []

        if isinstance(data, dict):
            rules_data = data.get("rules", [])
            if not isinstance(rules_data, list):
                raise ValueError("'rules' must be a list")
        elif isinstance(data, list):
            rules_data = data
        else:
            raise ValueError("Invalid rule format: expected dict or list")

        rules: list[Rule] = []
        for i, rule_data in enumerate(rules_data):
            try:
                rule = RuleLoader._parse_single_rule(rule_data)
                rules.append(rule)
            except (KeyError, ValueError) as e:
                raise ValueError(f"Invalid rule at index {i}: {e}") from e

        return rules

    @staticmethod
    def _parse_single_rule(data: dict) -> Rule:
        """Parse a single rule from a dict."""
        if not isinstance(data, dict):
            raise ValueError("Rule must be a dictionary")

        required_fields = ["id", "pattern", "severity"]
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")

        severity_str = data["severity"].lower()
        if severity_str not in RuleLoader.VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity_str}'. Must be one of: {', '.join(RuleLoader.VALID_SEVERITIES)}"
            )

        # Validate regex pattern
        try:
            re.compile(data["pattern"])
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}") from e

        return Rule(
            id=str(data["id"]),
            name=str(data.get("name", data["id"])),
            pattern=data["pattern"],
            severity=Severity(severity_str),
            description=str(data.get("description", "")),
            category=str(data.get("category", "custom")),
            entropy_threshold=data.get("entropy_threshold"),
            allowlist=data.get("allowlist", []),
            file_patterns=data.get("file_patterns", []),
            enabled=data.get("enabled", True),
        )

    @staticmethod
    def validate_rule_file(path: str | Path) -> list[str]:
        """Validate a rule file and return any errors."""
        errors: list[str] = []
        path = Path(path)

        if not path.exists():
            return [f"File not found: {path}"]

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return [f"YAML parse error: {e}"]

        if data is None:
            return ["File is empty"]

        rules_data: list[dict] = []
        if isinstance(data, dict):
            rules_data = data.get("rules", [])
        elif isinstance(data, list):
            rules_data = data
        else:
            return ["Invalid format: expected dict or list"]

        for i, rule_data in enumerate(rules_data):
            if not isinstance(rule_data, dict):
                errors.append(f"Rule {i}: must be a dictionary")
                continue

            for field in ["id", "pattern", "severity"]:
                if field not in rule_data:
                    errors.append(f"Rule {i}: missing required field '{field}'")

            if "severity" in rule_data:
                sev = str(rule_data["severity"]).lower()
                if sev not in RuleLoader.VALID_SEVERITIES:
                    errors.append(f"Rule {i}: invalid severity '{sev}'")

            if "pattern" in rule_data:
                try:
                    re.compile(rule_data["pattern"])
                except re.error as e:
                    errors.append(f"Rule {i}: invalid regex: {e}")

        return errors
