"""Tests for YAML rule loader."""

import tempfile
from pathlib import Path

import pytest

from gitguard.models import Severity
from gitguard.rules.loader import RuleLoader


class TestRuleLoaderFromString:
    def test_load_valid_rules(self):
        yaml_str = """
rules:
  - id: custom-1
    name: Custom Rule 1
    pattern: "CUSTOM_[A-Z0-9]{32}"
    severity: high
    description: Custom pattern
"""
        rules = RuleLoader.load_from_string(yaml_str)
        assert len(rules) == 1
        assert rules[0].id == "custom-1"
        assert rules[0].severity == Severity.HIGH

    def test_load_multiple_rules(self):
        yaml_str = """
rules:
  - id: r1
    name: Rule 1
    pattern: "pattern1"
    severity: high
  - id: r2
    name: Rule 2
    pattern: "pattern2"
    severity: low
"""
        rules = RuleLoader.load_from_string(yaml_str)
        assert len(rules) == 2

    def test_load_empty(self):
        rules = RuleLoader.load_from_string("")
        assert rules == []

    def test_load_list_format(self):
        yaml_str = """
- id: r1
  name: Rule 1
  pattern: "p1"
  severity: medium
"""
        rules = RuleLoader.load_from_string(yaml_str)
        assert len(rules) == 1

    def test_missing_required_field(self):
        yaml_str = """
rules:
  - id: r1
    name: Rule 1
    severity: high
"""
        with pytest.raises(ValueError, match="Missing required field"):
            RuleLoader.load_from_string(yaml_str)

    def test_invalid_severity(self):
        yaml_str = """
rules:
  - id: r1
    name: Rule 1
    pattern: "p"
    severity: extreme
"""
        with pytest.raises(ValueError, match="Invalid severity"):
            RuleLoader.load_from_string(yaml_str)

    def test_invalid_regex(self):
        yaml_str = """
rules:
  - id: r1
    name: Rule 1
    pattern: "[invalid"
    severity: high
"""
        with pytest.raises(ValueError, match="Invalid regex"):
            RuleLoader.load_from_string(yaml_str)

    def test_non_dict_rule(self):
        yaml_str = """
rules:
  - "just a string"
"""
        with pytest.raises(ValueError, match="must be a dictionary"):
            RuleLoader.load_from_string(yaml_str)

    def test_invalid_top_level(self):
        yaml_str = "just a string"
        with pytest.raises(ValueError, match="Invalid rule format"):
            RuleLoader.load_from_string(yaml_str)

    def test_rules_not_list(self):
        yaml_str = """
rules:
  id: r1
"""
        with pytest.raises(ValueError, match="must be a list"):
            RuleLoader.load_from_string(yaml_str)

    def test_optional_fields(self):
        yaml_str = """
rules:
  - id: r1
    name: Rule 1
    pattern: "p"
    severity: high
    category: custom
    entropy_threshold: 4.5
    allowlist:
      - "test"
    file_patterns:
      - "*.py"
    enabled: false
"""
        rules = RuleLoader.load_from_string(yaml_str)
        r = rules[0]
        assert r.category == "custom"
        assert r.entropy_threshold == 4.5
        assert r.allowlist == ["test"]
        assert r.file_patterns == ["*.py"]
        assert r.enabled is False


class TestRuleLoaderFromFile:
    def test_load_valid_file(self, tmp_path):
        rule_file = tmp_path / "rules.yml"
        rule_file.write_text("""
rules:
  - id: file-rule
    name: File Rule
    pattern: "FILE_SECRET"
    severity: medium
""")
        rules = RuleLoader.load_from_file(str(rule_file))
        assert len(rules) == 1

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            RuleLoader.load_from_file("/nonexistent/rules.yml")

    def test_empty_file(self, tmp_path):
        rule_file = tmp_path / "empty.yml"
        rule_file.write_text("")
        rules = RuleLoader.load_from_file(str(rule_file))
        assert rules == []


class TestRuleValidation:
    def test_validate_valid_file(self, tmp_path):
        rule_file = tmp_path / "rules.yml"
        rule_file.write_text("""
rules:
  - id: r1
    name: R1
    pattern: "p1"
    severity: high
""")
        errors = RuleLoader.validate_rule_file(str(rule_file))
        assert errors == []

    def test_validate_missing_fields(self, tmp_path):
        rule_file = tmp_path / "rules.yml"
        rule_file.write_text("""
rules:
  - id: r1
""")
        errors = RuleLoader.validate_rule_file(str(rule_file))
        assert len(errors) > 0

    def test_validate_invalid_severity(self, tmp_path):
        rule_file = tmp_path / "rules.yml"
        rule_file.write_text("""
rules:
  - id: r1
    name: R1
    pattern: "p"
    severity: extreme
""")
        errors = RuleLoader.validate_rule_file(str(rule_file))
        assert any("invalid severity" in e for e in errors)

    def test_validate_invalid_regex(self, tmp_path):
        rule_file = tmp_path / "rules.yml"
        rule_file.write_text("""
rules:
  - id: r1
    name: R1
    pattern: "[unclosed"
    severity: high
""")
        errors = RuleLoader.validate_rule_file(str(rule_file))
        assert any("invalid regex" in e for e in errors)

    def test_validate_nonexistent_file(self):
        errors = RuleLoader.validate_rule_file("/no/such/file.yml")
        assert len(errors) == 1
        assert "not found" in errors[0]

    def test_validate_invalid_yaml(self, tmp_path):
        rule_file = tmp_path / "bad.yml"
        rule_file.write_text("{{invalid yaml")
        errors = RuleLoader.validate_rule_file(str(rule_file))
        assert any("YAML" in e or "parse" in e.lower() for e in errors)

    def test_validate_empty_file(self, tmp_path):
        rule_file = tmp_path / "empty.yml"
        rule_file.write_text("")
        errors = RuleLoader.validate_rule_file(str(rule_file))
        assert any("empty" in e.lower() for e in errors)

    def test_validate_non_dict_rule(self, tmp_path):
        rule_file = tmp_path / "rules.yml"
        rule_file.write_text("""
rules:
  - "string rule"
""")
        errors = RuleLoader.validate_rule_file(str(rule_file))
        assert any("dictionary" in e for e in errors)

    def test_validate_invalid_format(self, tmp_path):
        rule_file = tmp_path / "rules.yml"
        rule_file.write_text("42")
        errors = RuleLoader.validate_rule_file(str(rule_file))
        assert any("format" in e.lower() or "invalid" in e.lower() for e in errors)
