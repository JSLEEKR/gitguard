"""Configuration management for gitguard."""

from __future__ import annotations

from pathlib import Path

import yaml

from gitguard.models import ScanConfig, Severity
from gitguard.rules.builtin import get_builtin_rules
from gitguard.rules.loader import RuleLoader


CONFIG_FILENAMES = [
    ".gitguard.yml",
    ".gitguard.yaml",
    "gitguard.yml",
    "gitguard.yaml",
]


def find_config_file(start_path: str | Path | None = None) -> Path | None:
    """Find a gitguard config file by walking up from start_path."""
    path = Path(start_path) if start_path else Path.cwd()

    for _ in range(20):  # Safety limit
        for name in CONFIG_FILENAMES:
            candidate = path / name
            if candidate.exists():
                return candidate
        parent = path.parent
        if parent == path:
            break
        path = parent

    return None


def load_config(config_path: str | Path | None = None) -> ScanConfig:
    """Load configuration from a YAML file, falling back to defaults."""
    config = ScanConfig()
    config.rules = get_builtin_rules()

    if config_path is None:
        config_path = find_config_file()

    if config_path is None:
        return config

    path = Path(config_path)
    if not path.exists():
        return config

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        return config

    return _apply_config(config, data)


def _apply_config(config: ScanConfig, data: dict) -> ScanConfig:
    """Apply YAML config data to a ScanConfig."""
    # Allowlists
    if "allowlist" in data:
        al = data["allowlist"]
        if isinstance(al, dict):
            config.allowlist_patterns = al.get("patterns", [])
            config.allowlist_paths = al.get("paths", [])
        elif isinstance(al, list):
            config.allowlist_patterns = al

    # Settings
    if "settings" in data:
        settings = data["settings"]
        if "max_file_size_kb" in settings:
            config.max_file_size_kb = int(settings["max_file_size_kb"])
        if "scan_all_files" in settings:
            config.scan_all_files = bool(settings["scan_all_files"])
        if "min_severity" in settings:
            try:
                config.min_severity = Severity(settings["min_severity"].lower())
            except (ValueError, AttributeError):
                pass
        if "entropy_enabled" in settings:
            config.entropy_enabled = bool(settings["entropy_enabled"])

    # Disable specific rules
    if "disabled_rules" in data:
        disabled = set(data["disabled_rules"])
        for rule in config.rules:
            if rule.id in disabled:
                rule.enabled = False

    # Custom rules
    if "rules" in data:
        custom_rules = RuleLoader._parse_rules({"rules": data["rules"]})
        config.rules.extend(custom_rules)

    # Custom rules from file
    if "custom_rules_path" in data:
        config.custom_rules_path = data["custom_rules_path"]
        try:
            custom = RuleLoader.load_from_file(data["custom_rules_path"])
            config.rules.extend(custom)
        except (FileNotFoundError, ValueError):
            pass

    return config


def generate_default_config() -> str:
    """Generate a default configuration YAML string."""
    return """\
# gitguard configuration
# Place this file as .gitguard.yml in your project root

settings:
  max_file_size_kb: 500
  min_severity: low
  entropy_enabled: true

allowlist:
  # Regex patterns to ignore in content
  patterns:
    - "EXAMPLE_KEY"
    - "test_secret"
    - "dummy"

  # File paths to skip (glob patterns)
  paths:
    - "**/*.test.*"
    - "**/*.spec.*"
    - "**/test_*"
    - "**/fixtures/**"
    - "**/testdata/**"

# Rules to disable by ID
disabled_rules: []
  # - generic-password
  # - crypto-private-key

# Custom rules (in addition to built-in rules)
# rules:
#   - id: my-custom-rule
#     name: My Custom Secret
#     pattern: "CUSTOM_[A-Z0-9]{32}"
#     severity: high
#     description: Custom secret pattern
#     category: custom
"""
