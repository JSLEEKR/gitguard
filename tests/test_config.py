"""Tests for configuration management."""

import pytest
from pathlib import Path

from gitguard.config import find_config_file, generate_default_config, load_config
from gitguard.models import Severity


class TestFindConfigFile:
    def test_find_in_current_dir(self, tmp_path):
        config = tmp_path / ".gitguard.yml"
        config.write_text("settings: {}")
        found = find_config_file(tmp_path)
        assert found == config

    def test_find_yaml_extension(self, tmp_path):
        config = tmp_path / ".gitguard.yaml"
        config.write_text("settings: {}")
        found = find_config_file(tmp_path)
        assert found == config

    def test_find_without_dot(self, tmp_path):
        config = tmp_path / "gitguard.yml"
        config.write_text("settings: {}")
        found = find_config_file(tmp_path)
        assert found == config

    def test_not_found(self, tmp_path):
        found = find_config_file(tmp_path)
        assert found is None

    def test_find_in_parent(self, tmp_path):
        config = tmp_path / ".gitguard.yml"
        config.write_text("settings: {}")
        sub = tmp_path / "sub" / "deep"
        sub.mkdir(parents=True)
        found = find_config_file(sub)
        assert found == config


class TestLoadConfig:
    def test_default_config(self):
        config = load_config()
        assert len(config.rules) > 0
        assert config.max_file_size_kb == 500

    def test_nonexistent_path(self):
        config = load_config("/nonexistent/config.yml")
        assert len(config.rules) > 0  # Falls back to defaults

    def test_load_with_settings(self, tmp_path):
        cfg = tmp_path / ".gitguard.yml"
        cfg.write_text("""
settings:
  max_file_size_kb: 1000
  min_severity: high
  entropy_enabled: false
  scan_all_files: true
""")
        config = load_config(str(cfg))
        assert config.max_file_size_kb == 1000
        assert config.min_severity == Severity.HIGH
        assert config.entropy_enabled is False
        assert config.scan_all_files is True

    def test_load_with_allowlist(self, tmp_path):
        cfg = tmp_path / ".gitguard.yml"
        cfg.write_text("""
allowlist:
  patterns:
    - "EXAMPLE"
    - "test_"
  paths:
    - "*.test.py"
    - "fixtures/*"
""")
        config = load_config(str(cfg))
        assert "EXAMPLE" in config.allowlist_patterns
        assert "*.test.py" in config.allowlist_paths

    def test_load_with_list_allowlist(self, tmp_path):
        cfg = tmp_path / ".gitguard.yml"
        cfg.write_text("""
allowlist:
  - "pattern1"
  - "pattern2"
""")
        config = load_config(str(cfg))
        assert len(config.allowlist_patterns) == 2

    def test_load_with_disabled_rules(self, tmp_path):
        cfg = tmp_path / ".gitguard.yml"
        cfg.write_text("""
disabled_rules:
  - generic-password
  - crypto-private-key
""")
        config = load_config(str(cfg))
        for rule in config.rules:
            if rule.id in ("generic-password", "crypto-private-key"):
                assert rule.enabled is False

    def test_load_with_custom_rules(self, tmp_path):
        cfg = tmp_path / ".gitguard.yml"
        cfg.write_text("rules:\n  - id: custom-1\n    name: Custom Rule\n    pattern: 'CUSTOM_\\w+'\n    severity: high\n")
        config = load_config(str(cfg))
        custom = [r for r in config.rules if r.id == "custom-1"]
        assert len(custom) == 1

    def test_load_empty_file(self, tmp_path):
        cfg = tmp_path / ".gitguard.yml"
        cfg.write_text("")
        config = load_config(str(cfg))
        assert len(config.rules) > 0  # Still has builtins

    def test_invalid_severity_ignored(self, tmp_path):
        cfg = tmp_path / ".gitguard.yml"
        cfg.write_text("""
settings:
  min_severity: invalid
""")
        config = load_config(str(cfg))
        assert config.min_severity == Severity.LOW  # Default


class TestGenerateDefaultConfig:
    def test_generates_yaml(self):
        config_str = generate_default_config()
        assert "settings:" in config_str
        assert "allowlist:" in config_str
        assert "disabled_rules:" in config_str

    def test_valid_yaml(self):
        import yaml
        config_str = generate_default_config()
        data = yaml.safe_load(config_str)
        assert isinstance(data, dict)
        assert "settings" in data
