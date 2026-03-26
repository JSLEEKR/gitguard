"""Tests for auto-fix suggestions."""

import pytest

from gitguard.models import Finding, Severity
from gitguard.suggestions import Suggestion, format_suggestions, suggest_fix


def _f(rule_id="test", line_content="x = 1", **kwargs):
    defaults = {
        "rule_name": rule_id,
        "severity": Severity.HIGH,
        "file_path": "app.py",
        "line_number": 10,
        "match_text": "secret",
    }
    defaults.update(kwargs)
    return Finding(rule_id=rule_id, line_content=line_content, **defaults)


class TestSuggestFix:
    def test_password_suggestion(self):
        s = suggest_fix(_f("generic-password", line_content='password = "secret"'))
        assert s.action == "use_env_var"
        assert "environ" in s.fix_text

    def test_aws_key_suggestion(self):
        s = suggest_fix(_f("aws-access-key"))
        assert s.action == "use_aws_config"
        assert "credential" in s.description.lower()

    def test_ssh_key_suggestion(self):
        s = suggest_fix(_f("ssh-private-key"))
        assert s.action == "add_to_gitignore"
        assert "gitignore" in s.fix_text.lower()

    def test_env_file_suggestion(self):
        s = suggest_fix(_f("env-file"))
        assert s.action == "add_to_gitignore"

    def test_database_url_suggestion(self):
        s = suggest_fix(_f("database-url"))
        assert s.action == "use_env_var"
        assert "DATABASE_URL" in s.fix_text

    def test_github_token_suggestion(self):
        s = suggest_fix(_f("github-token"))
        assert s.action == "use_env_var"

    def test_jwt_suggestion(self):
        s = suggest_fix(_f("jwt-token"))
        assert s.action == "remove"

    def test_unknown_rule_suggestion(self):
        s = suggest_fix(_f("unknown-rule-xyz"))
        assert s.action == "review"

    def test_generic_secret_suggestion(self):
        s = suggest_fix(_f("generic-secret", line_content='API_KEY = "abc"'))
        assert s.action == "use_env_var"

    def test_stripe_key_suggestion(self):
        s = suggest_fix(_f("stripe-key"))
        assert s.action == "use_env_var"

    def test_slack_token_suggestion(self):
        s = suggest_fix(_f("slack-token"))
        assert s.action == "use_env_var"

    def test_openai_key_suggestion(self):
        s = suggest_fix(_f("openai-api-key"))
        assert s.action == "use_env_var"

    def test_database_password_suggestion(self):
        s = suggest_fix(_f("database-password"))
        assert s.action == "use_env_var"

    def test_pgp_key_suggestion(self):
        s = suggest_fix(_f("pgp-private-key"))
        assert s.action == "add_to_gitignore"

    def test_private_key_file_suggestion(self):
        s = suggest_fix(_f("private-key-file"))
        assert s.action == "add_to_gitignore"


class TestFormatSuggestions:
    def test_empty(self):
        output = format_suggestions([])
        assert "No suggestions" in output

    def test_with_suggestions(self):
        finding = _f("generic-password")
        s = suggest_fix(finding)
        output = format_suggestions([s])
        assert "Suggestions" in output
        assert "app.py" in output
        assert "generic-password" in output

    def test_multiple_suggestions(self):
        suggestions = [
            suggest_fix(_f("aws-access-key")),
            suggest_fix(_f("generic-password")),
        ]
        output = format_suggestions(suggestions)
        assert "2 findings" in output
