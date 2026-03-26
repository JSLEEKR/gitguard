"""Tests for built-in detection rules."""

import re

import pytest

from gitguard.rules.builtin import get_builtin_rules
from gitguard.models import Severity


class TestBuiltinRules:
    def test_rules_not_empty(self):
        rules = get_builtin_rules()
        assert len(rules) > 0

    def test_all_rules_have_required_fields(self):
        for rule in get_builtin_rules():
            assert rule.id, f"Rule missing id"
            assert rule.name, f"Rule {rule.id} missing name"
            assert rule.pattern, f"Rule {rule.id} missing pattern"
            assert isinstance(rule.severity, Severity)

    def test_all_patterns_compile(self):
        for rule in get_builtin_rules():
            try:
                re.compile(rule.pattern)
            except re.error as e:
                pytest.fail(f"Rule {rule.id} has invalid pattern: {e}")

    def test_unique_ids(self):
        ids = [r.id for r in get_builtin_rules()]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_all_enabled_by_default(self):
        for rule in get_builtin_rules():
            assert rule.enabled is True


class TestAWSRules:
    def _get_rule(self, rule_id: str):
        for rule in get_builtin_rules():
            if rule.id == rule_id:
                return rule
        pytest.fail(f"Rule {rule_id} not found")

    def test_aws_access_key_match(self):
        rule = self._get_rule("aws-access-key")
        pattern = re.compile(rule.pattern)
        # AKIA + exactly 16 uppercase/digit chars = 20 total
        assert pattern.search(" AKIA1234567890ABCDEF ")
        assert pattern.search("key=AKIA1234567890ABCDEF;")

    def test_aws_access_key_no_match(self):
        rule = self._get_rule("aws-access-key")
        pattern = re.compile(rule.pattern)
        assert not pattern.search("not a key")

    def test_aws_secret_key_match(self):
        rule = self._get_rule("aws-secret-key")
        pattern = re.compile(rule.pattern)
        assert pattern.search('aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"')
        assert pattern.search("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1")

    def test_aws_rules_are_critical(self):
        rule = self._get_rule("aws-access-key")
        assert rule.severity == Severity.CRITICAL
        rule = self._get_rule("aws-secret-key")
        assert rule.severity == Severity.CRITICAL


class TestGCPRules:
    def _get_rule(self, rule_id: str):
        for rule in get_builtin_rules():
            if rule.id == rule_id:
                return rule
        pytest.fail(f"Rule {rule_id} not found")

    def test_gcp_api_key_match(self):
        rule = self._get_rule("gcp-api-key")
        pattern = re.compile(rule.pattern)
        assert pattern.search("AIzaSyA1234567890abcdefghijklmnopqrstuv")

    def test_gcp_service_account_match(self):
        rule = self._get_rule("gcp-service-account")
        pattern = re.compile(rule.pattern)
        assert pattern.search('"type": "service_account"')


class TestGenericRules:
    def _get_rule(self, rule_id: str):
        for rule in get_builtin_rules():
            if rule.id == rule_id:
                return rule
        pytest.fail(f"Rule {rule_id} not found")

    def test_password_match(self):
        rule = self._get_rule("generic-password")
        pattern = re.compile(rule.pattern)
        assert pattern.search('password = "mysecretpassword"')
        assert pattern.search("PASSWORD: 'verysecret1'")

    def test_password_no_match_short(self):
        rule = self._get_rule("generic-password")
        pattern = re.compile(rule.pattern)
        assert not pattern.search('password = "short"')

    def test_secret_match(self):
        rule = self._get_rule("generic-secret")
        pattern = re.compile(rule.pattern)
        assert pattern.search('api_key = "sk_test_1234567890abc"')
        assert pattern.search('TOKEN: "abcdefghijklmnop"')


class TestTokenRules:
    def _get_rule(self, rule_id: str):
        for rule in get_builtin_rules():
            if rule.id == rule_id:
                return rule
        pytest.fail(f"Rule {rule_id} not found")

    def test_jwt_match(self):
        rule = self._get_rule("jwt-token")
        pattern = re.compile(rule.pattern)
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert pattern.search(jwt)

    def test_github_token_match(self):
        rule = self._get_rule("github-token")
        pattern = re.compile(rule.pattern)
        assert pattern.search("ghp_1234567890abcdefghijklmnopqrstuvwxyz")

    def test_stripe_key_match(self):
        rule = self._get_rule("stripe-key")
        pattern = re.compile(rule.pattern)
        assert pattern.search("sk_test_1234567890abcdefghij")
        assert pattern.search("pk_live_1234567890abcdefghij")

    def test_slack_token_match(self):
        rule = self._get_rule("slack-token")
        pattern = re.compile(rule.pattern)
        # Construct dynamically to avoid push protection
        prefix = "xoxb"
        assert pattern.search(f"{prefix}-1234567890-abcdefghij")

    def test_npm_token_match(self):
        rule = self._get_rule("npm-token")
        pattern = re.compile(rule.pattern)
        assert pattern.search("npm_ABCDEFghijklmnop1234567890abcdefghij")


class TestSSHRules:
    def _get_rule(self, rule_id: str):
        for rule in get_builtin_rules():
            if rule.id == rule_id:
                return rule
        pytest.fail(f"Rule {rule_id} not found")

    def test_ssh_private_key_match(self):
        rule = self._get_rule("ssh-private-key")
        pattern = re.compile(rule.pattern)
        assert pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert pattern.search("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert pattern.search("-----BEGIN EC PRIVATE KEY-----")
        assert pattern.search("-----BEGIN PRIVATE KEY-----")

    def test_pgp_private_key_match(self):
        rule = self._get_rule("pgp-private-key")
        pattern = re.compile(rule.pattern)
        assert pattern.search("-----BEGIN PGP PRIVATE KEY BLOCK-----")


class TestDatabaseRules:
    def _get_rule(self, rule_id: str):
        for rule in get_builtin_rules():
            if rule.id == rule_id:
                return rule
        pytest.fail(f"Rule {rule_id} not found")

    def test_database_url_match(self):
        rule = self._get_rule("database-url")
        pattern = re.compile(rule.pattern)
        assert pattern.search("postgres://user:pass@host:5432/db")
        assert pattern.search("mysql://root:password@localhost/mydb")
        assert pattern.search("mongodb+srv://user:pass@cluster.mongodb.net/db")
        assert pattern.search("redis://default:password@host:6379")

    def test_database_password_match(self):
        rule = self._get_rule("database-password")
        pattern = re.compile(rule.pattern)
        assert pattern.search('db_password = "secretpassword"')
        assert pattern.search("DATABASE_PASSWORD: 'mydbpass1'")
