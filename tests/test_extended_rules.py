"""Tests for extended detection rules."""

import re

import pytest

from gitguard.rules.extended import get_extended_rules
from gitguard.models import Severity


class TestExtendedRules:
    def test_rules_not_empty(self):
        rules = get_extended_rules()
        assert len(rules) > 0

    def test_all_rules_valid(self):
        for rule in get_extended_rules():
            assert rule.id
            assert rule.name
            assert rule.pattern
            re.compile(rule.pattern)  # Should not raise

    def test_unique_ids(self):
        ids = [r.id for r in get_extended_rules()]
        assert len(ids) == len(set(ids))

    def test_no_overlap_with_builtin(self):
        from gitguard.rules.builtin import get_builtin_rules
        builtin_ids = {r.id for r in get_builtin_rules()}
        extended_ids = {r.id for r in get_extended_rules()}
        overlap = builtin_ids & extended_ids
        assert len(overlap) == 0, f"Overlapping IDs: {overlap}"


class TestDigitalOceanRules:
    def _find(self, rule_id):
        for r in get_extended_rules():
            if r.id == rule_id:
                return r
        pytest.fail(f"Rule {rule_id} not found")

    def test_do_token_match(self):
        r = self._find("digitalocean-token")
        p = re.compile(r.pattern)
        token = "dop_v1_" + "a1b2c3d4" * 8
        assert p.search(token)

    def test_do_oauth_match(self):
        r = self._find("digitalocean-oauth")
        p = re.compile(r.pattern)
        token = "doo_v1_" + "a1b2c3d4" * 8
        assert p.search(token)


class TestHerokuRules:
    def test_heroku_key_match(self):
        for r in get_extended_rules():
            if r.id == "heroku-api-key":
                p = re.compile(r.pattern)
                assert p.search('HEROKU_API_KEY = "12345678-1234-1234-1234-123456789abc"')
                return
        pytest.fail("heroku-api-key rule not found")


class TestMailgunRules:
    def test_mailgun_key_match(self):
        for r in get_extended_rules():
            if r.id == "mailgun-api-key":
                p = re.compile(r.pattern)
                assert p.search("key-" + "a" * 32)
                return
        pytest.fail("mailgun-api-key not found")


class TestTelegramRules:
    def test_telegram_token_match(self):
        for r in get_extended_rules():
            if r.id == "telegram-bot-token":
                p = re.compile(r.pattern)
                assert p.search("123456789:ABCdefGHIjklMNOpqrsTUVwxyz_12345678")
                return
        pytest.fail("telegram-bot-token not found")


class TestDiscordRules:
    def test_discord_webhook_match(self):
        for r in get_extended_rules():
            if r.id == "discord-webhook":
                p = re.compile(r.pattern)
                assert p.search("https://discord.com/api/webhooks/123456789/abcdef_token-xyz")
                return
        pytest.fail("discord-webhook not found")


class TestFirebaseRules:
    def test_firebase_url_match(self):
        for r in get_extended_rules():
            if r.id == "firebase-url":
                p = re.compile(r.pattern)
                assert p.search("https://my-project-123.firebaseio.com")
                return
        pytest.fail("firebase-url not found")


class TestDockerRules:
    def test_docker_auth_match(self):
        for r in get_extended_rules():
            if r.id == "docker-auth":
                p = re.compile(r.pattern)
                assert p.search('"auth": "' + "A" * 40 + '"')
                return
        pytest.fail("docker-auth not found")
