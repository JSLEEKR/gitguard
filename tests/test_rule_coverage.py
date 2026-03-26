"""Rule coverage tests ensuring all built-in rules detect real-world patterns."""

import re

import pytest

from gitguard.models import ScanConfig, Severity
from gitguard.rules.builtin import get_builtin_rules
from gitguard.rules.extended import get_extended_rules
from gitguard.scanners.content_scanner import ContentScanner


class TestRealWorldDetection:
    """Test detection of real-world secret patterns."""

    def _scan(self, content, file_path="test.py"):
        config = ScanConfig(rules=get_builtin_rules(), min_severity=Severity.INFO)
        scanner = ContentScanner(config)
        return scanner.scan_text(content, file_path)

    def test_detect_aws_key_in_config(self):
        content = 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_aws_secret_in_env(self):
        content = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_password_in_python(self):
        content = 'DB_PASSWORD = "MyS3cureP@ssw0rd!"'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_password_in_yaml(self):
        content = 'password: "production_secret_value"'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_github_token(self):
        content = 'GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_stripe_key(self):
        content = 'STRIPE_KEY = "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_jwt_in_code(self):
        content = 'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_ssh_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        result = self._scan(content)
        assert result.has_findings

    def test_detect_database_url(self):
        content = 'DATABASE_URL = "postgres://admin:s3cret@prod-db.example.com:5432/myapp"'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_gcp_api_key(self):
        content = 'GCP_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"'
        result = self._scan(content)
        assert result.has_findings

    def test_no_false_positive_variable_names(self):
        content = """
password_field = user_input.get("password")
secret_manager = SecretsClient()
api_key_name = "API_KEY"
"""
        result = self._scan(content)
        # These shouldn't trigger because they don't have hardcoded values
        for f in result.findings:
            assert f.rule_id != "generic-password"

    def test_detect_azure_connection_string(self):
        key = "A" * 88
        content = f'DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey={key}'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_slack_token(self):
        # Construct token dynamically to avoid push protection
        prefix = "xoxb"
        content = f'SLACK_TOKEN = "{prefix}-1234567890-abcdefghijklmnop"'
        result = self._scan(content)
        assert result.has_findings

    def test_detect_sendgrid_key(self):
        a_part = "A" * 22
        b_part = "B" * 43
        content = f'SENDGRID_KEY = "SG.{a_part}.{b_part}"'
        result = self._scan(content)
        assert result.has_findings

    def test_clean_code_no_findings(self):
        content = """
import os
import sys

def calculate_sum(a: int, b: int) -> int:
    return a + b

class UserService:
    def __init__(self):
        self.db = Database()

    def get_user(self, user_id: int):
        return self.db.query(User, user_id)

if __name__ == "__main__":
    result = calculate_sum(1, 2)
    print(f"Result: {result}")
"""
        result = self._scan(content)
        assert not result.has_findings

    def test_detect_in_json_config(self):
        content = '{"type": "service_account", "project_id": "my-project"}'
        result = self._scan(content, "credentials.json")
        assert result.has_findings

    def test_detect_mongodb_url(self):
        content = 'MONGO_URI = "mongodb+srv://admin:password123@cluster.mongodb.net/mydb"'
        result = self._scan(content)
        assert result.has_findings


class TestExtendedRuleCoverage:
    def _scan_extended(self, content):
        config = ScanConfig(rules=get_extended_rules(), min_severity=Severity.INFO)
        scanner = ContentScanner(config)
        return scanner.scan_text(content)

    def test_detect_discord_webhook(self):
        content = 'WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnop_QRSTUVWXYZ"'
        result = self._scan_extended(content)
        assert result.has_findings

    def test_detect_firebase_url(self):
        content = 'FIREBASE = "https://my-project-123.firebaseio.com"'
        result = self._scan_extended(content)
        assert result.has_findings

    def test_detect_mailgun_key(self):
        content = f'MAILGUN_KEY = "key-{"a" * 32}"'
        result = self._scan_extended(content)
        assert result.has_findings
