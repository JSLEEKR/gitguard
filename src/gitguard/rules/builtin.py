"""Built-in secret detection rules."""

from __future__ import annotations

from gitguard.models import Rule, Severity


def get_builtin_rules() -> list[Rule]:
    """Return all built-in detection rules."""
    return [
        *_aws_rules(),
        *_gcp_rules(),
        *_azure_rules(),
        *_generic_rules(),
        *_jwt_rules(),
        *_ssh_rules(),
        *_database_rules(),
        *_api_key_rules(),
        *_crypto_rules(),
    ]


def _aws_rules() -> list[Rule]:
    return [
        Rule(
            id="aws-access-key",
            name="AWS Access Key ID",
            pattern=r"(?:^|[^A-Z0-9])(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}(?:[^A-Z0-9]|$)",
            severity=Severity.CRITICAL,
            description="AWS Access Key ID found",
            category="aws",
        ),
        Rule(
            id="aws-secret-key",
            name="AWS Secret Access Key",
            pattern=r"(?i)(?:aws[_\-]?secret[_\-]?(?:access)?[_\-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            severity=Severity.CRITICAL,
            description="AWS Secret Access Key found",
            category="aws",
        ),
        Rule(
            id="aws-session-token",
            name="AWS Session Token",
            pattern=r"(?i)(?:aws[_\-]?session[_\-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
            severity=Severity.HIGH,
            description="AWS Session Token found",
            category="aws",
        ),
    ]


def _gcp_rules() -> list[Rule]:
    return [
        Rule(
            id="gcp-api-key",
            name="GCP API Key",
            pattern=r"AIza[0-9A-Za-z\-_]{35}",
            severity=Severity.HIGH,
            description="Google Cloud API key found",
            category="gcp",
        ),
        Rule(
            id="gcp-service-account",
            name="GCP Service Account Key",
            pattern=r'"type"\s*:\s*"service_account"',
            severity=Severity.CRITICAL,
            description="GCP service account key file detected",
            category="gcp",
            file_patterns=["*.json"],
        ),
    ]


def _azure_rules() -> list[Rule]:
    return [
        Rule(
            id="azure-storage-key",
            name="Azure Storage Account Key",
            pattern=r"(?i)(?:AccountKey|azure[_\-]?storage[_\-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{88})['\"]?",
            severity=Severity.CRITICAL,
            description="Azure Storage Account key found",
            category="azure",
        ),
        Rule(
            id="azure-connection-string",
            name="Azure Connection String",
            pattern=r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
            severity=Severity.CRITICAL,
            description="Azure connection string with key found",
            category="azure",
        ),
    ]


def _generic_rules() -> list[Rule]:
    return [
        Rule(
            id="generic-password",
            name="Generic Password Assignment",
            pattern=r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^\s"\']{8,}["\']',
            severity=Severity.HIGH,
            description="Hardcoded password detected",
            category="credentials",
        ),
        Rule(
            id="generic-secret",
            name="Generic Secret Assignment",
            pattern=r'(?i)(?:secret|token|api[_\-]?key)\s*[=:]\s*["\'][^\s"\']{8,}["\']',
            severity=Severity.HIGH,
            description="Hardcoded secret or token detected",
            category="credentials",
        ),
        Rule(
            id="env-file",
            name="Environment File",
            pattern=r".*",
            severity=Severity.MEDIUM,
            description=".env file should not be committed",
            category="files",
            file_patterns=[".env", ".env.*", "*.env"],
        ),
        Rule(
            id="private-key-file",
            name="Private Key File",
            pattern=r".*",
            severity=Severity.CRITICAL,
            description="Private key file should not be committed",
            category="files",
            file_patterns=["*.pem", "*.key", "id_rsa", "id_ed25519", "id_ecdsa"],
        ),
    ]


def _jwt_rules() -> list[Rule]:
    return [
        Rule(
            id="jwt-token",
            name="JWT Token",
            pattern=r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            severity=Severity.HIGH,
            description="JWT token found",
            category="tokens",
        ),
    ]


def _ssh_rules() -> list[Rule]:
    return [
        Rule(
            id="ssh-private-key",
            name="SSH Private Key",
            pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            severity=Severity.CRITICAL,
            description="SSH private key found",
            category="keys",
        ),
        Rule(
            id="pgp-private-key",
            name="PGP Private Key",
            pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            severity=Severity.CRITICAL,
            description="PGP private key found",
            category="keys",
        ),
    ]


def _database_rules() -> list[Rule]:
    return [
        Rule(
            id="database-url",
            name="Database Connection URL",
            pattern=r"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql)://[^\s'\"]{10,}",
            severity=Severity.HIGH,
            description="Database connection URL with potential credentials",
            category="database",
        ),
        Rule(
            id="database-password",
            name="Database Password",
            pattern=r'(?i)(?:db[_\-]?pass(?:word)?|database[_\-]?pass(?:word)?)\s*[=:]\s*["\'][^\s"\']{6,}["\']',
            severity=Severity.HIGH,
            description="Database password found",
            category="database",
        ),
    ]


def _api_key_rules() -> list[Rule]:
    return [
        Rule(
            id="github-token",
            name="GitHub Token",
            pattern=r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
            severity=Severity.CRITICAL,
            description="GitHub personal access token found",
            category="tokens",
        ),
        Rule(
            id="slack-token",
            name="Slack Token",
            pattern=r"xox[bpras]-[0-9]{10,}-[A-Za-z0-9-]+",
            severity=Severity.HIGH,
            description="Slack token found",
            category="tokens",
        ),
        Rule(
            id="stripe-key",
            name="Stripe API Key",
            pattern=r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}",
            severity=Severity.CRITICAL,
            description="Stripe API key found",
            category="tokens",
        ),
        Rule(
            id="sendgrid-key",
            name="SendGrid API Key",
            pattern=r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            severity=Severity.HIGH,
            description="SendGrid API key found",
            category="tokens",
        ),
        Rule(
            id="twilio-key",
            name="Twilio API Key",
            pattern=r"SK[0-9a-fA-F]{32}",
            severity=Severity.HIGH,
            description="Twilio API key found",
            category="tokens",
        ),
        Rule(
            id="npm-token",
            name="NPM Token",
            pattern=r"(?:npm_)[A-Za-z0-9]{36}",
            severity=Severity.HIGH,
            description="NPM access token found",
            category="tokens",
        ),
    ]


def _crypto_rules() -> list[Rule]:
    return [
        Rule(
            id="crypto-private-key",
            name="Cryptocurrency Private Key",
            pattern=r"(?:0x)?[0-9a-fA-F]{64}",
            severity=Severity.MEDIUM,
            description="Potential cryptocurrency private key (64 hex chars)",
            category="crypto",
            entropy_threshold=4.0,
        ),
    ]
