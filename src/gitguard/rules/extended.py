"""Extended detection rules for additional services."""

from __future__ import annotations

from gitguard.models import Rule, Severity


def get_extended_rules() -> list[Rule]:
    """Return extended detection rules for additional services."""
    return [
        *_digitalocean_rules(),
        *_heroku_rules(),
        *_mailgun_rules(),
        *_telegram_rules(),
        *_discord_rules(),
        *_openai_rules(),
        *_firebase_rules(),
        *_docker_rules(),
    ]


def _digitalocean_rules() -> list[Rule]:
    return [
        Rule(
            id="digitalocean-token",
            name="DigitalOcean Access Token",
            pattern=r"dop_v1_[a-f0-9]{64}",
            severity=Severity.CRITICAL,
            description="DigitalOcean personal access token found",
            category="cloud",
        ),
        Rule(
            id="digitalocean-oauth",
            name="DigitalOcean OAuth Token",
            pattern=r"doo_v1_[a-f0-9]{64}",
            severity=Severity.HIGH,
            description="DigitalOcean OAuth token found",
            category="cloud",
        ),
    ]


def _heroku_rules() -> list[Rule]:
    return [
        Rule(
            id="heroku-api-key",
            name="Heroku API Key",
            pattern=r"(?i)heroku[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]?",
            severity=Severity.HIGH,
            description="Heroku API key found",
            category="cloud",
        ),
    ]


def _mailgun_rules() -> list[Rule]:
    return [
        Rule(
            id="mailgun-api-key",
            name="Mailgun API Key",
            pattern=r"key-[0-9a-zA-Z]{32}",
            severity=Severity.HIGH,
            description="Mailgun API key found",
            category="email",
        ),
    ]


def _telegram_rules() -> list[Rule]:
    return [
        Rule(
            id="telegram-bot-token",
            name="Telegram Bot Token",
            pattern=r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
            severity=Severity.HIGH,
            description="Telegram bot token found",
            category="messaging",
        ),
    ]


def _discord_rules() -> list[Rule]:
    return [
        Rule(
            id="discord-bot-token",
            name="Discord Bot Token",
            pattern=r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",
            severity=Severity.HIGH,
            description="Discord bot token found",
            category="messaging",
        ),
        Rule(
            id="discord-webhook",
            name="Discord Webhook URL",
            pattern=r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
            severity=Severity.MEDIUM,
            description="Discord webhook URL found",
            category="messaging",
        ),
    ]


def _openai_rules() -> list[Rule]:
    return [
        Rule(
            id="openai-api-key",
            name="OpenAI API Key",
            pattern=r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
            severity=Severity.CRITICAL,
            description="OpenAI API key found",
            category="ai",
        ),
    ]


def _firebase_rules() -> list[Rule]:
    return [
        Rule(
            id="firebase-url",
            name="Firebase Database URL",
            pattern=r"https://[a-z0-9-]+\.firebaseio\.com",
            severity=Severity.MEDIUM,
            description="Firebase database URL found",
            category="cloud",
        ),
    ]


def _docker_rules() -> list[Rule]:
    return [
        Rule(
            id="docker-auth",
            name="Docker Registry Auth",
            pattern=r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
            severity=Severity.HIGH,
            description="Docker registry authentication token found",
            category="containers",
        ),
    ]
