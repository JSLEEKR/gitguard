"""Auto-fix suggestions for detected secrets."""

from __future__ import annotations

from dataclasses import dataclass

from gitguard.models import Finding, Severity


@dataclass
class Suggestion:
    """A suggestion for fixing a detected secret."""
    finding: Finding
    action: str
    description: str
    fix_text: str | None = None
    severity_note: str = ""


def suggest_fix(finding: Finding) -> Suggestion:
    """Generate a fix suggestion for a finding."""
    rule_id = finding.rule_id

    # Environment variable suggestions
    if rule_id in ("generic-password", "generic-secret", "database-password"):
        var_name = _extract_var_name(finding.line_content)
        env_var = var_name.upper() if var_name else "SECRET_VALUE"
        return Suggestion(
            finding=finding,
            action="use_env_var",
            description=f"Replace hardcoded value with environment variable",
            fix_text=f'os.environ.get("{env_var}")',
            severity_note="Hardcoded credentials should never be in source code",
        )

    if rule_id in ("aws-access-key", "aws-secret-key", "aws-session-token"):
        return Suggestion(
            finding=finding,
            action="use_aws_config",
            description="Use AWS credential provider chain instead of hardcoded keys",
            fix_text="Use ~/.aws/credentials, IAM roles, or environment variables",
            severity_note="AWS keys should use the credential provider chain",
        )

    if rule_id in ("ssh-private-key", "pgp-private-key", "private-key-file"):
        return Suggestion(
            finding=finding,
            action="add_to_gitignore",
            description="Add private key files to .gitignore",
            fix_text="echo '*.pem\n*.key\nid_rsa\nid_ed25519' >> .gitignore",
            severity_note="Private keys must never be committed to version control",
        )

    if rule_id == "env-file":
        return Suggestion(
            finding=finding,
            action="add_to_gitignore",
            description="Add .env files to .gitignore",
            fix_text="echo '.env\n.env.*' >> .gitignore",
            severity_note="Environment files contain secrets and should be gitignored",
        )

    if rule_id in ("database-url",):
        return Suggestion(
            finding=finding,
            action="use_env_var",
            description="Use DATABASE_URL environment variable",
            fix_text='os.environ.get("DATABASE_URL")',
            severity_note="Database URLs often contain credentials",
        )

    if rule_id in ("github-token", "slack-token", "stripe-key", "npm-token",
                    "sendgrid-key", "openai-api-key"):
        return Suggestion(
            finding=finding,
            action="use_env_var",
            description="Store API tokens in environment variables or a secrets manager",
            fix_text=f'os.environ.get("{rule_id.upper().replace("-", "_")}")',
            severity_note="API tokens should be stored securely, not in code",
        )

    if rule_id == "jwt-token":
        return Suggestion(
            finding=finding,
            action="remove",
            description="Remove hardcoded JWT token; tokens should be generated at runtime",
            severity_note="JWTs contain encoded claims and should not be hardcoded",
        )

    # Default suggestion
    return Suggestion(
        finding=finding,
        action="review",
        description="Review this finding and determine if it's a real secret",
        severity_note="If this is a false positive, add a suppression comment: # gitguard:disable",
    )


def _extract_var_name(line: str) -> str | None:
    """Try to extract the variable name from a line like 'var = value'."""
    import re
    match = re.match(r"\s*(\w+)\s*[=:]", line)
    if match:
        return match.group(1)
    return None


def format_suggestions(suggestions: list[Suggestion], use_color: bool = False) -> str:
    """Format suggestions as human-readable text."""
    if not suggestions:
        return "No suggestions available."

    lines: list[str] = []
    lines.append(f"Suggestions ({len(suggestions)} findings):")
    lines.append("")

    for i, s in enumerate(suggestions, 1):
        lines.append(f"  {i}. [{s.finding.severity.value.upper()}] {s.finding.file_path}:{s.finding.line_number}")
        lines.append(f"     Rule: {s.finding.rule_name}")
        lines.append(f"     Action: {s.description}")
        if s.fix_text:
            lines.append(f"     Fix: {s.fix_text}")
        if s.severity_note:
            lines.append(f"     Note: {s.severity_note}")
        lines.append("")

    return "\n".join(lines)
