<div align="center">

# 🛡️ gitguard

### Pre-commit security scanner for secrets

[![GitHub Stars](https://img.shields.io/github/stars/JSLEEKR/gitguard?style=for-the-badge&logo=github&color=yellow)](https://github.com/JSLEEKR/gitguard/stargazers)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-520%20passing-brightgreen?style=for-the-badge)](#)

<br/>

**Block secrets, credentials, and API keys from reaching your repository**

</div>

---

## Why This Exists

Secrets get committed. It happens to every team -- an API key hardcoded during local testing, an AWS credential that slipped into a config file, a JWT secret copy-pasted into a fixture. Once it is in git history, it is exposed. Rotating it is expensive. The damage is already done.

`gitguard` installs as a pre-commit hook and scans every diff before it reaches your repository. Twenty-five built-in rules cover the credentials that actually get leaked -- AWS, GCP, GitHub, Stripe, Slack, SSH keys, JWT tokens, and database URLs. Shannon entropy detection catches random-looking secrets that pattern matching misses.

- **Pre-commit by default** -- blocks the commit at the source before any push, branch, or CI run sees the secret
- **Diff-aware scanning** -- only scans added lines in the staged diff, so it stays fast even on large repositories
- **SARIF output** -- integrates with GitHub Code Scanning and any CI/CD pipeline that accepts the standard security format

## Features

- **25+ built-in rules** covering AWS, GCP, Azure, GitHub, Slack, Stripe, SSH keys, JWT tokens, database URLs, and more
- **Git hook integration** - installs as a pre-commit hook to block commits with secrets
- **Diff-aware scanning** - scans only added lines in git diffs for speed
- **File/directory scanning** - full recursive scanning capability
- **Custom rules** via YAML configuration with regex patterns
- **Shannon entropy detection** for high-entropy strings (random secrets)
- **Multiple output formats** - text (colored), JSON, SARIF (for CI/CD)
- **Configurable allowlists** for patterns, paths, and per-rule exceptions
- **Severity levels** - Critical, High, Medium, Low, Info with risk scoring

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Install as pre-commit hook
gitguard install

# Scan staged changes
gitguard scan --staged

# Scan specific files
gitguard scan-file src/ config.py

# Generate default config
gitguard init

# List available rules
gitguard list-rules
```

## Configuration

Create `.gitguard.yml` in your project root:

```yaml
settings:
  max_file_size_kb: 500
  min_severity: low
  entropy_enabled: true

allowlist:
  patterns:
    - "EXAMPLE_KEY"
    - "test_secret"
  paths:
    - "**/*.test.*"
    - "**/fixtures/**"

disabled_rules:
  - crypto-private-key

rules:
  - id: my-custom-rule
    name: My Custom Secret
    pattern: 'CUSTOM_[A-Z0-9]{32}'
    severity: high
```

## Output Formats

```bash
# Human-readable (default)
gitguard scan-file src/

# JSON
gitguard scan-file src/ --format json

# SARIF (for GitHub Actions, etc.)
gitguard scan-file src/ --format sarif
```

## License

MIT
