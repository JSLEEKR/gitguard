# gitguard

Git pre-commit security scanner that detects secrets, credentials, API keys, and sensitive patterns before they reach your repository.

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
