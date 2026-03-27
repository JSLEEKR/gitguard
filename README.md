<div align="center">

# 🛡️ gitguard

### Pre-commit security scanner that catches secrets before they reach your repo

[![GitHub Stars](https://img.shields.io/github/stars/JSLEEKR/gitguard?style=for-the-badge&logo=github&color=yellow)](https://github.com/JSLEEKR/gitguard/stargazers)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-520%20passing-brightgreen?style=for-the-badge)](#testing)

<br/>

**Block secrets, credentials, and API keys from reaching your repository -- automatically**

25+ Built-in Rules + Shannon Entropy Detection + SARIF CI/CD Integration

[Quick Start](#-quick-start) | [Features](#features) | [CLI Commands](#-cli-commands) | [Architecture](#-architecture)

</div>

---

## Why This Exists

Secrets get committed. It happens to every team -- an API key hardcoded during local testing, an AWS credential that slipped into a config file, a JWT secret copy-pasted into a fixture. Once it is in git history, it is exposed. Rotating credentials is expensive. The damage is already done.

`gitguard` installs as a pre-commit hook and scans every diff before it reaches your repository. Twenty-five built-in rules cover the credentials that actually get leaked -- AWS, GCP, Azure, GitHub, Stripe, Slack, SSH keys, JWT tokens, and database URLs. Shannon entropy detection catches random-looking secrets that pattern matching alone would miss.

- **Pre-commit by default** -- blocks the commit at the source before any push, branch, or CI run sees the secret
- **Diff-aware scanning** -- only scans added lines in the staged diff, so it stays fast even on large repositories
- **SARIF output** -- integrates with GitHub Code Scanning and any CI/CD pipeline that accepts the standard security format
- **Zero configuration** -- works out of the box with sensible defaults, customizable when you need it

Stop rotating leaked credentials. Start blocking them at the source.

---

## Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Detection** | 25+ Built-in Rules | AWS, GCP, Azure, GitHub, Slack, Stripe, SSH, JWT, database URLs, and more |
| **Detection** | Shannon Entropy | Catches high-entropy strings (random secrets) that regex patterns miss |
| **Detection** | Extended Rules | Additional patterns for NPM tokens, SendGrid, Twilio, crypto keys |
| **Detection** | Custom Rules | Define your own regex patterns via YAML configuration |
| **Scanning** | Diff Scanner | Scans only added lines in git diffs for speed |
| **Scanning** | File Scanner | Full recursive file and directory scanning |
| **Scanning** | History Scanner | Scans git commit history for previously leaked secrets |
| **Scanning** | Baseline Scanner | Full-repo scan of all tracked files for security baseline |
| **Scanning** | Parallel Scanner | Thread-pool based scanning for large codebases |
| **Output** | Text Formatter | Colored human-readable output with severity indicators |
| **Output** | JSON Formatter | Machine-readable JSON output for tooling |
| **Output** | SARIF Formatter | Standard format for GitHub Code Scanning and CI/CD |
| **Output** | CSV/JSONL Export | Audit-friendly export formats for compliance |
| **Integration** | Git Hook Installer | One-command pre-commit hook setup |
| **Integration** | CI/CD Detection | Auto-detects GitHub Actions, GitLab CI, Jenkins, CircleCI, Travis, Azure DevOps, Bitbucket |
| **Integration** | GitHub Workflow | Generates GitHub Actions workflow YAML |
| **Integration** | pre-commit Config | Generates .pre-commit-config.yaml entry |
| **Configuration** | YAML Config | `.gitguard.yml` with allowlists, severity, custom rules |
| **Configuration** | .gitguardignore | Glob-based file exclusion with negation support |
| **Configuration** | Inline Suppression | `# gitguard:disable` and `# gitguard:disable-next-line` comments |
| **Analysis** | Severity Levels | Critical, High, Medium, Low, Info with weighted risk scoring |
| **Analysis** | Severity Escalation | Auto-escalates findings in production configs, Dockerfiles, CI configs |
| **Analysis** | Fix Suggestions | Context-aware remediation advice for every finding type |
| **Analysis** | Audit Logging | Track scan history with pass/fail status and risk scores |
| **Performance** | Pattern Cache | LRU cache for compiled regex patterns with hit-rate tracking |
| **Performance** | Content Hashing | SHA-256 content hashing to skip unchanged files |
| **Performance** | Scan Timer | Checkpoint-based timing for performance profiling |

---

## 🚀 Quick Start

```bash
# 1. Install gitguard
pip install -e .

# 2. Install as pre-commit hook
gitguard install

# 3. Start committing -- gitguard scans automatically
git commit -m "your commit"
```

That is it. Every commit now runs through gitguard before it reaches your repository.

---

## 📋 CLI Commands

### `gitguard scan`

Scan staged or all git changes for secrets.

```bash
# Scan staged changes (default, used by pre-commit hook)
gitguard scan --staged

# Scan all changes (staged + unstaged)
gitguard scan --all

# With JSON output
gitguard scan --staged --format json

# With SARIF output for CI
gitguard scan --staged --format sarif

# Verbose mode
gitguard scan --staged -v
```

### `gitguard scan-file`

Scan specific files or directories.

```bash
# Scan a directory
gitguard scan-file src/

# Scan multiple paths
gitguard scan-file config.py src/ .env

# Scan with SARIF output
gitguard scan-file . --format sarif > results.sarif
```

### `gitguard scan-history`

Scan git commit history for previously leaked secrets.

```bash
# Scan last 50 commits (default)
gitguard scan-history

# Scan last 100 commits on a specific branch
gitguard scan-history --max-commits 100 --branch main

# JSON output
gitguard scan-history --format json
```

### `gitguard scan-baseline`

Scan all tracked files for a complete security baseline.

```bash
gitguard scan-baseline
gitguard scan-baseline --format sarif
gitguard scan-baseline -v
```

### `gitguard install` / `uninstall`

Manage the pre-commit hook.

```bash
gitguard install          # Install hook
gitguard install --force  # Overwrite existing hook
gitguard uninstall        # Remove hook
```

### `gitguard init`

Generate a default `.gitguard.yml` config file.

```bash
gitguard init
```

### `gitguard list-rules`

List all available detection rules.

```bash
gitguard list-rules
gitguard list-rules --format json
```

### `gitguard status`

Show gitguard status for the current repository.

```bash
gitguard status
# Output:
# gitguard v1.0.0
# Git repo: Yes
# Hook installed: Yes
# Config file: .gitguard.yml
# Built-in rules: 25
```

---

## 🔍 Built-in Detection Rules

### Cloud Providers

| Rule ID | Name | Severity | What It Catches |
|---------|------|----------|-----------------|
| `aws-access-key` | AWS Access Key ID | CRITICAL | AKIA/ABIA/ACCA/ASIA prefixed keys |
| `aws-secret-key` | AWS Secret Access Key | CRITICAL | 40-char base64 AWS secrets |
| `aws-session-token` | AWS Session Token | HIGH | Temporary session credentials |
| `gcp-api-key` | GCP API Key | HIGH | AIza-prefixed Google API keys |
| `gcp-service-account` | GCP Service Account | CRITICAL | Service account JSON key files |
| `azure-storage-key` | Azure Storage Key | CRITICAL | 88-char base64 storage keys |
| `azure-connection-string` | Azure Connection String | CRITICAL | Full connection strings with keys |

### Tokens and API Keys

| Rule ID | Name | Severity | What It Catches |
|---------|------|----------|-----------------|
| `github-token` | GitHub Token | CRITICAL | ghp/gho/ghu/ghs/ghr prefixed tokens |
| `slack-token` | Slack Token | HIGH | xoxb/xoxp/xoxr/xoxa/xoxs tokens |
| `stripe-key` | Stripe API Key | CRITICAL | sk_test/sk_live/pk_test/pk_live keys |
| `sendgrid-key` | SendGrid API Key | HIGH | SG. prefixed API keys |
| `twilio-key` | Twilio API Key | HIGH | SK-prefixed 32-char hex keys |
| `npm-token` | NPM Token | HIGH | npm_ prefixed access tokens |
| `jwt-token` | JWT Token | HIGH | eyJ-prefixed encoded JWT tokens |

### Keys and Credentials

| Rule ID | Name | Severity | What It Catches |
|---------|------|----------|-----------------|
| `ssh-private-key` | SSH Private Key | CRITICAL | RSA/EC/DSA/OPENSSH private key headers |
| `pgp-private-key` | PGP Private Key | CRITICAL | PGP private key block headers |
| `generic-password` | Generic Password | HIGH | Hardcoded password assignments |
| `generic-secret` | Generic Secret | HIGH | Hardcoded secret/token/api_key assignments |
| `database-url` | Database URL | HIGH | mysql/postgres/mongodb/redis connection URLs |
| `database-password` | Database Password | HIGH | Hardcoded db_password assignments |
| `env-file` | Environment File | MEDIUM | .env files that should be gitignored |
| `private-key-file` | Private Key File | CRITICAL | .pem, .key, id_rsa files |
| `crypto-private-key` | Cryptocurrency Key | MEDIUM | 64-char hex strings (entropy-gated) |

---

## ⚙️ Configuration

Create `.gitguard.yml` in your project root:

```yaml
# gitguard configuration
settings:
  max_file_size_kb: 500      # Skip files larger than this
  min_severity: low           # Minimum severity to report
  entropy_enabled: true       # Enable Shannon entropy detection

allowlist:
  # Regex patterns to ignore in content
  patterns:
    - "EXAMPLE_KEY"
    - "test_secret"
    - "dummy"

  # File paths to skip (glob patterns)
  paths:
    - "**/*.test.*"
    - "**/*.spec.*"
    - "**/fixtures/**"
    - "**/testdata/**"

# Disable specific rules by ID
disabled_rules:
  - crypto-private-key

# Custom rules (in addition to built-in rules)
rules:
  - id: my-custom-rule
    name: My Custom Secret
    pattern: "CUSTOM_[A-Z0-9]{32}"
    severity: high
    description: Custom secret pattern
    category: custom
```

### .gitguardignore

Create a `.gitguardignore` file (similar to `.gitignore`):

```
# Skip test fixtures
fixtures/**
testdata/**

# Skip specific files
*.test.py

# Negation (don't skip this even if matched above)
!important.test.py
```

### Inline Suppression

Suppress specific findings with comments:

```python
password = "test123"  # gitguard:disable
password = "test123"  # gitguard:disable=generic-password

# gitguard:disable-next-line
password = "test123"

# gitguard:disable-next-line=generic-password,generic-secret
password = "test123"
```

---

## 🏗️ Architecture

```
gitguard/
├── cli.py                  # Click-based CLI entry point
├── models.py               # Core data models (Rule, Finding, ScanResult, ScanConfig)
├── config.py               # YAML config loading and merging
├── git.py                  # Git operations (diff, staged changes)
├── entropy.py              # Shannon entropy calculation
├── scanners/
│   ├── content_scanner.py  # Text content scanning against rules
│   ├── diff_scanner.py     # Git diff parsing and scanning
│   ├── file_scanner.py     # File and directory scanning
│   ├── history_scanner.py  # Git commit history scanning
│   └── baseline_scanner.py # Full-repo baseline scanning
├── rules/
│   ├── builtin.py          # 25+ built-in detection rules
│   ├── extended.py         # Extended rule patterns
│   ├── loader.py           # Custom rule loading from YAML
│   ├── manager.py          # Rule management and filtering
│   └── tester.py           # Rule testing utilities
├── formatters/
│   ├── text.py             # Colored text output
│   ├── json_fmt.py         # JSON output
│   └── sarif.py            # SARIF format for CI/CD
├── hooks/
│   └── installer.py        # Git hook installation
├── parallel.py             # Thread-pool parallel scanning
├── cache.py                # Regex pattern cache with LRU eviction
├── audit.py                # Scan audit logging (CSV/JSONL export)
├── escalation.py           # Severity escalation based on context
├── suggestions.py          # Auto-fix suggestions per rule
├── suppression.py          # Inline comment suppression parsing
├── ignorefile.py           # .gitguardignore file support
├── ci.py                   # CI/CD environment detection and integration
├── filters.py              # Finding filters and deduplication
└── report.py               # Report generation utilities
```

### Data Flow

```
Git Diff / Files
      │
      ▼
┌─────────────┐    ┌──────────────┐
│ Config Load  │───▶│ Rule Engine  │
│ .gitguard.yml│    │ 25+ patterns │
└─────────────┘    └──────┬───────┘
                          │
                          ▼
                ┌─────────────────┐
                │ Content Scanner │
                │ + Entropy Check │
                └────────┬────────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
        ┌──────────┐ ┌────────┐ ┌──────┐
        │Allowlist │ │Suppress│ │Filter│
        │  Check   │ │ Check  │ │  Min │
        └────┬─────┘ └───┬────┘ └──┬───┘
             └────────────┼────────┘
                          ▼
                ┌─────────────────┐
                │   Escalation    │
                │ (prod/CI files) │
                └────────┬────────┘
                         ▼
              ┌──────────────────┐
              │  Format Output   │
              │ Text/JSON/SARIF  │
              └──────────────────┘
```

---

## 📡 API Reference

### Core Classes

```python
from gitguard.models import Rule, Finding, ScanResult, ScanConfig, Severity

# Create a custom rule
rule = Rule(
    id="my-rule",
    name="My Rule",
    pattern=r"SECRET_[A-Z0-9]{32}",
    severity=Severity.HIGH,
    category="custom",
)

# Configure a scan
config = ScanConfig(
    rules=[rule],
    allowlist_patterns=["test_*"],
    min_severity=Severity.MEDIUM,
    entropy_enabled=True,
)
```

### Scanning

```python
from gitguard.scanners.content_scanner import ContentScanner
from gitguard.scanners.file_scanner import FileScanner
from gitguard.scanners.diff_scanner import DiffScanner

# Scan text content
scanner = ContentScanner(config)
result = scanner.scan_text(content, file_path="config.py")

# Scan files
file_scanner = FileScanner(config)
result = file_scanner.scan_file("config.py")
result = file_scanner.scan_directory("src/")

# Scan git diff
diff_scanner = DiffScanner(config)
result = diff_scanner.scan_diff(diff_text)
```

### Parallel Scanning

```python
from gitguard.parallel import ParallelScanner

scanner = ParallelScanner(config, max_workers=8)
result = scanner.scan_directory("src/")
result = scanner.scan_files(["a.py", "b.py", "c.py"])
```

### Entropy Detection

```python
from gitguard.entropy import shannon_entropy, is_high_entropy, extract_high_entropy_strings

entropy = shannon_entropy("AKIAIOSFODNN7EXAMPLE")  # => ~3.8
is_secret = is_high_entropy("a1b2c3d4e5f6g7h8", threshold=4.5)
secrets = extract_high_entropy_strings(line, min_length=16)
```

### Audit Logging

```python
from gitguard.audit import AuditLog, export_findings_csv, export_findings_jsonl

audit = AuditLog()
entry = audit.record(result, scan_type="diff", branch="main")

csv_output = export_findings_csv(result.findings)
jsonl_output = export_findings_jsonl(result.findings)
```

### Fix Suggestions

```python
from gitguard.suggestions import suggest_fix, format_suggestions

suggestions = [suggest_fix(f) for f in result.findings]
print(format_suggestions(suggestions))
```

### CI/CD Integration

```python
from gitguard.ci import detect_ci, is_ci, generate_github_workflow

env = detect_ci()  # => CIEnvironment.GITHUB_ACTIONS
workflow_yaml = generate_github_workflow()
```

---

## 🔧 How It Works

1. **Hook Trigger** -- When you run `git commit`, the pre-commit hook calls `gitguard scan --staged`
2. **Diff Extraction** -- gitguard runs `git diff --staged` to get only the lines being committed
3. **Rule Matching** -- Each added line is tested against 25+ regex patterns for known secret formats
4. **Entropy Analysis** -- High-entropy strings (Shannon entropy >= 4.5) are flagged as potential secrets
5. **Allowlist Filtering** -- Matches are checked against global and per-rule allowlists
6. **Suppression Check** -- Inline `# gitguard:disable` comments are honored
7. **Severity Escalation** -- Findings in production configs, Dockerfiles, or CI configs are auto-escalated
8. **Risk Scoring** -- Each finding is weighted by severity (Critical=10, High=7, Medium=4, Low=2, Info=1)
9. **Output Formatting** -- Results are formatted as text, JSON, or SARIF depending on the environment
10. **Exit Code** -- Non-zero exit blocks the commit if any findings exist

---

## ❓ Troubleshooting

### False Positives

Use any of these approaches:

```yaml
# 1. Allowlist patterns in .gitguard.yml
allowlist:
  patterns:
    - "EXAMPLE_KEY"
    - "test_fixture"

# 2. Allowlist file paths
  paths:
    - "**/test_*"
    - "**/fixtures/**"
```

```python
# 3. Inline suppression
api_key = "test_key_123"  # gitguard:disable=generic-secret
```

```
# 4. .gitguardignore file
tests/fixtures/**
```

### Hook Not Running

```bash
# Check hook status
gitguard status

# Reinstall
gitguard install --force
```

### Scanning Too Slow

```bash
# Use allowlist paths to skip test/vendor directories
# Use .gitguardignore for file exclusions
# Use --staged flag (default) to scan only changes
```

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all 520 tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=gitguard --cov-report=term-missing

# Run specific test module
pytest tests/test_content_scanner.py -v
```

---

## License

MIT
