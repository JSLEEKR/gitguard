# Changelog

All notable changes to gitguard will be documented in this file.

## [1.0.0] - 2026-03-26

### Added

- **Core scanning engine** with 25+ built-in detection rules
- **Rule categories**: AWS (access key, secret key, session token), GCP (API key, service account), Azure (storage key, connection string), generic credentials, JWT tokens, SSH/PGP keys, database URLs, API tokens (GitHub, Slack, Stripe, SendGrid, Twilio, NPM), cryptocurrency keys
- **Shannon entropy detection** for high-entropy strings with configurable thresholds
- **Git hook installer** for one-command pre-commit hook setup
- **Diff scanner** for staged/unstaged git change scanning
- **File scanner** for recursive file and directory scanning
- **History scanner** for scanning git commit history
- **Baseline scanner** for full-repo security baseline
- **Parallel scanner** with ThreadPoolExecutor for large codebases
- **Content scanner** with pre-compiled regex patterns and file-pattern filtering
- **Three output formats**: colored text, JSON, SARIF (for CI/CD integration)
- **YAML configuration** via `.gitguard.yml` with allowlists, severity settings, custom rules
- **`.gitguardignore`** file support with glob patterns and negation
- **Inline suppression** comments (`# gitguard:disable`, `# gitguard:disable-next-line`)
- **Severity escalation** for findings in production configs, Dockerfiles, CI configs
- **Fix suggestions** with context-aware remediation advice per rule type
- **Audit logging** with CSV and JSONL export formats
- **CI/CD detection** for GitHub Actions, GitLab CI, Jenkins, CircleCI, Travis, Azure DevOps, Bitbucket
- **GitHub Actions workflow generator** and pre-commit config generator
- **Pattern cache** with LRU eviction and hit-rate tracking
- **Scan timer** with checkpoint-based performance profiling
- **Risk scoring** with severity-weighted scoring (Critical=10, High=7, Medium=4, Low=2, Info=1)
- **Custom rules** support via YAML configuration and external rule files
- **Rule tester** utilities for validating custom patterns
- **Click-based CLI** with 8 commands: scan, scan-file, scan-history, scan-baseline, install, uninstall, init, list-rules, status
- **520 passing tests** covering all modules
