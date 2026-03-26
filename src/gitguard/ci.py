"""CI/CD integration helpers."""

from __future__ import annotations

import json
import os
import sys
from enum import Enum


class CIEnvironment(Enum):
    """Detected CI environment."""
    GITHUB_ACTIONS = "github-actions"
    GITLAB_CI = "gitlab-ci"
    JENKINS = "jenkins"
    CIRCLECI = "circleci"
    TRAVIS = "travis"
    AZURE_DEVOPS = "azure-devops"
    BITBUCKET = "bitbucket"
    UNKNOWN = "unknown"
    LOCAL = "local"


def detect_ci() -> CIEnvironment:
    """Detect which CI environment we're running in."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return CIEnvironment.GITHUB_ACTIONS
    if os.environ.get("GITLAB_CI") == "true":
        return CIEnvironment.GITLAB_CI
    if os.environ.get("JENKINS_URL"):
        return CIEnvironment.JENKINS
    if os.environ.get("CIRCLECI") == "true":
        return CIEnvironment.CIRCLECI
    if os.environ.get("TRAVIS") == "true":
        return CIEnvironment.TRAVIS
    if os.environ.get("BUILD_BUILDID"):
        return CIEnvironment.AZURE_DEVOPS
    if os.environ.get("BITBUCKET_BUILD_NUMBER"):
        return CIEnvironment.BITBUCKET
    if os.environ.get("CI"):
        return CIEnvironment.UNKNOWN
    return CIEnvironment.LOCAL


def is_ci() -> bool:
    """Check if running in a CI environment."""
    return detect_ci() != CIEnvironment.LOCAL


def github_actions_output(findings_count: int, risk_score: int, status: str) -> str:
    """Generate GitHub Actions output commands."""
    lines: list[str] = []
    lines.append(f"::set-output name=findings::{findings_count}")
    lines.append(f"::set-output name=risk_score::{risk_score}")
    lines.append(f"::set-output name=status::{status}")
    if findings_count > 0:
        lines.append(f"::warning::gitguard found {findings_count} potential secrets (risk score: {risk_score})")
    return "\n".join(lines)


def generate_github_workflow() -> str:
    """Generate a GitHub Actions workflow YAML for gitguard."""
    return """\
name: Security Scan

on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  gitguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install gitguard
        run: pip install gitguard

      - name: Scan for secrets
        run: gitguard scan-file . --format sarif > results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
"""


def generate_pre_commit_config() -> str:
    """Generate a .pre-commit-config.yaml entry."""
    return """\
# Add to your .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: gitguard
        name: gitguard secret scanner
        entry: gitguard scan --staged
        language: python
        types: [text]
        stages: [commit]
"""


def exit_code_for_ci(has_findings: bool, strict: bool = True) -> int:
    """Determine exit code for CI."""
    if has_findings and strict:
        return 1
    return 0
