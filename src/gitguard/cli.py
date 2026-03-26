"""Command-line interface for gitguard."""

from __future__ import annotations

import sys

import click

from gitguard import __version__
from gitguard.config import find_config_file, generate_default_config, load_config
from gitguard.formatters.json_fmt import JsonFormatter
from gitguard.formatters.sarif import SarifFormatter
from gitguard.formatters.text import TextFormatter
from gitguard.git import Git, GitError
from gitguard.hooks.installer import HookInstaller
from gitguard.rules.builtin import get_builtin_rules
from gitguard.scanners.diff_scanner import DiffScanner
from gitguard.scanners.file_scanner import FileScanner


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """gitguard - Git pre-commit security scanner for secrets and credentials."""
    pass


@main.command()
@click.option("--staged", is_flag=True, help="Scan only staged changes")
@click.option("--all", "scan_all", is_flag=True, help="Scan all changes (staged + unstaged)")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "sarif"]),
              default="text", help="Output format")
@click.option("--config", "config_path", type=click.Path(), help="Config file path")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed findings")
@click.option("--no-color", is_flag=True, help="Disable colored output")
def scan(
    staged: bool,
    scan_all: bool,
    output_format: str,
    config_path: str | None,
    verbose: bool,
    no_color: bool,
) -> None:
    """Scan for secrets in git changes."""
    config = load_config(config_path)

    try:
        git = Git()
        if not git.is_repo():
            click.echo("Error: Not a git repository", err=True)
            sys.exit(1)

        if staged:
            diff_text = git.staged_diff()
        elif scan_all:
            diff_text = git.all_diff()
        else:
            diff_text = git.staged_diff()

    except GitError as e:
        click.echo(f"Git error: {e}", err=True)
        sys.exit(1)

    scanner = DiffScanner(config)
    result = scanner.scan_diff(diff_text)

    output = _format_result(result, output_format, verbose, not no_color)
    click.echo(output)

    if result.has_findings:
        sys.exit(1)


@main.command(name="scan-file")
@click.argument("paths", nargs=-1, required=True)
@click.option("--format", "output_format", type=click.Choice(["text", "json", "sarif"]),
              default="text", help="Output format")
@click.option("--config", "config_path", type=click.Path(), help="Config file path")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed findings")
@click.option("--no-color", is_flag=True, help="Disable colored output")
def scan_file(
    paths: tuple[str, ...],
    output_format: str,
    config_path: str | None,
    verbose: bool,
    no_color: bool,
) -> None:
    """Scan specific files or directories for secrets."""
    config = load_config(config_path)
    scanner = FileScanner(config)

    from gitguard.models import ScanResult, Finding
    combined = ScanResult()

    for path in paths:
        from pathlib import Path as P
        p = P(path)
        if p.is_dir():
            result = scanner.scan_directory(p)
        elif p.is_file():
            result = scanner.scan_file(p)
        else:
            click.echo(f"Warning: {path} not found, skipping", err=True)
            continue

        combined.findings.extend(result.findings)
        combined.files_scanned += result.files_scanned
        combined.lines_scanned += result.lines_scanned
        combined.rules_applied = max(combined.rules_applied, result.rules_applied)
        combined.scan_time_ms += result.scan_time_ms

    output = _format_result(combined, output_format, verbose, not no_color)
    click.echo(output)

    if combined.has_findings:
        sys.exit(1)


@main.command()
@click.option("--force", is_flag=True, help="Overwrite existing hook")
def install(force: bool) -> None:
    """Install gitguard as a git pre-commit hook."""
    installer = HookInstaller()
    result = installer.install(force=force)
    click.echo(result)


@main.command()
def uninstall() -> None:
    """Remove gitguard pre-commit hook."""
    installer = HookInstaller()
    result = installer.uninstall()
    click.echo(result)


@main.command()
def init() -> None:
    """Generate a default .gitguard.yml config file."""
    from pathlib import Path as P
    config_file = P.cwd() / ".gitguard.yml"
    if config_file.exists():
        click.echo("Config file .gitguard.yml already exists")
        sys.exit(1)
    config_file.write_text(generate_default_config())
    click.echo("Created .gitguard.yml with default configuration")


@main.command(name="list-rules")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]),
              default="text", help="Output format")
def list_rules(output_format: str) -> None:
    """List all available detection rules."""
    rules = get_builtin_rules()

    if output_format == "json":
        import json
        data = [r.to_dict() for r in rules]
        click.echo(json.dumps(data, indent=2))
    else:
        categories: dict[str, list] = {}
        for rule in rules:
            categories.setdefault(rule.category, []).append(rule)

        for cat, cat_rules in sorted(categories.items()):
            click.echo(f"\n[{cat.upper()}]")
            for rule in cat_rules:
                status = "ON" if rule.enabled else "OFF"
                click.echo(
                    f"  {rule.id:30s} {rule.severity.value:8s} [{status}] {rule.name}"
                )


@main.command(name="scan-history")
@click.option("--max-commits", default=50, help="Maximum commits to scan")
@click.option("--branch", default=None, help="Branch to scan")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]),
              default="text", help="Output format")
@click.option("--no-color", is_flag=True, help="Disable colored output")
def scan_history(max_commits: int, branch: str | None, output_format: str, no_color: bool) -> None:
    """Scan git commit history for secrets."""
    config = load_config()

    try:
        git = Git()
        if not git.is_repo():
            click.echo("Error: Not a git repository", err=True)
            sys.exit(1)
    except GitError as e:
        click.echo(f"Git error: {e}", err=True)
        sys.exit(1)

    from gitguard.scanners.history_scanner import HistoryScanner
    scanner = HistoryScanner(config)
    result, commit_findings = scanner.scan_history(max_commits=max_commits, branch=branch)

    if output_format == "json":
        import json
        data = {
            "summary": result.summary(),
            "commit_findings": [
                {
                    "commit": cf.commit_hash[:8],
                    "message": cf.commit_message,
                    "author": cf.author,
                    "finding": cf.finding.to_dict(),
                }
                for cf in commit_findings
            ],
        }
        click.echo(json.dumps(data, indent=2))
    else:
        output = _format_result(result, "text", False, not no_color)
        click.echo(output)
        if commit_findings:
            click.echo("\nCommit details:")
            for cf in commit_findings:
                click.echo(f"  {cf.commit_hash[:8]} ({cf.author}): {cf.commit_message}")
                click.echo(f"    -> {cf.finding.rule_name} in {cf.finding.file_path}")

    if result.has_findings:
        sys.exit(1)


@main.command(name="scan-baseline")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "sarif"]),
              default="text", help="Output format")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed findings")
@click.option("--no-color", is_flag=True, help="Disable colored output")
def scan_baseline(output_format: str, verbose: bool, no_color: bool) -> None:
    """Scan all tracked files for a security baseline."""
    config = load_config()

    try:
        git = Git()
        if not git.is_repo():
            click.echo("Error: Not a git repository", err=True)
            sys.exit(1)
    except GitError as e:
        click.echo(f"Git error: {e}", err=True)
        sys.exit(1)

    from gitguard.scanners.baseline_scanner import BaselineScanner
    scanner = BaselineScanner(config)
    result = scanner.scan_repo()

    output = _format_result(result, output_format, verbose, not no_color)
    click.echo(output)

    if result.has_findings:
        sys.exit(1)


@main.command()
def status() -> None:
    """Show gitguard status for current repository."""
    installer = HookInstaller()

    click.echo(f"gitguard v{__version__}")
    click.echo(f"Git repo: {'Yes' if installer.is_git_repo() else 'No'}")
    click.echo(f"Hook installed: {'Yes' if installer.is_installed() else 'No'}")

    config_file = find_config_file()
    click.echo(f"Config file: {config_file or 'None (using defaults)'}")

    rules = get_builtin_rules()
    click.echo(f"Built-in rules: {len(rules)}")


def _format_result(
    result, output_format: str, verbose: bool, use_color: bool
) -> str:
    """Format scan result based on format option."""
    if output_format == "json":
        return JsonFormatter(pretty=True).format(result)
    elif output_format == "sarif":
        return SarifFormatter().format(result)
    else:
        return TextFormatter(use_color=use_color, verbose=verbose).format(result)


if __name__ == "__main__":
    main()
