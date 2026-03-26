"""Finding filters and deduplication."""

from __future__ import annotations

from gitguard.models import Finding, ScanResult, Severity


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings based on file, line, and rule."""
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def filter_by_severity(
    findings: list[Finding], min_severity: Severity
) -> list[Finding]:
    """Filter findings by minimum severity."""
    return [f for f in findings if f.severity >= min_severity]


def filter_by_rules(
    findings: list[Finding], rule_ids: set[str], exclude: bool = False
) -> list[Finding]:
    """Filter findings by rule IDs. If exclude=True, remove matching rules."""
    if exclude:
        return [f for f in findings if f.rule_id not in rule_ids]
    return [f for f in findings if f.rule_id in rule_ids]


def filter_by_files(
    findings: list[Finding], file_patterns: list[str], exclude: bool = False
) -> list[Finding]:
    """Filter findings by file path patterns."""
    import fnmatch
    result: list[Finding] = []
    for f in findings:
        matches = any(
            fnmatch.fnmatch(f.file_path, p) or fnmatch.fnmatch(f.file_path.split("/")[-1], p)
            for p in file_patterns
        )
        if exclude:
            if not matches:
                result.append(f)
        else:
            if matches:
                result.append(f)
    return result


def sort_findings(
    findings: list[Finding], by: str = "severity"
) -> list[Finding]:
    """Sort findings by a given field."""
    if by == "severity":
        return sorted(findings, key=lambda f: f.severity.weight, reverse=True)
    elif by == "file":
        return sorted(findings, key=lambda f: (f.file_path, f.line_number))
    elif by == "line":
        return sorted(findings, key=lambda f: f.line_number)
    elif by == "rule":
        return sorted(findings, key=lambda f: f.rule_id)
    return findings


def group_findings(
    findings: list[Finding], by: str = "file"
) -> dict[str, list[Finding]]:
    """Group findings by a given field."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        if by == "file":
            key = f.file_path
        elif by == "rule":
            key = f.rule_id
        elif by == "severity":
            key = f.severity.value
        else:
            key = "all"
        groups.setdefault(key, []).append(f)
    return groups


def apply_filters(
    result: ScanResult,
    min_severity: Severity | None = None,
    include_rules: set[str] | None = None,
    exclude_rules: set[str] | None = None,
    include_files: list[str] | None = None,
    exclude_files: list[str] | None = None,
    deduplicate: bool = True,
) -> ScanResult:
    """Apply multiple filters to a scan result."""
    findings = list(result.findings)

    if deduplicate:
        findings = deduplicate_findings(findings)

    if min_severity is not None:
        findings = filter_by_severity(findings, min_severity)

    if include_rules is not None:
        findings = filter_by_rules(findings, include_rules)

    if exclude_rules is not None:
        findings = filter_by_rules(findings, exclude_rules, exclude=True)

    if include_files is not None:
        findings = filter_by_files(findings, include_files)

    if exclude_files is not None:
        findings = filter_by_files(findings, exclude_files, exclude=True)

    return ScanResult(
        findings=findings,
        files_scanned=result.files_scanned,
        lines_scanned=result.lines_scanned,
        rules_applied=result.rules_applied,
        scan_time_ms=result.scan_time_ms,
    )
