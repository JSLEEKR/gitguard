"""Text/console output formatter."""

from __future__ import annotations

from gitguard.models import ScanResult, Severity


SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",  # Red
    Severity.HIGH: "\033[93m",      # Yellow
    Severity.MEDIUM: "\033[33m",    # Orange
    Severity.LOW: "\033[36m",       # Cyan
    Severity.INFO: "\033[37m",      # White
}
RESET = "\033[0m"
BOLD = "\033[1m"


class TextFormatter:
    """Formats scan results as human-readable text."""

    def __init__(self, use_color: bool = True, verbose: bool = False) -> None:
        self.use_color = use_color
        self.verbose = verbose

    def format(self, result: ScanResult) -> str:
        """Format a scan result as text."""
        lines: list[str] = []

        if not result.has_findings:
            lines.append(self._colorize("No secrets detected.", Severity.INFO))
            lines.append(self._format_stats(result))
            return "\n".join(lines)

        lines.append(self._header(result))
        lines.append("")

        # Group by file
        by_file = result.findings_by_file()
        for file_path, findings in sorted(by_file.items()):
            lines.append(self._colorize(f"  {file_path}", Severity.HIGH))
            for finding in sorted(findings, key=lambda f: f.line_number):
                severity_tag = self._severity_tag(finding.severity)
                lines.append(
                    f"    {severity_tag} Line {finding.line_number}: "
                    f"{finding.rule_name}"
                )
                if self.verbose:
                    lines.append(f"      Match: {finding.masked_match}")
                    if finding.description:
                        lines.append(f"      Info:  {finding.description}")
            lines.append("")

        lines.append(self._format_stats(result))
        return "\n".join(lines)

    def _header(self, result: ScanResult) -> str:
        total = len(result.findings)
        icon = "!!"
        msg = f"{icon} Found {total} potential secret(s)"
        return self._colorize(msg, Severity.CRITICAL)

    def _severity_tag(self, severity: Severity) -> str:
        tag = f"[{severity.value.upper()}]"
        return self._colorize(tag, severity)

    def _format_stats(self, result: ScanResult) -> str:
        parts = [
            f"Files: {result.files_scanned}",
            f"Lines: {result.lines_scanned}",
            f"Rules: {result.rules_applied}",
            f"Time: {result.scan_time_ms:.1f}ms",
        ]
        if result.has_findings:
            parts.append(f"Risk score: {result.risk_score}")
        return "  " + " | ".join(parts)

    def _colorize(self, text: str, severity: Severity) -> str:
        if not self.use_color:
            return text
        color = SEVERITY_COLORS.get(severity, "")
        return f"{color}{text}{RESET}"
