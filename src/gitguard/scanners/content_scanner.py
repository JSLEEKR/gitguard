"""Content scanner - scans text content for secrets using rules."""

from __future__ import annotations

import fnmatch
import re
import time

from gitguard.entropy import shannon_entropy
from gitguard.models import Finding, Rule, ScanConfig, ScanResult, Severity


class ContentScanner:
    """Scans text content against detection rules."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self._compiled_rules: dict[str, re.Pattern] = {}
        self._compiled_allowlist: list[re.Pattern] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for rule in self.config.rules:
            if rule.enabled:
                try:
                    self._compiled_rules[rule.id] = re.compile(rule.pattern)
                except re.error:
                    pass  # Skip invalid patterns

        for pattern in self.config.allowlist_patterns:
            try:
                self._compiled_allowlist.append(re.compile(pattern))
            except re.error:
                pass

    def scan_text(self, content: str, file_path: str = "<stdin>") -> ScanResult:
        """Scan text content for secrets."""
        start = time.monotonic()
        findings: list[Finding] = []
        lines = content.splitlines()

        active_rules = [r for r in self.config.rules if r.enabled]

        # Check file pattern rules
        applicable_rules = self._filter_rules_for_file(active_rules, file_path)

        for line_num, line in enumerate(lines, 1):
            if self._is_allowlisted(line):
                continue

            for rule in applicable_rules:
                compiled = self._compiled_rules.get(rule.id)
                if compiled is None:
                    continue

                for match in compiled.finditer(line):
                    match_text = match.group(0)

                    # Check rule-specific allowlist
                    if self._is_rule_allowlisted(match_text, rule):
                        continue

                    # Check entropy threshold
                    if rule.entropy_threshold is not None:
                        entropy = shannon_entropy(match_text)
                        if entropy < rule.entropy_threshold:
                            continue

                    # Severity filter
                    if rule.severity < self.config.min_severity:
                        continue

                    findings.append(Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line,
                        match_text=match_text,
                        description=rule.description,
                    ))

        elapsed = (time.monotonic() - start) * 1000

        return ScanResult(
            findings=findings,
            files_scanned=1,
            lines_scanned=len(lines),
            rules_applied=len(applicable_rules),
            scan_time_ms=elapsed,
        )

    def scan_lines(
        self, lines: list[str], file_path: str = "<stdin>"
    ) -> ScanResult:
        """Scan a list of lines for secrets."""
        content = "\n".join(lines)
        return self.scan_text(content, file_path)

    def _filter_rules_for_file(
        self, rules: list[Rule], file_path: str
    ) -> list[Rule]:
        """Filter rules based on file pattern matching."""
        applicable: list[Rule] = []
        for rule in rules:
            if not rule.file_patterns:
                applicable.append(rule)
            else:
                for pattern in rule.file_patterns:
                    if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(
                        file_path.split("/")[-1], pattern
                    ):
                        applicable.append(rule)
                        break
        return applicable

    def _is_allowlisted(self, line: str) -> bool:
        """Check if a line matches any global allowlist pattern."""
        for pattern in self._compiled_allowlist:
            if pattern.search(line):
                return True
        return False

    def _is_rule_allowlisted(self, match_text: str, rule: Rule) -> bool:
        """Check if a match is allowlisted by the rule."""
        for allow in rule.allowlist:
            if allow in match_text:
                return True
        return False

    def _is_path_allowlisted(self, file_path: str) -> bool:
        """Check if a file path matches any allowlisted path pattern."""
        for pattern in self.config.allowlist_paths:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False
