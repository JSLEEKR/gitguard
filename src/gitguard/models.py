"""Core data models for gitguard."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return weights[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self < other

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return not self <= other

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return not self < other


@dataclass
class Rule:
    """A detection rule for secrets/credentials."""
    id: str
    name: str
    pattern: str
    severity: Severity
    description: str = ""
    category: str = "general"
    entropy_threshold: float | None = None
    allowlist: list[str] = field(default_factory=list)
    file_patterns: list[str] = field(default_factory=list)
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "pattern": self.pattern,
            "severity": self.severity.value,
            "description": self.description,
            "category": self.category,
            "entropy_threshold": self.entropy_threshold,
            "allowlist": self.allowlist,
            "file_patterns": self.file_patterns,
            "enabled": self.enabled,
        }


@dataclass
class Finding:
    """A detected secret or credential."""
    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    match_text: str
    description: str = ""
    masked_match: str = ""

    def __post_init__(self) -> None:
        if not self.masked_match and self.match_text:
            self.masked_match = self._mask(self.match_text)

    @staticmethod
    def _mask(text: str) -> str:
        if len(text) <= 8:
            return "*" * len(text)
        return text[:4] + "*" * (len(text) - 8) + text[-4:]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content[:200],
            "match_text": self.masked_match,
            "description": self.description,
        }


@dataclass
class ScanResult:
    """Result of a security scan."""
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    rules_applied: int = 0
    scan_time_ms: float = 0.0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    @property
    def risk_score(self) -> int:
        return sum(f.severity.weight for f in self.findings)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def findings_by_file(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.file_path, []).append(f)
        return result

    def summary(self) -> dict:
        by_severity = {}
        for s in Severity:
            count = len(self.findings_by_severity(s))
            if count > 0:
                by_severity[s.value] = count
        return {
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "rules_applied": self.rules_applied,
            "risk_score": self.risk_score,
            "scan_time_ms": round(self.scan_time_ms, 2),
        }


@dataclass
class ScanConfig:
    """Configuration for a scan."""
    rules: list[Rule] = field(default_factory=list)
    allowlist_patterns: list[str] = field(default_factory=list)
    allowlist_paths: list[str] = field(default_factory=list)
    max_file_size_kb: int = 500
    scan_all_files: bool = False
    min_severity: Severity = Severity.LOW
    entropy_enabled: bool = True
    custom_rules_path: str | None = None
