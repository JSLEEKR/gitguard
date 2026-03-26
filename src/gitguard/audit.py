"""Audit logging for gitguard scans."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from gitguard.models import Finding, ScanResult


@dataclass
class AuditEntry:
    """A single audit log entry."""
    timestamp: str
    scan_type: str
    status: str
    findings_count: int
    risk_score: int
    files_scanned: int
    scan_time_ms: float
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "scan_type": self.scan_type,
            "status": self.status,
            "findings_count": self.findings_count,
            "risk_score": self.risk_score,
            "files_scanned": self.files_scanned,
            "scan_time_ms": round(self.scan_time_ms, 2),
            **self.details,
        }


class AuditLog:
    """In-memory audit log for tracking scan history."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(self, result: ScanResult, scan_type: str = "diff", **details) -> AuditEntry:
        """Record a scan result."""
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            scan_type=scan_type,
            status="FAIL" if result.has_findings else "PASS",
            findings_count=len(result.findings),
            risk_score=result.risk_score,
            files_scanned=result.files_scanned,
            scan_time_ms=result.scan_time_ms,
            details=details,
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    @property
    def total_scans(self) -> int:
        return len(self._entries)

    @property
    def failed_scans(self) -> int:
        return sum(1 for e in self._entries if e.status == "FAIL")

    @property
    def passed_scans(self) -> int:
        return sum(1 for e in self._entries if e.status == "PASS")

    def to_json(self, pretty: bool = True) -> str:
        data = [e.to_dict() for e in self._entries]
        return json.dumps(data, indent=2 if pretty else None)

    def clear(self) -> None:
        self._entries.clear()


def export_findings_csv(findings: list[Finding]) -> str:
    """Export findings as CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "rule_id", "rule_name", "severity", "file_path",
        "line_number", "match_masked", "description",
    ])
    for f in findings:
        writer.writerow([
            f.rule_id, f.rule_name, f.severity.value, f.file_path,
            f.line_number, f.masked_match, f.description,
        ])
    return output.getvalue()


def export_findings_jsonl(findings: list[Finding]) -> str:
    """Export findings as JSON Lines format."""
    lines: list[str] = []
    for f in findings:
        lines.append(json.dumps(f.to_dict()))
    return "\n".join(lines)
