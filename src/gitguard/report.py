"""Report generation for scan results."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from gitguard.models import ScanResult, Severity


@dataclass
class ScanReport:
    """Aggregated report from one or more scan results."""
    results: list[ScanResult] = field(default_factory=list)
    project_name: str = ""
    generated_at: str = ""

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def add_result(self, result: ScanResult) -> None:
        self.results.append(result)

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)

    @property
    def total_files_scanned(self) -> int:
        return sum(r.files_scanned for r in self.results)

    @property
    def total_lines_scanned(self) -> int:
        return sum(r.lines_scanned for r in self.results)

    @property
    def total_risk_score(self) -> int:
        return sum(r.risk_score for r in self.results)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: Counter = Counter()
        for r in self.results:
            for f in r.findings:
                counts[f.severity.value] += 1
        return dict(counts)

    @property
    def category_counts(self) -> dict[str, int]:
        counts: Counter = Counter()
        for r in self.results:
            for f in r.findings:
                counts[f.rule_id.split("-")[0]] += 1
        return dict(counts)

    @property
    def top_rules(self) -> list[tuple[str, int]]:
        counts: Counter = Counter()
        for r in self.results:
            for f in r.findings:
                counts[f.rule_id] += 1
        return counts.most_common(10)

    @property
    def affected_files(self) -> list[str]:
        files: set[str] = set()
        for r in self.results:
            for f in r.findings:
                files.add(f.file_path)
        return sorted(files)

    @property
    def pass_fail(self) -> str:
        return "FAIL" if self.total_findings > 0 else "PASS"

    def to_dict(self) -> dict:
        return {
            "project": self.project_name,
            "generated_at": self.generated_at,
            "status": self.pass_fail,
            "summary": {
                "total_findings": self.total_findings,
                "total_files_scanned": self.total_files_scanned,
                "total_lines_scanned": self.total_lines_scanned,
                "risk_score": self.total_risk_score,
                "severity_counts": self.severity_counts,
            },
            "top_rules": [{"rule": r, "count": c} for r, c in self.top_rules],
            "affected_files": self.affected_files,
        }

    def to_json(self, pretty: bool = True) -> str:
        if pretty:
            return json.dumps(self.to_dict(), indent=2)
        return json.dumps(self.to_dict())

    def to_markdown(self) -> str:
        lines: list[str] = []
        lines.append(f"# Security Scan Report")
        if self.project_name:
            lines.append(f"**Project:** {self.project_name}")
        lines.append(f"**Status:** {self.pass_fail}")
        lines.append(f"**Generated:** {self.generated_at}")
        lines.append("")
        lines.append("## Summary")
        lines.append(f"- Findings: {self.total_findings}")
        lines.append(f"- Files scanned: {self.total_files_scanned}")
        lines.append(f"- Lines scanned: {self.total_lines_scanned}")
        lines.append(f"- Risk score: {self.total_risk_score}")
        lines.append("")

        if self.severity_counts:
            lines.append("## By Severity")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = self.severity_counts.get(sev, 0)
                if count > 0:
                    lines.append(f"- {sev.upper()}: {count}")
            lines.append("")

        if self.top_rules:
            lines.append("## Top Rules")
            lines.append("| Rule | Count |")
            lines.append("|------|-------|")
            for rule, count in self.top_rules:
                lines.append(f"| {rule} | {count} |")
            lines.append("")

        if self.affected_files:
            lines.append("## Affected Files")
            for f in self.affected_files:
                lines.append(f"- {f}")
            lines.append("")

        return "\n".join(lines)
