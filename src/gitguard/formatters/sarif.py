"""SARIF output formatter for CI/CD integration."""

from __future__ import annotations

import json

from gitguard import __version__
from gitguard.models import ScanResult, Severity


SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SarifFormatter:
    """Formats scan results in SARIF format for CI/CD integration."""

    def format(self, result: ScanResult) -> str:
        """Format a scan result as SARIF JSON."""
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "gitguard",
                            "version": __version__,
                            "informationUri": "https://github.com/JSLEEKR/gitguard",
                            "rules": self._build_rules(result),
                        }
                    },
                    "results": self._build_results(result),
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _build_rules(self, result: ScanResult) -> list[dict]:
        seen: dict[str, dict] = {}
        for finding in result.findings:
            if finding.rule_id not in seen:
                seen[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_name,
                    "shortDescription": {"text": finding.rule_name},
                    "fullDescription": {"text": finding.description or finding.rule_name},
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF.get(finding.severity, "warning")
                    },
                }
        return list(seen.values())

    def _build_results(self, result: ScanResult) -> list[dict]:
        results = []
        for finding in result.findings:
            results.append({
                "ruleId": finding.rule_id,
                "level": SEVERITY_TO_SARIF.get(finding.severity, "warning"),
                "message": {
                    "text": f"{finding.rule_name}: {finding.description}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path,
                            },
                            "region": {
                                "startLine": finding.line_number,
                            },
                        }
                    }
                ],
            })
        return results
