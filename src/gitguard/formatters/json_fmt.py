"""JSON output formatter."""

from __future__ import annotations

import json

from gitguard.models import ScanResult


class JsonFormatter:
    """Formats scan results as JSON."""

    def __init__(self, pretty: bool = True) -> None:
        self.pretty = pretty

    def format(self, result: ScanResult) -> str:
        """Format a scan result as JSON."""
        data = {
            "summary": result.summary(),
            "findings": [f.to_dict() for f in result.findings],
        }
        if self.pretty:
            return json.dumps(data, indent=2)
        return json.dumps(data)

    def format_summary_only(self, result: ScanResult) -> str:
        """Format only the summary as JSON."""
        if self.pretty:
            return json.dumps(result.summary(), indent=2)
        return json.dumps(result.summary())
