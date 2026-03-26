"""Inline suppression comments for gitguard.

Supports:
  # gitguard:disable
  # gitguard:disable=rule-id
  # gitguard:disable=rule-id,other-rule
  # gitguard:disable-next-line
  # gitguard:disable-next-line=rule-id
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


DISABLE_PATTERN = re.compile(
    r"#\s*gitguard:disable(?:=([a-zA-Z0-9_,\-]+))?\s*$"
)
DISABLE_NEXT_LINE_PATTERN = re.compile(
    r"#\s*gitguard:disable-next-line(?:=([a-zA-Z0-9_,\-]+))?\s*$"
)


@dataclass
class SuppressionMap:
    """Tracks which lines/rules are suppressed via inline comments."""
    # line_number -> set of rule_ids (empty set = all rules)
    suppressed_lines: dict[int, set[str]] = field(default_factory=dict)

    def is_suppressed(self, line_number: int, rule_id: str) -> bool:
        """Check if a finding on this line/rule is suppressed."""
        if line_number not in self.suppressed_lines:
            return False
        rules = self.suppressed_lines[line_number]
        # Empty set means all rules are suppressed
        return len(rules) == 0 or rule_id in rules

    @property
    def total_suppressions(self) -> int:
        return len(self.suppressed_lines)


def parse_suppressions(content: str) -> SuppressionMap:
    """Parse inline suppression comments from file content."""
    smap = SuppressionMap()
    lines = content.splitlines()

    for i, line in enumerate(lines):
        line_num = i + 1

        # Check for disable on same line
        match = DISABLE_PATTERN.search(line)
        if match:
            rules = _parse_rule_list(match.group(1))
            smap.suppressed_lines[line_num] = rules
            continue

        # Check for disable-next-line
        match = DISABLE_NEXT_LINE_PATTERN.search(line)
        if match:
            rules = _parse_rule_list(match.group(1))
            next_line = line_num + 1
            if next_line <= len(lines):
                smap.suppressed_lines[next_line] = rules

    return smap


def _parse_rule_list(rule_str: str | None) -> set[str]:
    """Parse a comma-separated list of rule IDs."""
    if not rule_str:
        return set()  # Empty = all rules
    return {r.strip() for r in rule_str.split(",") if r.strip()}
