"""Shannon entropy calculation for detecting high-entropy strings."""

from __future__ import annotations

import math
import re
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def hex_entropy(data: str) -> float:
    """Calculate entropy assuming hex charset."""
    hex_match = re.search(r"[0-9a-fA-F]{16,}", data)
    if hex_match:
        return shannon_entropy(hex_match.group())
    return 0.0


def base64_entropy(data: str) -> float:
    """Calculate entropy assuming base64 charset."""
    b64_match = re.search(r"[A-Za-z0-9+/=]{20,}", data)
    if b64_match:
        return shannon_entropy(b64_match.group())
    return 0.0


def is_high_entropy(data: str, threshold: float = 4.5) -> bool:
    """Check if a string has high entropy (likely random/secret)."""
    if len(data) < 8:
        return False
    return shannon_entropy(data) >= threshold


def extract_high_entropy_strings(
    line: str, min_length: int = 16, threshold: float = 4.5
) -> list[str]:
    """Extract high-entropy substrings from a line."""
    results: list[str] = []
    # Find potential secret strings (alphanumeric + common secret chars)
    pattern = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % min_length)

    for match in pattern.finditer(line):
        candidate = match.group()
        if shannon_entropy(candidate) >= threshold:
            results.append(candidate)

    return results
