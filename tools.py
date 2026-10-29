"""Compatibility exports for the original ``tools`` module."""

from scamshield.tools.checks import (
    OFFICIAL,
    OPERATORS,
    PATTERNS,
    TOOLS,
    check_phone,
    check_url,
    extract_indicators,
    match_scam_patterns,
    run_tool,
)

__all__ = [
    "OFFICIAL",
    "OPERATORS",
    "PATTERNS",
    "TOOLS",
    "check_phone",
    "check_url",
    "extract_indicators",
    "match_scam_patterns",
    "run_tool",
]
