from __future__ import annotations

import re

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)(password\s*=\s*)[^&\s]+"),
    re.compile(r"(?i)(password\s*:\s*)[^\s,;]+"),
    re.compile(r"(?i)(token\s*=\s*)[^&\s]+"),
    re.compile(r"(?i)(token\s*:\s*)[^\s,;]+"),
    re.compile(r"(?i)(api[_-]?key\s*=\s*)[^&\s]+"),
    re.compile(r"(?i)(api[_-]?key\s*:\s*)[^\s,;]+"),
    re.compile(r"(?i)(secret\s*=\s*)[^&\s]+"),
    re.compile(r"(?i)(secret\s*:\s*)[^\s,;]+"),
    re.compile(r"(?i)(session\s*=\s*)[^&\s]+"),
    re.compile(r"(?i)(cookie\s*=\s*)[^&\s]+"),
]


def redact_text(text: str) -> str:
    result = text
    for pattern in SECRET_PATTERNS:
        result = pattern.sub(r"\1[REDACTED]", result)
    return result
