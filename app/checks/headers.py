from __future__ import annotations

from app.probes.headers import *  # noqa: F401,F403


def check_security_headers(headers: dict[str, str]) -> list[str]:
    # Check the v1 headers.
    missing = []
    for name in ("content-security-policy", "x-frame-options", "x-content-type-options"):
        if name not in {key.lower() for key in headers}:
            missing.append(name)
    return missing
