from __future__ import annotations

from app.probes.waf import *  # noqa: F401,F403


def detect_waf_signals(headers: dict[str, str]) -> list[str]:
    signals = []
    lowered = {k.lower(): v.lower() for k, v in headers.items()}
    for marker in ("cf-ray", "x-sucuri-id", "x-cdn", "x-waf"):
        if marker in lowered:
            signals.append(marker)
    return signals
