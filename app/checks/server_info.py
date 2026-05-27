from __future__ import annotations


def extract_server_banner(headers: dict[str, str]) -> str | None:
    for key in ("server", "x-powered-by"):
        if key in {name.lower() for name in headers}:
            for actual_key, value in headers.items():
                if actual_key.lower() == key:
                    return value
    return None

