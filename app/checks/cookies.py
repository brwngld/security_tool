from __future__ import annotations


def check_cookie_flags(set_cookie_headers: list[str]) -> list[str]:
    return [header for header in set_cookie_headers if "secure" not in header.lower() or "httponly" not in header.lower()]

