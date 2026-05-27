from __future__ import annotations


def security_header_snippet() -> str:
    return (
        "add_header X-Content-Type-Options nosniff always;\n"
        "add_header X-Frame-Options SAMEORIGIN always;\n"
        "add_header Referrer-Policy no-referrer-when-downgrade always;\n"
    )

