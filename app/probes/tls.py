from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def summarize_tls(target: str, timeout_seconds: float = 5.0) -> dict[str, str]:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or parsed.path
    port = parsed.port or 443

    if parsed.scheme and parsed.scheme.lower() != "https":
        return {
            "target": target,
            "status": "skipped",
            "reason": "target is not https",
        }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout_seconds) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert()
                not_after = cert.get("notAfter", "")
                expires_on = ""
                days_left = ""
                if not_after:
                    expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = str((expires_at - datetime.now(timezone.utc)).days)
                    expires_on = expires_at.date().isoformat()

                return {
                    "target": target,
                    "status": "ok",
                    "host": host,
                    "port": str(port),
                    "subject": str(cert.get("subject", "")),
                    "issuer": str(cert.get("issuer", "")),
                    "expires_on": expires_on,
                    "days_left": days_left,
                    "tls_version": tls_socket.version() or "",
                }
    except Exception as exc:
        return {
            "target": target,
            "status": "error",
            "error": str(exc),
        }
