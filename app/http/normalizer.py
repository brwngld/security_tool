from __future__ import annotations

from urllib.parse import urljoin, urlparse, urlunparse


def normalize_url(base_url: str, candidate: str) -> str:
    # Resolve relative links against the page that found them.
    resolved = urljoin(base_url, candidate)
    parsed = urlparse(resolved)
    normalized = parsed._replace(fragment="")
    return urlunparse(normalized)


def same_host(url_a: str, url_b: str) -> bool:
    # Compare netlocs for a plain scope check.
    return urlparse(url_a).netloc.lower() == urlparse(url_b).netloc.lower()
