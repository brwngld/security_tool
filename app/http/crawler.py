from __future__ import annotations

import re

from bs4 import BeautifulSoup

from app.http.normalizer import normalize_url, same_host


def _matches_scope(
    base_url: str,
    candidate: str,
    *,
    same_host_only: bool,
    include_patterns: list[re.Pattern[str]] | None,
    exclude_patterns: list[re.Pattern[str]] | None,
) -> bool:
    if same_host_only and not same_host(base_url, candidate):
        return False
    if include_patterns and not any(pattern.search(candidate) for pattern in include_patterns):
        return False
    if exclude_patterns and any(pattern.search(candidate) for pattern in exclude_patterns):
        return False
    return True


def extract_links(
    html_text: str,
    base_url: str,
    *,
    same_host_only: bool = True,
    include_patterns: list[re.Pattern[str]] | None = None,
    exclude_patterns: list[re.Pattern[str]] | None = None,
) -> list[str]:
    soup = BeautifulSoup(html_text, "html.parser")
    discovered: list[str] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        candidate = anchor.get("href", "").strip()
        if not candidate or candidate.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        normalized = normalize_url(base_url, candidate)
        if not _matches_scope(
            base_url,
            normalized,
            same_host_only=same_host_only,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        ):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        discovered.append(normalized)
    return discovered


def extract_robots_sitemaps(
    robots_text: str,
    base_url: str,
    *,
    same_host_only: bool = True,
    include_patterns: list[re.Pattern[str]] | None = None,
    exclude_patterns: list[re.Pattern[str]] | None = None,
) -> list[str]:
    discovered: list[str] = []
    seen: set[str] = set()
    for line in robots_text.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith("sitemap:"):
            continue
        candidate = stripped.split(":", 1)[1].strip()
        if not candidate:
            continue
        normalized = normalize_url(base_url, candidate)
        if normalized in seen:
            continue
        if not _matches_scope(
            base_url,
            normalized,
            same_host_only=same_host_only,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        ):
            continue
        seen.add(normalized)
        discovered.append(normalized)
    return discovered


def extract_sitemap_urls(
    sitemap_xml: str,
    base_url: str,
    *,
    same_host_only: bool = True,
    include_patterns: list[re.Pattern[str]] | None = None,
    exclude_patterns: list[re.Pattern[str]] | None = None,
) -> list[str]:
    discovered: list[str] = []
    seen: set[str] = set()
    for candidate in re.findall(r"<loc>(.*?)</loc>", sitemap_xml, flags=re.IGNORECASE | re.DOTALL):
        candidate = candidate.strip()
        if not candidate:
            continue
        normalized = normalize_url(base_url, candidate)
        if normalized in seen:
            continue
        if not _matches_scope(
            base_url,
            normalized,
            same_host_only=same_host_only,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        ):
            continue
        seen.add(normalized)
        discovered.append(normalized)
    return discovered
