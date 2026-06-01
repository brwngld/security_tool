from __future__ import annotations

from collections import deque
import re
import httpx
from urllib.parse import urlparse

from app.checks.headers import check_security_headers
from app.checks.exposed_files import check_exposed_files
from app.checks.cookies import check_cookie_flags
from app.checks.server_info import extract_server_banner
from app.checks.waf import detect_waf_signals
from app.checks.tls import summarize_tls
from app.remediation.recommendations import recommend_fix
from app.http.auth import CrawlAuthConfig, authenticate_client
from app.http.client import build_client, fetch_page
from app.http.crawler import extract_links, extract_robots_sitemaps, extract_sitemap_urls
from app.http.normalizer import normalize_url, same_host
from app.models import Finding, ScanResult, Target


def _canonicalize_target(target_url: str) -> tuple[str, Target]:
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    canonical_url = normalize_url(f"{parsed.scheme}://{parsed.netloc or parsed.path}", parsed.path or "/")
    target = Target(url=canonical_url, scheme=parsed.scheme or "https", host=parsed.netloc or parsed.path)
    return canonical_url, target


def _cookie_name(cookie_header: str) -> str:
    return cookie_header.split("=", 1)[0].strip().lower()


def _cookie_confidence(cookie_header: str) -> str:
    cookie_name = _cookie_name(cookie_header)
    if "csrf" in cookie_name or "xsrf" in cookie_name:
        return "medium"
    return "high"


def _cookie_expected_impact(cookie_header: str) -> str:
    cookie_name = _cookie_name(cookie_header)
    if "csrf" in cookie_name or "xsrf" in cookie_name:
        return "Review issuance location before applying."
    return "Report only; no system change required."


def _aggregate_crawl_findings(findings: list[Finding]) -> list[Finding]:
    grouped: list[Finding] = []
    seen: dict[tuple, Finding] = {}

    for finding in findings:
        evidence_items = finding.evidence.items()
        if finding.category == "cookies":
            cookie_name = str(finding.evidence.get("cookie_name", "")).strip().lower()
            evidence_key = (("cookie_name", cookie_name),)
        else:
            evidence_key = tuple(
                sorted(
                    (
                        key,
                        str(value),
                    )
                    for key, value in evidence_items
                    if key != "url"
                )
            )
        fingerprint = (
            finding.category,
            finding.title,
            finding.severity,
            finding.fix_level,
            finding.risk_level,
            finding.expected_impact,
            finding.confidence,
            evidence_key,
        )
        existing = seen.get(fingerprint)
        if existing is None:
            copy = finding.model_copy(deep=True)
            copy.affected_urls = [finding.target_url]
            seen[fingerprint] = copy
            grouped.append(copy)
            continue
        if finding.target_url not in existing.affected_urls:
            existing.affected_urls.append(finding.target_url)

    return grouped


def _discover_crawl_seeds(
    client: httpx.Client,
    base_url: str,
    *,
    same_host_only: bool,
    include_patterns: list[re.Pattern[str]] | None,
    exclude_patterns: list[re.Pattern[str]] | None,
    seed_robots: bool,
    seed_sitemap: bool,
) -> tuple[list[str], list[str]]:
    discovered: list[str] = []
    seen: set[str] = set()
    sources: list[str] = []

    def add_seed(candidate: str) -> None:
        normalized = normalize_url(base_url, candidate)
        if normalized in seen:
            return
        if same_host_only and not same_host(base_url, normalized):
            return
        if include_patterns and not any(pattern.search(normalized) for pattern in include_patterns):
            return
        if exclude_patterns and any(pattern.search(normalized) for pattern in exclude_patterns):
            return
        seen.add(normalized)
        discovered.append(normalized)

    if seed_robots:
        for candidate in (normalize_url(base_url, "/robots.txt"),):
            try:
                response = fetch_page(client, candidate)
            except httpx.RequestError:
                continue
            if response.status_code < 400:
                robot_seeds = extract_robots_sitemaps(
                    response.text,
                    base_url,
                    same_host_only=same_host_only,
                    include_patterns=include_patterns,
                    exclude_patterns=exclude_patterns,
                )
                if robot_seeds and "robots.txt" not in sources:
                    sources.append("robots.txt")
                for seed in robot_seeds:
                    add_seed(seed)

    sitemap_candidates: list[str] = []
    if seed_sitemap:
        sitemap_candidates.append(normalize_url(base_url, "/sitemap.xml"))

    for sitemap_url in sitemap_candidates:
        try:
            response = fetch_page(client, sitemap_url)
        except httpx.RequestError:
            continue
        if response.status_code >= 400:
            continue
        sitemap_seeds = extract_sitemap_urls(
            response.text,
            base_url,
            same_host_only=same_host_only,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        )
        if sitemap_seeds and "sitemap.xml" not in sources:
            sources.append("sitemap.xml")
        for seed in sitemap_seeds:
            add_seed(seed)

    return discovered, sources


def _build_target_unreachable_result(target: Target, canonical_url: str, notes: list[str]) -> ScanResult:
    findings = [
        Finding(
            id="target-unreachable",
            target_url=canonical_url,
            title="Target unreachable",
            description="PsyberShield could not complete the initial request.",
            severity="low",
            category="connectivity",
            evidence={
                "error": notes[-1].split(": ", 1)[-1] if notes else "RequestError",
                "url": canonical_url,
            },
            fix_level=0,
            risk_level="low",
            expected_impact="Report only; no system change required.",
            references=[],
        )
    ]
    fix_plans = [recommend_fix(finding) for finding in findings]
    return ScanResult(
        target=target,
        findings=findings,
        fix_plans=fix_plans,
        scanned_urls=[canonical_url],
        notes=notes,
        waf_signals=[],
        tls_summary={},
        scan_confidence=0.0,
    )


def _scan_response(
    client: httpx.Client,
    canonical_url: str,
    page_url: str,
    response: httpx.Response,
    include_exposed_files: bool,
    finding_prefix: str = "",
) -> tuple[list[Finding], list[str], list[str]]:
    findings: list[Finding] = []
    notes: list[str] = []
    waf_signals = detect_waf_signals(dict(response.headers))
    if not same_host(canonical_url, page_url):
        notes.append("Redirect moved the scan outside the original host.")

    missing_headers = check_security_headers(dict(response.headers))
    for header_name in missing_headers:
        findings.append(
            Finding(
                id=f"{finding_prefix}missing-{header_name}",
                target_url=page_url,
                title=f"Missing security header: {header_name}",
                description=f"The response does not include the {header_name} header.",
                severity="low",
                category="headers",
                evidence={
                    "header": header_name,
                    "status_code": response.status_code,
                    "url": page_url,
                },
                fix_level=0,
                risk_level="low",
                expected_impact="Report only; no system change required.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
            )
        )

    weak_cookie_headers = check_cookie_flags(response.headers.get_list("set-cookie"))
    for cookie_header in weak_cookie_headers:
            findings.append(
                Finding(
                    id=f"{finding_prefix}weak-cookie-{len(findings)}",
                    target_url=page_url,
                    title="Weak cookie flags",
                    description=(
                        "A cookie is missing Secure or HttpOnly. "
                        "CSRF-related cookies can intentionally remain readable to client-side code."
                    )
                    if _cookie_confidence(cookie_header) == "medium"
                    else "A cookie is missing Secure or HttpOnly.",
                    severity="low",
                    category="cookies",
                    evidence={
                        "cookie_name": _cookie_name(cookie_header),
                        "set_cookie": cookie_header,
                        "status_code": response.status_code,
                        "url": page_url,
                    },
                    fix_level=0,
                    risk_level="low",
                    confidence=_cookie_confidence(cookie_header),
                    expected_impact=_cookie_expected_impact(cookie_header),
                    references=["https://owasp.org/www-community/HttpOnly"],
                )
            )

    server_banner = extract_server_banner(dict(response.headers))
    if server_banner:
        findings.append(
            Finding(
                id=f"{finding_prefix}server-banner-disclosure",
                target_url=page_url,
                title="Server information disclosure",
                description="The response reveals a server banner or framework header.",
                severity="low",
                category="server_info",
                evidence={
                    "header_value": server_banner,
                    "status_code": response.status_code,
                    "url": page_url,
                },
                fix_level=0,
                risk_level="low",
                expected_impact="Report only; no system change required.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )
        )

    notes.extend([f"WAF signal: {signal}" for signal in waf_signals])
    if include_exposed_files:
        findings.extend(check_exposed_files(client, page_url))

    return findings, notes, waf_signals


def _scan_https(target: Target, timeout_seconds: float) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    tls_summary: dict[str, str] = {}
    if target.scheme == "https":
        tls_summary = summarize_tls(str(target.url), timeout_seconds=timeout_seconds)
        if tls_summary.get("status") == "ok":
            days_left = tls_summary.get("days_left", "")
            if days_left.isdigit() and int(days_left) <= 30:
                findings.append(
                    Finding(
                        id="tls-certificate-expiry",
                        target_url=str(target.url),
                        title="TLS certificate expires soon",
                        description="The certificate has 30 days or less left.",
                        severity="medium",
                        category="tls",
                        evidence=tls_summary,
                        fix_level=0,
                        risk_level="low",
                        expected_impact="Report only; no system change required.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
                    )
                )
    return findings, tls_summary


def _build_scan_result(
    target: Target,
    findings: list[Finding],
    notes: list[str],
    scanned_urls: list[str],
    waf_signals: list[str],
    tls_summary: dict[str, str],
    scan_confidence: float,
) -> ScanResult:
    fix_plans = [recommend_fix(finding) for finding in findings]
    unique_waf_signals = list(dict.fromkeys(waf_signals))
    return ScanResult(
        target=target,
        findings=findings,
        fix_plans=fix_plans,
        scanned_urls=scanned_urls,
        notes=notes,
        waf_signals=unique_waf_signals,
        tls_summary=tls_summary,
        scan_confidence=scan_confidence,
    )


def scan_target(
    target_url: str,
    timeout_seconds: float = 10.0,
    auth_config: CrawlAuthConfig | None = None,
) -> ScanResult:
    canonical_url, target = _canonicalize_target(target_url)
    findings: list[Finding] = []
    notes: list[str] = []
    scanned_urls = [canonical_url]

    with build_client(timeout_seconds) as client:
        notes.extend(authenticate_client(client, canonical_url, auth_config))
        try:
            response = fetch_page(client, canonical_url)
        except httpx.RequestError as exc:
            notes.append(f"Request failed: {exc.__class__.__name__}")
            return _build_target_unreachable_result(target, canonical_url, notes)

        page_url = str(response.url)
        page_findings, page_notes, waf_signals = _scan_response(
            client,
            canonical_url,
            page_url,
            response,
            include_exposed_files=True,
        )
        findings.extend(page_findings)
        notes.extend(page_notes)
        tls_findings, tls_summary = _scan_https(target, timeout_seconds)
        findings.extend(tls_findings)

    return _build_scan_result(target, findings, notes, scanned_urls, waf_signals, tls_summary, 1.0)


def crawl_target(
    target_url: str,
    timeout_seconds: float = 10.0,
    max_pages: int = 20,
    max_crawl_depth: int = 2,
    same_host_only: bool = True,
    include_patterns: list[re.Pattern[str]] | None = None,
    exclude_patterns: list[re.Pattern[str]] | None = None,
    seed_robots: bool = False,
    seed_sitemap: bool = False,
    auth_config: CrawlAuthConfig | None = None,
) -> ScanResult:
    canonical_url, target = _canonicalize_target(target_url)
    findings: list[Finding] = []
    notes: list[str] = []
    scanned_urls: list[str] = []
    waf_signals: list[str] = []
    page_queue = deque([(canonical_url, 0)])
    visited: set[str] = set()

    with build_client(timeout_seconds) as client:
        notes.extend(authenticate_client(client, canonical_url, auth_config))
        crawl_seed_urls, crawl_seed_sources = _discover_crawl_seeds(
            client,
            canonical_url,
            same_host_only=same_host_only,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            seed_robots=seed_robots,
            seed_sitemap=seed_sitemap,
        )
        for seed in crawl_seed_urls:
            if seed not in visited and seed != canonical_url:
                page_queue.appendleft((seed, 0))

        while page_queue and len(scanned_urls) < max_pages:
            page_url, depth = page_queue.popleft()
            if page_url in visited:
                continue
            visited.add(page_url)
            scanned_urls.append(page_url)

            try:
                response = fetch_page(client, page_url)
            except httpx.RequestError as exc:
                notes.append(f"Request failed at {page_url}: {exc.__class__.__name__}")
                if len(scanned_urls) == 1:
                    notes.append(f"Request failed: {exc.__class__.__name__}")
                    return _build_target_unreachable_result(target, canonical_url, notes)
                continue

            finding_prefix = f"p{len(scanned_urls)}-"
            page_findings, page_notes, page_waf_signals = _scan_response(
                client,
                canonical_url,
                str(response.url),
                response,
                include_exposed_files=page_url == canonical_url,
                finding_prefix=finding_prefix,
            )
            findings.extend(page_findings)
            notes.extend(page_notes)
            waf_signals.extend(page_waf_signals)

            if depth < max_crawl_depth and "html" in response.headers.get("content-type", "").lower():
                for link in extract_links(
                    response.text,
                    str(response.url),
                    same_host_only=same_host_only,
                    include_patterns=include_patterns,
                    exclude_patterns=exclude_patterns,
                ):
                    if link not in visited:
                        page_queue.append((link, depth + 1))

    tls_findings, tls_summary = _scan_https(target, timeout_seconds)
    findings.extend(tls_findings)
    findings = _aggregate_crawl_findings(findings)
    fix_plans = [recommend_fix(finding) for finding in findings]
    crawl_sources = list(crawl_seed_sources)
    if "page links" not in crawl_sources:
        crawl_sources.append("page links")
    notes.append(f"Crawled {len(scanned_urls)} page(s) within scope.")
    return ScanResult(
        target=target,
        findings=findings,
        fix_plans=fix_plans,
        scanned_urls=scanned_urls,
        crawl_seed_sources=crawl_sources,
        notes=notes,
        waf_signals=waf_signals,
        tls_summary=tls_summary,
        scan_confidence=1.0 if scanned_urls else 0.0,
    )

