from __future__ import annotations

import httpx
import re

from app import scanner
from app.http.crawler import extract_links, extract_robots_sitemaps, extract_sitemap_urls


class DummyClient:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def make_response(url: str, body: str, headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("GET", url)
    return httpx.Response(200, request=request, text=body, headers=headers or {})


def test_extract_links_keeps_same_host_links() -> None:
    html = """
    <html>
      <body>
        <a href="/about">About</a>
        <a href="https://example.com/contact">Contact</a>
        <a href="https://other.example.org/">Outside</a>
        <a href="mailto:team@example.com">Mail</a>
      </body>
    </html>
    """

    links = extract_links(html, "https://example.com/")

    assert links == [
        "https://example.com/about",
        "https://example.com/contact",
    ]


def test_extract_links_can_allow_offsite_links_when_requested() -> None:
    html = """
    <html>
      <body>
        <a href="/about">About</a>
        <a href="https://other.example.org/">Outside</a>
      </body>
    </html>
    """

    links = extract_links(html, "https://example.com/", same_host_only=False)

    assert links == [
        "https://example.com/about",
        "https://other.example.org/",
    ]


def test_extract_links_supports_include_and_exclude_filters() -> None:
    html = """
    <html>
      <body>
        <a href="/about">About</a>
        <a href="/auth/login">Login</a>
        <a href="/auth/register">Register</a>
      </body>
    </html>
    """

    links = extract_links(
        html,
        "https://example.com/",
        include_patterns=[re.compile(r"/auth/")],
        exclude_patterns=[re.compile(r"register")],
    )

    assert links == ["https://example.com/auth/login"]


def test_extract_robots_and_sitemap_urls_filters_scope() -> None:
    robots_text = """
    User-agent: *
    Sitemap: https://example.com/sitemap.xml
    Sitemap: https://other.example.org/sitemap.xml
    """
    sitemap_xml = """
    <urlset>
      <url><loc>https://example.com/about</loc></url>
      <url><loc>https://example.com/auth/login</loc></url>
      <url><loc>https://other.example.org/</loc></url>
    </urlset>
    """

    robots_links = extract_robots_sitemaps(robots_text, "https://example.com/")
    sitemap_links = extract_sitemap_urls(
        sitemap_xml,
        "https://example.com/",
        include_patterns=[re.compile(r"/auth/")],
    )

    assert robots_links == ["https://example.com/sitemap.xml"]
    assert sitemap_links == ["https://example.com/auth/login"]


def test_crawl_target_walks_in_scope_pages(monkeypatch) -> None:
    start_url = "http://example.com/"
    about_url = "http://example.com/about"
    responses = {
        start_url: make_response(
            start_url,
            '<html><body><a href="/about">About</a></body></html>',
            headers={
                "content-type": "text/html; charset=utf-8",
                "set-cookie": "session=abc; Path=/; SameSite=Lax",
                "server": "nginx/1.20.1",
            },
        ),
        about_url: make_response(
            about_url,
            "<html><body><p>About page</p></body></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
            },
        ),
    }

    monkeypatch.setattr(scanner, "build_client", lambda timeout_seconds: DummyClient())
    monkeypatch.setattr(scanner, "fetch_page", lambda client, url: responses[url])
    monkeypatch.setattr(scanner, "check_exposed_files", lambda client, base_url: [])

    result = scanner.crawl_target(start_url, timeout_seconds=1.0, max_pages=5, max_crawl_depth=2)

    assert result.scanned_urls == [start_url, about_url]
    assert any(finding.category == "cookies" for finding in result.findings)
    assert any(finding.category == "server_info" for finding in result.findings)
    assert any(finding.category == "headers" for finding in result.findings)
    assert "Crawled 2 page(s) within scope." in result.notes


def test_crawl_target_respects_include_scope(monkeypatch) -> None:
    start_url = "http://example.com/"
    about_url = "http://example.com/about"
    auth_url = "http://example.com/auth/login"
    responses = {
        start_url: make_response(
            start_url,
            '<html><body><a href="/about">About</a><a href="/auth/login">Login</a></body></html>',
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.20.1",
            },
        ),
        about_url: make_response(
            about_url,
            "<html><body><p>About page</p></body></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.20.1",
            },
        ),
        auth_url: make_response(
            auth_url,
            "<html><body><p>Auth page</p></body></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.20.1",
            },
        ),
    }

    monkeypatch.setattr(scanner, "build_client", lambda timeout_seconds: DummyClient())
    monkeypatch.setattr(scanner, "fetch_page", lambda client, url: responses[url])
    monkeypatch.setattr(scanner, "check_exposed_files", lambda client, base_url: [])

    result = scanner.crawl_target(
        start_url,
        timeout_seconds=1.0,
        max_pages=5,
        max_crawl_depth=2,
        include_patterns=[re.compile(r"/auth/")],
    )

    assert result.scanned_urls == [start_url, auth_url]


def test_crawl_target_respects_exclude_scope(monkeypatch) -> None:
    start_url = "http://example.com/"
    about_url = "http://example.com/about"
    auth_url = "http://example.com/auth/login"
    responses = {
        start_url: make_response(
            start_url,
            '<html><body><a href="/about">About</a><a href="/auth/login">Login</a></body></html>',
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.20.1",
            },
        ),
        about_url: make_response(
            about_url,
            "<html><body><p>About page</p></body></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.20.1",
            },
        ),
        auth_url: make_response(
            auth_url,
            "<html><body><p>Auth page</p></body></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.20.1",
            },
        ),
    }

    monkeypatch.setattr(scanner, "build_client", lambda timeout_seconds: DummyClient())
    monkeypatch.setattr(scanner, "fetch_page", lambda client, url: responses[url])
    monkeypatch.setattr(scanner, "check_exposed_files", lambda client, base_url: [])

    result = scanner.crawl_target(
        start_url,
        timeout_seconds=1.0,
        max_pages=5,
        max_crawl_depth=2,
        exclude_patterns=[re.compile(r"/about")],
    )

    assert result.scanned_urls == [start_url, auth_url]


def test_crawl_target_seeds_from_robots_and_sitemap(monkeypatch) -> None:
    start_url = "http://example.com/"
    robots_url = "http://example.com/robots.txt"
    sitemap_url = "http://example.com/sitemap.xml"
    about_url = "http://example.com/about"
    login_url = "http://example.com/auth/login"
    responses = {
        start_url: make_response(
            start_url,
            "<html><body><p>Home</p></body></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.20.1",
            },
        ),
        robots_url: make_response(
            robots_url,
            "User-agent: *\nSitemap: http://example.com/sitemap.xml",
            headers={"content-type": "text/plain"},
        ),
        sitemap_url: make_response(
            sitemap_url,
            "<urlset><url><loc>http://example.com/about</loc></url><url><loc>http://example.com/auth/login</loc></url></urlset>",
            headers={"content-type": "application/xml"},
        ),
        about_url: make_response(
            about_url,
            "<html><body><p>About page</p></body></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.20.1",
            },
        ),
        login_url: make_response(
            login_url,
            "<html><body><p>Login page</p></body></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "nginx/1.20.1",
            },
        ),
    }

    monkeypatch.setattr(scanner, "build_client", lambda timeout_seconds: DummyClient())
    monkeypatch.setattr(scanner, "fetch_page", lambda client, url: responses[url])
    monkeypatch.setattr(scanner, "check_exposed_files", lambda client, base_url: [])

    result = scanner.crawl_target(
        start_url,
        timeout_seconds=1.0,
        max_pages=5,
        max_crawl_depth=1,
        seed_robots=True,
        seed_sitemap=True,
    )

    assert "http://example.com/about" in result.scanned_urls
    assert "http://example.com/auth/login" in result.scanned_urls
    assert "http://example.com/" in result.scanned_urls


def test_crawl_target_aggregates_duplicate_findings(monkeypatch) -> None:
    start_url = "http://example.com/"
    login_url = "http://example.com/auth/login"
    responses = {
        start_url: make_response(
            start_url,
            '<html><body><a href="/auth/login">Login</a></body></html>',
            headers={
                "content-type": "text/html; charset=utf-8",
                "set-cookie": "session=abc; Path=/; SameSite=Lax",
                "server": "nginx/1.20.1",
            },
        ),
        login_url: make_response(
            login_url,
            "<html><body><p>Login page</p></body></html>",
            headers={
                "content-type": "text/html; charset=utf-8",
                "set-cookie": "session=def; Path=/; SameSite=Lax",
                "server": "nginx/1.20.1",
            },
        ),
    }

    monkeypatch.setattr(scanner, "build_client", lambda timeout_seconds: DummyClient())
    monkeypatch.setattr(scanner, "fetch_page", lambda client, url: responses[url])
    monkeypatch.setattr(scanner, "check_exposed_files", lambda client, base_url: [])

    result = scanner.crawl_target(start_url, timeout_seconds=1.0, max_pages=5, max_crawl_depth=2)

    server_info_findings = [finding for finding in result.findings if finding.category == "server_info"]
    cookie_findings = [finding for finding in result.findings if finding.category == "cookies"]

    assert len(server_info_findings) == 1
    assert server_info_findings[0].affected_urls == [start_url, login_url]
    assert len(cookie_findings) == 1
    assert cookie_findings[0].confidence == "high"
