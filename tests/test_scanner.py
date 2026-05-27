import app.scanner as scanner_module


class FakeHeaders(dict):
    def get_list(self, name: str) -> list[str]:
        if name.lower() == "set-cookie":
            return [
                "sessionid=abc123; Path=/; Secure; HttpOnly",
                "theme=dark; Path=/",
            ]
        return []


class FakeResponse:
    def __init__(self) -> None:
        self.url = "https://example.com/"
        self.status_code = 200
        self.headers = FakeHeaders({
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Server": "nginx/1.24.0",
            "CF-Ray": "abc123",
        })


class CsrfCookieHeaders(FakeHeaders):
    def get_list(self, name: str) -> list[str]:
        if name.lower() == "set-cookie":
            return ["csrf_token=abc123; Path=/; SameSite=Lax"]
        return []


class FakeClient:
    def __enter__(self) -> "FakeClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def get(self, url: str, headers=None):
        if url.endswith("/.env"):
            return type(
                "Response",
                (),
                {
                    "url": url,
                    "status_code": 200,
                    "headers": {"content-type": "text/plain"},
                },
            )()
        return type(
            "Response",
            (),
            {
                "url": url,
                "status_code": 404,
                "headers": {"content-type": "text/plain"},
            },
        )()


def test_scan_target_creates_findings_from_missing_headers(monkeypatch) -> None:
    monkeypatch.setattr(scanner_module, "build_client", lambda timeout_seconds=10.0: FakeClient())
    monkeypatch.setattr(scanner_module, "fetch_page", lambda client, url: FakeResponse())
    monkeypatch.setattr(scanner_module, "summarize_tls", lambda target, timeout_seconds=5.0: {"status": "ok", "days_left": "90"})

    result = scanner_module.scan_target("https://example.com")

    assert str(result.target.url) == "https://example.com/"
    assert len(result.findings) == 4
    assert result.findings[0].title == "Missing security header: x-content-type-options"
    assert result.findings[1].title == "Weak cookie flags"
    assert result.findings[2].title == "Server information disclosure"
    assert result.findings[3].title == "Exposed file: .env"
    assert result.fix_plans[0].finding_id == result.findings[0].id
    assert result.fix_plans[1].finding_id == result.findings[1].id
    assert result.fix_plans[2].finding_id == result.findings[2].id
    assert result.fix_plans[3].finding_id == result.findings[3].id
    assert result.waf_signals == ["cf-ray"]
    assert result.tls_summary["status"] == "ok"


def test_scan_target_passes_timeout_to_tls_and_http(monkeypatch) -> None:
    seen: dict[str, float] = {}

    def fake_build_client(timeout_seconds=10.0):
        seen["http_timeout"] = timeout_seconds
        return FakeClient()

    def fake_summarize_tls(target, timeout_seconds=5.0):
        seen["tls_timeout"] = timeout_seconds
        return {"status": "ok", "days_left": "90"}

    monkeypatch.setattr(scanner_module, "build_client", fake_build_client)
    monkeypatch.setattr(scanner_module, "fetch_page", lambda client, url: FakeResponse())
    monkeypatch.setattr(scanner_module, "summarize_tls", fake_summarize_tls)

    scanner_module.scan_target("https://example.com", timeout_seconds=3.5)

    assert seen["http_timeout"] == 3.5
    assert seen["tls_timeout"] == 3.5


def test_scan_target_builds_preview_fix_plans(monkeypatch) -> None:
    monkeypatch.setattr(scanner_module, "build_client", lambda timeout_seconds=10.0: FakeClient())
    monkeypatch.setattr(scanner_module, "fetch_page", lambda client, url: FakeResponse())
    monkeypatch.setattr(scanner_module, "summarize_tls", lambda target, timeout_seconds=5.0: {"status": "ok", "days_left": "90"})

    result = scanner_module.scan_target("https://example.com")

    assert result.fix_plans[0].expected_impact.startswith("Add")
    assert result.fix_plans[1].expected_impact == "Set Secure and HttpOnly where the cookie is issued first."


def test_scan_target_marks_csrf_cookie_findings_as_medium_confidence(monkeypatch) -> None:
    class CsrfResponse(FakeResponse):
        def __init__(self) -> None:
            super().__init__()
            self.headers = CsrfCookieHeaders({
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "Server": "nginx/1.24.0",
            })

    monkeypatch.setattr(scanner_module, "build_client", lambda timeout_seconds=10.0: FakeClient())
    monkeypatch.setattr(scanner_module, "fetch_page", lambda client, url: CsrfResponse())
    monkeypatch.setattr(scanner_module, "summarize_tls", lambda target, timeout_seconds=5.0: {"status": "ok", "days_left": "90"})

    result = scanner_module.scan_target("https://example.com")

    cookie_finding = next(finding for finding in result.findings if finding.category == "cookies")
    assert cookie_finding.confidence == "medium"
    assert "Review issuance location before applying." in cookie_finding.expected_impact
