from app.checks.headers import check_security_headers


def test_check_security_headers_reports_only_missing_headers() -> None:
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
    }
    assert check_security_headers(headers) == ["x-content-type-options"]
