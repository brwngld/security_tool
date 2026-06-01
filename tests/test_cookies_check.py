from app.probes.cookies import check_cookie_flags


def test_check_cookie_flags_reports_headers_without_secure_or_httponly() -> None:
    headers = [
        "sessionid=abc123; Path=/; Secure; HttpOnly",
        "theme=dark; Path=/",
    ]

    assert check_cookie_flags(headers) == ["theme=dark; Path=/"]
