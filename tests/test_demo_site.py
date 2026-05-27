from app.demo_site import demo_page


def test_demo_page_root_exposes_common_issues() -> None:
    status, headers, body = demo_page("/")

    assert status == 200
    assert headers["Server"] == "nginx/1.24.0"
    assert "Set-Cookie" in headers
    assert "/.env" in body


def test_demo_page_env_file_is_reachable() -> None:
    status, headers, body = demo_page("/.env")

    assert status == 200
    assert headers["Content-Type"].startswith("text/plain")
    assert "SECRET=demo" in body
