from app.probes.server_info import extract_server_banner


def test_extract_server_banner_prefers_server_header() -> None:
    headers = {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2"}

    assert extract_server_banner(headers) == "nginx/1.24.0"
