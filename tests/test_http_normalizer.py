from app.http.normalizer import normalize_url, same_host


def test_normalize_url_removes_fragment_and_resolves_relative_path() -> None:
    assert normalize_url("https://example.com/app/page", "../login#section") == "https://example.com/login"


def test_same_host_detects_scope_changes_by_network_location() -> None:
    assert same_host("https://example.com", "https://example.com/path") is True
    assert same_host("https://example.com", "https://other.example.com") is False
