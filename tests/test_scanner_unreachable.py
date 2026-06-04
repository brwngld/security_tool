import httpx

import app.engine as scanner_module


class FailingClient:
    def __enter__(self) -> "FailingClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def test_scan_target_handles_request_failure(monkeypatch) -> None:
    monkeypatch.setattr(scanner_module, "build_client", lambda timeout_seconds=10.0: FailingClient())
    monkeypatch.setattr(scanner_module, "fetch_page", lambda client, url: (_ for _ in ()).throw(httpx.ConnectError("boom")))
    monkeypatch.setattr(scanner_module, "summarize_tls", lambda target, timeout_seconds=5.0: {"status": "ok", "days_left": "90"})

    result = scanner_module.scan_target("https://example.com")

    assert result.scan_confidence == 0.0
    assert result.findings[0].title == "Target unreachable"
