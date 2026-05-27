from app.checks.exposed_files import check_exposed_files


class FakeResponse:
    def __init__(self, url: str, status_code: int) -> None:
        self.url = url
        self.status_code = status_code
        self.headers = {"content-type": "text/plain"}


class FakeClient:
    def get(self, url: str, headers=None):
        if url.endswith("/.env"):
            return FakeResponse(url, 200)
        return FakeResponse(url, 404)


def test_check_exposed_files_reports_reachable_sensitive_files() -> None:
    findings = check_exposed_files(FakeClient(), "https://example.com/")

    assert len(findings) == 1
    assert findings[0].title == "Exposed file: .env"
