from app.probes.tls import summarize_tls


class FakeTlsSocket:
    def __init__(self) -> None:
        self._cert = {
            "notAfter": "Jan 30 12:00:00 2030 GMT",
            "subject": (("commonName", "example.com"),),
            "issuer": (("commonName", "Example CA"),),
        }

    def __enter__(self) -> "FakeTlsSocket":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def getpeercert(self):
        return self._cert

    def version(self):
        return "TLSv1.3"


class FakeRawSocket:
    def __enter__(self) -> "FakeRawSocket":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class FakeContext:
    def wrap_socket(self, raw_socket, server_hostname=None):
        return FakeTlsSocket()


def test_summarize_tls_reports_certificate_details(monkeypatch) -> None:
    monkeypatch.setattr("app.probes.tls.ssl.create_default_context", lambda: FakeContext())
    monkeypatch.setattr("app.probes.tls.socket.create_connection", lambda address, timeout=None: FakeRawSocket())

    result = summarize_tls("https://example.com")

    assert result["status"] == "ok"
    assert result["expires_on"] == "2030-01-30"
    assert result["tls_version"] == "TLSv1.3"
