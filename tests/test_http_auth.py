from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import httpx

from app.http.auth import CrawlAuthConfig, authenticate_client


def test_authenticate_client_logs_in_and_checks_protected_page() -> None:
    requests: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path, request.headers.get("cookie", "")))
        if request.method == "POST" and request.url.path == "/auth/login":
            payload = json.loads(request.content.decode("utf-8"))
            assert payload == {"identifier": "alice", "password": "secret"}
            return httpx.Response(
                200,
                json={"message": "ok"},
                headers={"set-cookie": "session_id=session-123; Path=/; HttpOnly"},
            )
        if request.method == "GET" and request.url.path == "/account":
            assert "session_id=session-123" in request.headers.get("cookie", "")
            return httpx.Response(200, text="ok")
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    notes = authenticate_client(
        client,
        "https://example.com",
        CrawlAuthConfig(
            login_url="/auth/login",
            auth_method="json",
            username="alice",
            password="secret",
            auth_check_url="/account",
        ),
    )

    assert any("Authenticated via" in note for note in notes)
    assert any("Authenticated check passed" in note for note in notes)
    assert client.cookies.get("session_id") == "session-123"
    assert requests == [
        ("POST", "/auth/login", ""),
        ("GET", "/account", "session_id=session-123"),
    ]


def test_authenticate_client_accepts_cookie_header() -> None:
    requests: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path, request.headers.get("cookie", "")))
        if request.method == "GET" and request.url.path == "/account":
            assert "session_id=session-123" in request.headers.get("cookie", "")
            assert "csrf_token=abc123" in request.headers.get("cookie", "")
            return httpx.Response(200, text="ok")
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    notes = authenticate_client(
        client,
        "https://example.com",
        CrawlAuthConfig(cookie="session_id=session-123; csrf_token=abc123", auth_check_url="/account"),
    )

    assert any("Loaded auth cookie" in note for note in notes)
    assert any("Authenticated check passed" in note for note in notes)
    assert requests == [("GET", "/account", "session_id=session-123; csrf_token=abc123")]


def test_authenticate_client_loads_and_saves_session_file(tmp_path: Path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"cookies": {"session_id": "from-file"}}), encoding="utf-8")

    requests: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path, request.headers.get("cookie", "")))
        if request.method == "GET" and request.url.path == "/account":
            assert "session_id=from-file" in request.headers.get("cookie", "")
            return httpx.Response(200, text="ok")
        return httpx.Response(200, json={"message": "ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    notes = authenticate_client(
        client,
        "https://example.com",
        CrawlAuthConfig(session_file=str(session_file), save_session=True, auth_check_url="/account"),
    )

    payload = json.loads(session_file.read_text(encoding="utf-8"))
    assert payload["cookies"]["session_id"] == "from-file"
    assert any("Loaded session from" in note for note in notes)
    assert any("Saved session to" in note for note in notes)
    assert any("Authenticated check passed" in note for note in notes)
    assert requests == [("GET", "/account", "session_id=from-file")]


def test_authenticate_client_loads_and_saves_storage_state(tmp_path: Path) -> None:
    storage_state = tmp_path / "storage_state.json"
    storage_state.write_text(
        json.dumps(
            {
                "cookies": [
                    {
                        "name": "session_id",
                        "value": "from-storage",
                        "domain": "example.com",
                        "path": "/",
                        "expires": -1,
                        "httpOnly": True,
                        "secure": True,
                        "sameSite": "Lax",
                    }
                ],
                "origins": [],
            }
        ),
        encoding="utf-8",
    )

    requests: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path, request.headers.get("cookie", "")))
        if request.method == "GET" and request.url.path == "/account":
            assert "session_id=from-storage" in request.headers.get("cookie", "")
            return httpx.Response(200, text="ok")
        return httpx.Response(200, json={"message": "ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    notes = authenticate_client(
        client,
        "https://example.com",
        CrawlAuthConfig(storage_state=str(storage_state), save_storage_state=True, auth_check_url="/account"),
    )

    payload = json.loads(storage_state.read_text(encoding="utf-8"))
    assert payload["cookies"][0]["name"] == "session_id"
    assert payload["cookies"][0]["value"] == "from-storage"
    assert payload["cookies"][0]["domain"] == "example.com"
    assert any("Loaded browser storage state from" in note for note in notes)
    assert any("Saved browser storage state to" in note for note in notes)
    assert any("Authenticated check passed" in note for note in notes)
    assert requests == [("GET", "/account", "session_id=from-storage")]


def test_authenticate_client_uses_browser_auth_and_saves_storage_state(tmp_path: Path, monkeypatch) -> None:
    storage_state = tmp_path / "browser_state.json"
    storage_state.write_text(
        json.dumps(
            {
                "cookies": [
                    {
                        "name": "session_id",
                        "value": "from-state",
                        "domain": "example.com",
                        "path": "/",
                        "expires": -1,
                        "httpOnly": False,
                        "secure": True,
                        "sameSite": "Lax",
                    }
                ],
                "origins": [],
            }
        ),
        encoding="utf-8",
    )

    class FakeResponse:
        def __init__(self, status: int = 200) -> None:
            self.status = status

    class FakePage:
        def __init__(self, context: "FakeContext") -> None:
            self._context = context
            self.url = ""
            self.keyboard = self

        async def goto(self, url: str, wait_until: str = "domcontentloaded") -> FakeResponse:  # noqa: ARG002
            self.url = url
            return FakeResponse(200)

        async def fill(self, selector: str, value: str) -> None:
            self._context.filled.append((selector, value))

        async def click(self, selector: str) -> None:
            self._context.clicked.append(selector)
            self._context.cookies_data["session_id"] = "browser-session"

        async def wait_for_load_state(self, state: str) -> None:  # noqa: ARG002
            return None

        async def press(self, key: str) -> None:
            self._context.keys.append(key)

    class FakeContext:
        def __init__(self, storage_state_path: str | None = None) -> None:
            self.cookies_data: dict[str, str] = {}
            self.filled: list[tuple[str, str]] = []
            self.clicked: list[str] = []
            self.keys: list[str] = []
            self.saved_state_path: str | None = None
            if storage_state_path:
                payload = json.loads(Path(storage_state_path).read_text(encoding="utf-8"))
                for cookie in payload.get("cookies", []):
                    self.cookies_data[str(cookie["name"])] = str(cookie["value"])

        async def add_cookies(self, cookies: list[dict[str, object]]) -> None:
            for cookie in cookies:
                self.cookies_data[str(cookie["name"])] = str(cookie["value"])

        async def new_page(self) -> FakePage:
            return FakePage(self)

        async def cookies(self) -> list[dict[str, object]]:
            return [
                {
                    "name": name,
                    "value": value,
                    "domain": "example.com",
                    "path": "/",
                    "expires": -1,
                    "httpOnly": False,
                    "secure": True,
                    "sameSite": "Lax",
                }
                for name, value in self.cookies_data.items()
            ]

        async def storage_state(self, path: str | None = None) -> dict[str, object]:
            payload = {
                "cookies": [
                    {
                        "name": name,
                        "value": value,
                        "domain": "example.com",
                        "path": "/",
                        "expires": -1,
                        "httpOnly": False,
                        "secure": True,
                        "sameSite": "Lax",
                    }
                    for name, value in self.cookies_data.items()
                ],
                "origins": [],
            }
            if path is not None:
                self.saved_state_path = path
                Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return payload

        async def close(self) -> None:
            return None

    class FakeBrowser:
        def __init__(self) -> None:
            self.contexts: list[FakeContext] = []

        async def new_context(self, storage_state: str | None = None) -> FakeContext:
            context = FakeContext(storage_state)
            self.contexts.append(context)
            return context

        async def close(self) -> None:
            return None

    class FakeChromium:
        def __init__(self) -> None:
            self.browser = FakeBrowser()

        async def launch(self, headless: bool = True) -> FakeBrowser:  # noqa: ARG002
            return self.browser

    class FakeAsyncPlaywright:
        def __init__(self) -> None:
            self.chromium = FakeChromium()

        async def __aenter__(self) -> "FakeAsyncPlaywright":
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            return None

    def async_playwright() -> FakeAsyncPlaywright:
        return FakeAsyncPlaywright()

    fake_async_api = types.ModuleType("playwright.async_api")
    fake_async_api.async_playwright = async_playwright
    fake_playwright = types.ModuleType("playwright")
    monkeypatch.setitem(sys.modules, "playwright", fake_playwright)
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_async_api)

    requests: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path, request.headers.get("cookie", "")))
        if request.method == "GET" and request.url.path == "/account":
            assert "session_id=browser-session" in request.headers.get("cookie", "")
            return httpx.Response(200, text="ok")
        raise AssertionError(f"Unexpected request: {request.method} {request.url.path}")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    notes = authenticate_client(
        client,
        "https://example.com",
        CrawlAuthConfig(
            login_url="/auth/login",
            auth_method="browser",
            username="alice",
            password="secret",
            browser_username_selector='input[name="identifier"]',
            browser_password_selector='input[name="password"]',
            browser_submit_selector='button[type="submit"]',
            storage_state=str(storage_state),
            save_storage_state=True,
            auth_check_url="/account",
        ),
    )

    payload = json.loads(storage_state.read_text(encoding="utf-8"))
    assert payload["cookies"][0]["name"] == "session_id"
    assert payload["cookies"][0]["value"] == "browser-session"
    assert any("Authenticated via browser" in note for note in notes)
    assert any("Loaded browser storage state from" in note for note in notes)
    assert any("Authenticated check passed" in note for note in notes)
    assert any("Saved browser storage state to" in note for note in notes)
    assert client.cookies.get("session_id") == "browser-session"
    assert requests == []
