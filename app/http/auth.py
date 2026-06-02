from __future__ import annotations

import asyncio
from dataclasses import dataclass
from http.cookies import SimpleCookie
import json
from pathlib import Path
from urllib.parse import urlparse

import httpx

from app.environment import lookup_env_value
from app.http.normalizer import normalize_url


@dataclass(slots=True)
class CrawlAuthConfig:
    login_url: str | None = None
    auth_method: str = "json"
    username: str | None = None
    password: str | None = None
    password_env: str | None = None
    env_file: str | None = None
    user_field: str = "identifier"
    pass_field: str = "password"
    cookie: str | None = None
    session_file: str | None = None
    save_session: bool = False
    storage_state: str | None = None
    save_storage_state: bool = False
    browser_username_selector: str | None = None
    browser_password_selector: str | None = None
    browser_submit_selector: str | None = None
    browser_headless: bool = True
    auth_check_url: str | None = None


def _parse_cookie_header(cookie_header: str) -> dict[str, str]:
    cookie = SimpleCookie()
    cookie.load(cookie_header)
    return {name: morsel.value for name, morsel in cookie.items()}


def _load_session_file(session_file: str) -> dict[str, str]:
    path = Path(session_file)
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    cookies = payload.get("cookies", {})
    if isinstance(cookies, dict):
        return {str(name): str(value) for name, value in cookies.items()}
    if isinstance(cookies, list):
        loaded: dict[str, str] = {}
        for item in cookies:
            if isinstance(item, dict) and item.get("name") and item.get("value") is not None:
                loaded[str(item["name"])] = str(item["value"])
        return loaded
    return {}


def _save_session_file(session_file: str, client: httpx.Client) -> None:
    path = Path(session_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"cookies": {name: value for name, value in client.cookies.items()}}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _load_storage_state_file(storage_state: str) -> dict[str, str]:
    path = Path(storage_state)
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    cookies = payload.get("cookies", {})
    if isinstance(cookies, dict):
        return {str(name): str(value) for name, value in cookies.items()}
    if isinstance(cookies, list):
        loaded: dict[str, str] = {}
        for item in cookies:
            if isinstance(item, dict) and item.get("name") and item.get("value") is not None:
                loaded[str(item["name"])] = str(item["value"])
        return loaded
    return {}


def _save_storage_state_file(storage_state: str, base_url: str, client: httpx.Client) -> None:
    path = Path(storage_state)
    path.parent.mkdir(parents=True, exist_ok=True)
    parsed_url = urlparse(base_url)
    domain = parsed_url.hostname or "localhost"
    secure = parsed_url.scheme == "https"
    cookies = [
        {
            "name": name,
            "value": value,
            "domain": domain,
            "path": "/",
            "expires": -1,
            "httpOnly": False,
            "secure": secure,
            "sameSite": "Lax",
        }
        for name, value in client.cookies.items()
    ]
    payload = {"cookies": cookies, "origins": []}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _cookie_map_to_playwright_cookies(cookie_map: dict[str, str], base_url: str) -> list[dict[str, object]]:
    parsed_url = urlparse(base_url)
    domain = parsed_url.hostname or "localhost"
    secure = parsed_url.scheme == "https"
    return [
        {
            "name": name,
            "value": value,
            "domain": domain,
            "path": "/",
            "expires": -1,
            "httpOnly": False,
            "secure": secure,
            "sameSite": "Lax",
        }
        for name, value in cookie_map.items()
    ]


def _build_cookie_map(config: CrawlAuthConfig) -> dict[str, str]:
    cookie_map: dict[str, str] = {}
    if config.session_file:
        cookie_map.update(_load_session_file(config.session_file))
    if config.storage_state:
        cookie_map.update(_load_storage_state_file(config.storage_state))
    if config.cookie:
        cookie_map.update(_parse_cookie_header(config.cookie))
    return cookie_map


def _resolve_password(config: CrawlAuthConfig) -> tuple[str | None, str | None]:
    if config.password:
        return config.password, "Browser auth: password provided directly."
    if config.password_env:
        env_file = Path(config.env_file) if config.env_file else None
        found = lookup_env_value(config.password_env, Path.cwd(), env_file)
        if found is not None:
            if found.source == "environment":
                return found.value, "Browser auth: password resolved from shell environment."
            return found.value, f"Browser auth: password resolved from env-file ({found.source})."
    return None, None


async def _authenticate_client_with_browser(
    client: httpx.Client,
    base_url: str,
    config: CrawlAuthConfig,
) -> list[str]:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise ValueError("Browser auth requires Playwright. Install it with `pip install .[browser]`.") from exc

    if not config.login_url and not config.storage_state:
        raise ValueError("Browser auth requires a login URL or a storage-state file.")

    login_url = normalize_url(base_url, config.login_url) if config.login_url else None
    check_url = normalize_url(base_url, config.auth_check_url) if config.auth_check_url else None
    password, password_note = _resolve_password(config)
    cookie_map = _build_cookie_map(config)
    notes: list[str] = ["Browser auth: started."]
    if password_note:
        notes.append(password_note)

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=config.browser_headless)
        try:
            context_kwargs: dict[str, object] = {}
            if config.storage_state and Path(config.storage_state).exists():
                context_kwargs["storage_state"] = config.storage_state
            context = await browser.new_context(**context_kwargs)
            try:
                if cookie_map:
                    await context.add_cookies(_cookie_map_to_playwright_cookies(cookie_map, base_url))
                    notes.append("Loaded cookies into the browser session.")
                if config.storage_state:
                    notes.append(f"Browser auth: storage-state preload from {config.storage_state}.")

                page = await context.new_page()
                if login_url:
                    await page.goto(login_url, wait_until="domcontentloaded")
                    if config.username and config.browser_username_selector:
                        await page.fill(config.browser_username_selector, config.username)
                    elif config.username:
                        await page.fill(f'input[name="{config.user_field}"]', config.username)
                    if password and config.browser_password_selector:
                        await page.fill(config.browser_password_selector, password)
                    elif password:
                        await page.fill(f'input[name="{config.pass_field}"]', password)
                    if config.username or password:
                        if config.browser_submit_selector:
                            await page.click(config.browser_submit_selector)
                        else:
                            await page.keyboard.press("Enter")
                    await page.wait_for_load_state("networkidle")
                    notes.append(f"Browser auth: login submitted at {login_url}.")
                elif config.storage_state:
                    notes.append(f"Browser auth: storage-state reused from {config.storage_state}.")

                if check_url:
                    response = await page.goto(check_url, wait_until="domcontentloaded")
                    if response is not None and response.status in {401, 403}:
                        failure_note = f"Browser auth: check failed at {check_url} with status {response.status}."
                        notes.append(failure_note)
                        raise ValueError(failure_note)
                    login_path = urlparse(login_url).path if login_url else ""
                    if login_path and urlparse(str(page.url)).path == login_path and page.url != check_url:
                        failure_note = f"Browser auth: check failed at {check_url} (redirected back to login)."
                        notes.append(failure_note)
                        raise ValueError(failure_note)
                    notes.append(f"Browser auth: check passed at {check_url}.")

                if config.save_storage_state and config.storage_state:
                    await context.storage_state(path=config.storage_state)
                    notes.append(f"Browser auth: storage-state saved to {config.storage_state}.")

                cookies = await context.cookies()
                client.cookies.update({cookie["name"]: cookie["value"] for cookie in cookies})
            finally:
                await context.close()
        finally:
            await browser.close()

    return notes


def authenticate_client(client: httpx.Client, base_url: str, config: CrawlAuthConfig | None) -> list[str]:
    if config is None:
        return []

    notes: list[str] = []
    cookie_map = _build_cookie_map(config)
    if config.session_file and _load_session_file(config.session_file):
        notes.append(f"Loaded session from {config.session_file}.")
    if config.storage_state and _load_storage_state_file(config.storage_state):
        notes.append(f"Loaded browser storage state from {config.storage_state}.")
    if config.cookie:
        cookie_values = _parse_cookie_header(config.cookie)
        if cookie_values:
            notes.append("Loaded auth cookie(s) into the crawl session.")
    if cookie_map:
        client.cookies.update(cookie_map)

    method = config.auth_method.strip().lower()
    if method == "browser":
        notes.extend(asyncio.run(_authenticate_client_with_browser(client, base_url, config)))
        if config.save_session and config.session_file:
            _save_session_file(config.session_file, client)
            notes.append(f"Saved session to {config.session_file}.")
        return notes

    if config.login_url:
        if not config.username:
            raise ValueError("Username is required for authenticated crawling.")
        password, _ = _resolve_password(config)
        if not password:
            raise ValueError("Password is required for authenticated crawling.")

        login_url = normalize_url(base_url, config.login_url)
        payload = {config.user_field: config.username, config.pass_field: password}
        if method == "json":
            response = client.post(login_url, json=payload, headers={"User-Agent": "PsyberShield/0.1.0"})
        elif method == "form":
            response = client.post(login_url, data=payload, headers={"User-Agent": "PsyberShield/0.1.0"})
        else:
            raise ValueError("Unsupported auth method. Use json or form.")

        if response.status_code >= 400:
            raise ValueError(f"Login failed with status {response.status_code}.")
        notes.append(f"Authenticated via {login_url}.")

    if config.auth_check_url:
        check_url = normalize_url(base_url, config.auth_check_url)
        response = client.get(check_url, headers={"User-Agent": "PsyberShield/0.1.0"})
        if response.status_code in {401, 403}:
            raise ValueError(f"Authenticated check failed at {check_url} with status {response.status_code}.")
        login_path = urlparse(normalize_url(base_url, config.login_url)).path if config.login_url else ""
        if login_path and urlparse(str(response.url)).path == login_path and response.history:
            raise ValueError(f"Authenticated check redirected back to the login page from {check_url}.")
        notes.append(f"Authenticated check passed at {check_url}.")

    if config.save_session and config.session_file:
        _save_session_file(config.session_file, client)
        notes.append(f"Saved session to {config.session_file}.")
    if config.save_storage_state and config.storage_state:
        _save_storage_state_file(config.storage_state, base_url, client)
        notes.append(f"Saved browser storage state to {config.storage_state}.")

    return notes

