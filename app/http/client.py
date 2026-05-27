from __future__ import annotations

import httpx


def build_client(timeout_seconds: float = 10.0) -> httpx.Client:
    # Keep the client simple so request behavior stays easy to reason about.
    return httpx.Client(timeout=timeout_seconds, follow_redirects=True)


def fetch_page(client: httpx.Client, url: str) -> httpx.Response:
    # One GET is enough for this slice.
    return client.get(url, headers={"User-Agent": "Turan/0.1.0"})
