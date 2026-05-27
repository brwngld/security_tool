from __future__ import annotations

import pytest

from app.context import resolve_application_context, summarize_application_context


def test_resolve_application_context_discovers_nginx_target(workspace_temp_dir, monkeypatch) -> None:
    for key in ("APP_URL", "TARGET_URL", "BASE_URL"):
        monkeypatch.delenv(key, raising=False)

    nginx_config = workspace_temp_dir / "nginx.conf"
    nginx_config.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name autoentrytrack.test;\n"
        "    proxy_pass http://127.0.0.1:5000;\n"
        "}\n",
        encoding="utf-8",
    )

    context = resolve_application_context(None, workspace_temp_dir, None, require_target=True)

    assert context.target is not None
    assert context.target.source == "discovery"
    assert context.target.value == "http://127.0.0.1:5000"
    assert context.discovery.nginx_config == str(nginx_config)
    assert context.discovery.public_url == "https://autoentrytrack.test"


def test_resolve_application_context_prefers_systemd_env_file(workspace_temp_dir, monkeypatch) -> None:
    for key in ("APP_URL", "TARGET_URL", "BASE_URL"):
        monkeypatch.delenv(key, raising=False)

    app_root = workspace_temp_dir / "apps" / "AutoEntryTrack"
    app_root.mkdir(parents=True, exist_ok=True)
    app_env = app_root / ".env"
    app_env.write_text("APP_URL=http://127.0.0.1:5000\n", encoding="utf-8")

    project_env = workspace_temp_dir / ".env"
    project_env.write_text("APP_URL=http://127.0.0.1:9000\n", encoding="utf-8")

    systemd_dir = workspace_temp_dir / "systemd"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    (systemd_dir / "autoentrytrack.service").write_text(
        "[Service]\n"
        f"WorkingDirectory={app_root.as_posix()}\n"
        f"EnvironmentFile={app_env.as_posix()}\n"
        "ExecStart=/usr/bin/python app.py\n",
        encoding="utf-8",
    )

    context = resolve_application_context(None, workspace_temp_dir, None, require_target=True)

    assert context.target is not None
    assert context.target.source == str(app_env)
    assert context.target.value == "http://127.0.0.1:5000"
    assert context.discovery.env_file == str(app_env)
    assert context.discovery.env_source == "systemd EnvironmentFile"
    assert "env=systemd EnvironmentFile" in summarize_application_context(context)


def test_resolve_application_context_skips_discovery_for_explicit_url(workspace_temp_dir, monkeypatch) -> None:
    def fail_if_called(*args, **kwargs):  # pragma: no cover - guard rail
        raise AssertionError("discovery should not run when a URL is already provided")

    monkeypatch.setattr("app.context.discover_application_context", fail_if_called)

    context = resolve_application_context("https://example.com", workspace_temp_dir, None, require_target=True)

    assert context.target is not None
    assert context.target.source == "command line"
    assert context.target.value == "https://example.com"
