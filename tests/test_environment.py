from __future__ import annotations

import pytest

from app.environment import NO_SCAN_TARGET_MESSAGE, resolve_scan_target


def test_resolve_scan_target_uses_app_url_from_env_file(workspace_temp_dir, monkeypatch) -> None:
    env_file = workspace_temp_dir / "autoentrytrack.env"
    env_file.write_text("APP_URL=http://127.0.0.1:8000\n", encoding="utf-8")
    monkeypatch.chdir(workspace_temp_dir)

    resolved = resolve_scan_target(None, workspace_temp_dir, env_file)

    assert resolved.value == "http://127.0.0.1:8000"
    assert resolved.key == "APP_URL"
    assert resolved.source == str(env_file)


def test_resolve_scan_target_prefers_explicit_url(workspace_temp_dir, monkeypatch) -> None:
    env_file = workspace_temp_dir / "autoentrytrack.env"
    env_file.write_text("APP_URL=http://127.0.0.1:8000\n", encoding="utf-8")
    monkeypatch.chdir(workspace_temp_dir)

    resolved = resolve_scan_target("https://example.com", workspace_temp_dir, env_file)

    assert resolved.value == "https://example.com"
    assert resolved.source == "command line"


def test_resolve_scan_target_prefers_os_env_over_env_files(workspace_temp_dir, monkeypatch) -> None:
    env_file = workspace_temp_dir / "autoentrytrack.env"
    env_file.write_text("APP_URL=http://127.0.0.1:8000\n", encoding="utf-8")
    (workspace_temp_dir / ".env").write_text("APP_URL=http://127.0.0.1:9000\n", encoding="utf-8")
    monkeypatch.chdir(workspace_temp_dir)
    monkeypatch.setenv("APP_URL", "http://127.0.0.1:7000")

    resolved = resolve_scan_target(None, workspace_temp_dir, env_file)

    assert resolved.value == "http://127.0.0.1:7000"
    assert resolved.source == "environment"


def test_resolve_scan_target_uses_project_env_when_os_env_is_missing(workspace_temp_dir, monkeypatch) -> None:
    (workspace_temp_dir / ".env").write_text("APP_URL=http://127.0.0.1:9000\n", encoding="utf-8")
    monkeypatch.chdir(workspace_temp_dir)
    monkeypatch.delenv("APP_URL", raising=False)

    resolved = resolve_scan_target(None, workspace_temp_dir)

    assert resolved.value == "http://127.0.0.1:9000"
    assert resolved.source == str(workspace_temp_dir / ".env")


def test_resolve_scan_target_tells_you_how_to_fix_missing_target(workspace_temp_dir, monkeypatch) -> None:
    monkeypatch.chdir(workspace_temp_dir)

    with pytest.raises(ValueError, match="No scan target provided"):
        resolve_scan_target(None, workspace_temp_dir)

    with pytest.raises(ValueError) as excinfo:
        resolve_scan_target(None, workspace_temp_dir)

    assert str(excinfo.value) == NO_SCAN_TARGET_MESSAGE
    assert "Checked:" in NO_SCAN_TARGET_MESSAGE
    assert "- command line URL: not set" in NO_SCAN_TARGET_MESSAGE
    assert "- OS environment: not set" in NO_SCAN_TARGET_MESSAGE
    assert "- --env-file: not set" in NO_SCAN_TARGET_MESSAGE
    assert "- project .env: not set" in NO_SCAN_TARGET_MESSAGE
    assert "python -m app.main scan --env-file /path/to/autoentrytrack/.env" in NO_SCAN_TARGET_MESSAGE
