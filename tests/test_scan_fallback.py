from __future__ import annotations

from rich.console import Console

from app import main
from app.config import AppConfig
from app.models import ScanResult, Target


def test_scan_command_uses_env_target_when_url_is_missing(monkeypatch, workspace_temp_dir) -> None:
    env_file = workspace_temp_dir / "autoentrytrack.env"
    env_file.write_text("APP_URL=http://127.0.0.1:8000\n", encoding="utf-8")

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.chdir(workspace_temp_dir)
    monkeypatch.setattr(
        main,
        "scan_target",
        lambda target_url, timeout_seconds=10.0: ScanResult(target=Target(url=target_url, scheme="http", host="127.0.0.1")),
    )
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig())

    main.scan(None, env_file=env_file)

    text = recorded_console.export_text()
    assert "Using APP_URL from" in text
    assert env_file.name in text
    assert "PsyberShield Scan" in text
