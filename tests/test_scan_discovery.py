from __future__ import annotations

from rich.console import Console

from app import main
from app.config import AppConfig
from app.models import ScanResult, Target


def test_scan_command_discovers_local_target_without_a_url(monkeypatch, workspace_temp_dir) -> None:
    nginx_config = workspace_temp_dir / "nginx.conf"
    nginx_config.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name autoentrytrack.test;\n"
        "    proxy_pass http://127.0.0.1:5000;\n"
        "}\n",
        encoding="utf-8",
    )

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

    main.scan(None)

    text = recorded_console.export_text()
    assert "No URL supplied. Discovery:" in text
    assert "Discovery:" in text
    assert "Application Context" in text
    assert "http://127.0.0.1:5000" in text
