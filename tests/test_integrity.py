from pathlib import Path

from rich.console import Console

from app import main
from app.integrity import analyze_integrity_sources
from app.models import IntegrityFile, IntegrityReport
from app.reports.integrity_report import write_json_integrity_report


def test_analyze_integrity_sources_flags_changed_missing_and_new_files(workspace_temp_dir) -> None:
    app_dir = workspace_temp_dir / "app"
    startup_dir = workspace_temp_dir / "startup"
    app_dir.mkdir(parents=True, exist_ok=True)
    startup_dir.mkdir(parents=True, exist_ok=True)

    config_path = workspace_temp_dir / "nginx.conf"
    app_main = app_dir / "main.py"
    startup_script = startup_dir / "run.sh"
    webroot_file = workspace_temp_dir / "static" / "index.html"
    webroot_file.parent.mkdir(parents=True, exist_ok=True)

    config_path.write_text("server_tokens off;\n", encoding="utf-8")
    app_main.write_text('print("v1")\n', encoding="utf-8")
    startup_script.write_text("#!/bin/sh\necho v1\n", encoding="utf-8")
    webroot_file.write_text("<h1>v1</h1>\n", encoding="utf-8")

    baseline = analyze_integrity_sources(workspace_temp_dir)
    baseline_path = workspace_temp_dir / "baseline.json"
    write_json_integrity_report(baseline, baseline_path)

    config_path.unlink()
    app_main.write_text('print("v2")\n', encoding="utf-8")
    (startup_dir / "rotate.sh").write_text("#!/bin/sh\necho new\n", encoding="utf-8")

    report = analyze_integrity_sources(workspace_temp_dir, baseline_path=baseline_path)

    statuses = {file_item.status for file_item in report.files}
    titles = {finding.title for finding in report.findings}

    assert {"changed", "missing", "new"}.issubset(statuses)
    assert "Monitored file changed" in titles
    assert "Monitored file is missing" in titles
    assert "New monitored file appeared" in titles
    assert any("Integrity drift detected" in note for note in report.notes)


def test_integrity_command_renders_report_and_writes_outputs(monkeypatch, workspace_temp_dir) -> None:
    report = IntegrityReport(
        root=str(workspace_temp_dir),
        baseline_path=str(workspace_temp_dir / "baseline.json"),
        monitored_paths=[str(workspace_temp_dir / "app" / "main.py")],
        files=[
            IntegrityFile(
                path=str(workspace_temp_dir / "app" / "main.py"),
                category="config",
                kind="application",
                exists=True,
                status="changed",
                sha256="abc123",
                size=12,
                modified_at="2026-05-29T10:00:00+00:00",
            )
        ],
        findings=[],
        notes=["Compared against baseline."],
    )

    recorded_console = Console(record=True, width=120)
    output_calls: list[tuple[Path | None, Path | None, Path | None]] = []
    audit_events = []

    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "analyze_integrity_sources", lambda root, baseline_path=None, extra_paths=None: report)
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: audit_events.append((Path(path), event)))
    monkeypatch.setattr(main, "write_integrity_outputs", lambda report, json_output_path, markdown_output_path, html_output_path: output_calls.append((json_output_path, markdown_output_path, html_output_path)))

    main.integrity(
        workspace_temp_dir,
        baseline=workspace_temp_dir / "baseline.json",
        json_output=workspace_temp_dir / "outputs" / "integrity.json",
        markdown_output=workspace_temp_dir / "outputs" / "integrity.md",
        html_output=workspace_temp_dir / "outputs" / "integrity.html",
    )

    text = recorded_console.export_text()
    assert "File Integrity" in text
    assert output_calls
    assert audit_events
    assert audit_events[0][1].action == "integrity"


def test_integrity_command_forwards_notification_targets(monkeypatch, workspace_temp_dir) -> None:
    report = IntegrityReport(
        root=str(workspace_temp_dir),
        baseline_path=str(workspace_temp_dir / "baseline.json"),
        monitored_paths=[str(workspace_temp_dir / "app" / "main.py")],
        files=[],
        findings=[],
        notes=[],
    )

    recorded_console = Console(record=True, width=120)
    notification_calls = []
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "analyze_integrity_sources", lambda root, baseline_path=None, extra_paths=None: report)
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: None)
    monkeypatch.setattr(
        main,
        "send_notification_outputs",
        lambda report, **kwargs: notification_calls.append((report, kwargs)),
    )
    monkeypatch.setattr(main, "write_integrity_outputs", lambda *args, **kwargs: None)

    main.integrity(
        workspace_temp_dir,
        baseline=workspace_temp_dir / "baseline.json",
        webhook_url=["https://hooks.example/webhook"],
        slack_webhook_url=["https://hooks.example/slack"],
        discord_webhook_url=["https://hooks.example/discord"],
        email_to=["ops@example.com"],
        email_from="PsyberShield@example.com",
        smtp_host="smtp.example.com",
        smtp_username="PsyberShield",
        smtp_password_env="SMTP_PASSWORD",
    )

    assert notification_calls
    forwarded = notification_calls[0][1]
    assert forwarded["webhook_urls"] == ["https://hooks.example/webhook"]
    assert forwarded["slack_webhook_urls"] == ["https://hooks.example/slack"]
    assert forwarded["discord_webhook_urls"] == ["https://hooks.example/discord"]
    assert forwarded["email_recipients"] == ["ops@example.com"]
    assert forwarded["email_sender"] == "PsyberShield@example.com"

