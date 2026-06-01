from pathlib import Path

from rich.console import Console

from app import main
from app.audit import AuditEvent, append_audit_event
from app.models import IncidentFinding, IncidentReport
from app.timeline import load_timeline_report_from_path


def test_load_timeline_report_orders_log_finding_audit_and_containment(workspace_temp_dir) -> None:
    incident_report = IncidentReport(
        target="http://127.0.0.1:8000",
        source_files=[str(workspace_temp_dir / "access.log")],
        findings=[
            IncidentFinding(
                id="incident-scan-1",
                source_file=str(workspace_temp_dir / "access.log"),
                log_family="nginx-access",
                title="Suspicious probing",
                category="scanner",
                severity="high",
                confidence="high",
                description="Probing activity.",
                evidence={"first_seen": "2026-05-29T10:00:00+00:00", "last_seen": "2026-05-29T10:05:00+00:00"},
                affected_ips=["10.0.0.1"],
                recommended_action="Block it.",
                block_action="deny 10.0.0.1;",
                count=3,
            )
        ],
        blocked_ips=["10.0.0.1"],
        containment_applied=True,
        containment_target="nginx.conf",
        containment_artifact="incident-denylist.conf",
    )
    incident_path = workspace_temp_dir / "incident.json"
    incident_path.write_text(incident_report.model_dump_json(indent=2), encoding="utf-8")

    audit_log = workspace_temp_dir / "audit.log"
    append_audit_event(
        audit_log,
        AuditEvent(
            timestamp="2026-05-29T09:59:00+00:00",
            action="scan",
            target="http://127.0.0.1:8000",
            result="completed",
        ),
    )
    append_audit_event(
        audit_log,
        AuditEvent(
            timestamp="2026-05-29T10:06:00+00:00",
            action="incident",
            target="http://127.0.0.1:8000",
            result="contained",
            details={"containment_applied": True},
        ),
    )

    report = load_timeline_report_from_path(incident_path, audit_log)

    kinds = [event.kind for event in report.events]
    timestamps = [event.timestamp for event in report.events]

    assert kinds[0] == "audit"
    assert "log finding" in kinds
    assert "containment" in kinds
    assert timestamps == sorted(timestamps)


def test_timeline_command_renders_and_writes_outputs(monkeypatch, workspace_temp_dir) -> None:
    incident_report = IncidentReport(
        target="http://127.0.0.1:8000",
        source_files=[str(workspace_temp_dir / "access.log")],
        findings=[],
        blocked_ips=[],
        notes=["No active attack indicators were found."],
    )
    incident_path = workspace_temp_dir / "incident.json"
    incident_path.write_text(incident_report.model_dump_json(indent=2), encoding="utf-8")

    recorded_console = Console(record=True, width=120)
    output_calls = []
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "write_timeline_outputs", lambda report, json_output_path, markdown_output_path, html_output_path: output_calls.append((json_output_path, markdown_output_path, html_output_path)))

    main.timeline(
        incident_path,
        json_output=workspace_temp_dir / "outputs" / "timeline.json",
        markdown_output=workspace_temp_dir / "outputs" / "timeline.md",
        html_output=workspace_temp_dir / "outputs" / "timeline.html",
    )

    text = recorded_console.export_text()
    assert "Timeline" in text
    assert output_calls


def test_timeline_command_forwards_notification_targets(monkeypatch, workspace_temp_dir) -> None:
    incident_report = IncidentReport(
        target="http://127.0.0.1:8000",
        source_files=[str(workspace_temp_dir / "access.log")],
        findings=[],
        blocked_ips=[],
        notes=["No active attack indicators were found."],
    )
    incident_path = workspace_temp_dir / "incident.json"
    incident_path.write_text(incident_report.model_dump_json(indent=2), encoding="utf-8")

    recorded_console = Console(record=True, width=120)
    notification_calls = []
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(
        main,
        "send_notification_outputs",
        lambda report, **kwargs: notification_calls.append((report, kwargs)),
    )
    monkeypatch.setattr(main, "write_timeline_outputs", lambda *args, **kwargs: None)

    main.timeline(
        incident_path,
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

