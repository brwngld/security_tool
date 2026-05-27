import json

from rich.console import Console

from app import main
from app.audit import append_audit_event, build_scan_audit_event
from app.config import AppConfig
from app.models import Finding, ScanResult, Target


def build_scan_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        findings=[
            Finding(
                id="f1",
                target_url="https://example.com",
                title="Weak cookie flags",
                description="A cookie is missing Secure or HttpOnly.",
                severity="low",
                category="cookies",
                fix_level=0,
                risk_level="low",
            )
        ],
    )


def test_audit_command_shows_matching_events(workspace_temp_dir, monkeypatch) -> None:
    audit_path = workspace_temp_dir / "audit.log"
    append_audit_event(audit_path, build_scan_audit_event(build_scan_result(), 0, "scan"))
    append_audit_event(
        audit_path,
        build_scan_audit_event(build_scan_result(), 0, "baseline"),
    )

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path=str(audit_path)))

    main.audit(event="scan")

    text = recorded_console.export_text()
    assert "Audit Log" in text
    assert "scan" in text
    assert "baseline" not in text
    assert "Read audit log from" in text


def test_audit_command_accepts_the_log_file_alias(workspace_temp_dir, monkeypatch) -> None:
    audit_path = workspace_temp_dir / "audit.log"
    append_audit_event(audit_path, build_scan_audit_event(build_scan_result(), 0, "scan"))

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path=str(audit_path)))

    main.audit(log_file=audit_path)

    text = recorded_console.export_text()
    assert "Audit Log" in text
    assert "scan" in text


def test_audit_command_writes_json_output(workspace_temp_dir, monkeypatch) -> None:
    audit_path = workspace_temp_dir / "audit.log"
    json_output = workspace_temp_dir / "audit.json"
    append_audit_event(audit_path, build_scan_audit_event(build_scan_result(), 0, "scan"))

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path=str(audit_path)))

    main.audit(json_output=json_output)

    text = recorded_console.export_text()
    assert "Wrote audit JSON to" in text
    assert json_output.exists()
    payload = json.loads(json_output.read_text(encoding="utf-8"))
    assert len(payload) == 1
    assert payload[0]["action"] == "scan"
    assert payload[0]["target"] == "https://example.com/"
