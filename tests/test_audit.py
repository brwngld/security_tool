from app import main
from app.audit import append_audit_event, build_fix_audit_event, build_scan_audit_event, describe_audit_event
from app.config import AppConfig
from app.models import Finding, FixDecision, FixPlan, ScanResult, Target


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
                expected_impact="Report only.",
            )
        ],
        fix_plans=[
            FixPlan(
                finding_id="f1",
                fix_level=0,
                risk_level="low",
                rollback_command="Delete the note file.",
                expected_impact="Set Secure and HttpOnly where the cookie is issued first.",
            )
        ],
    )


def test_append_audit_event_writes_one_line(workspace_temp_dir) -> None:
    audit_path = workspace_temp_dir / "audit.log"
    append_audit_event(
        audit_path,
        build_scan_audit_event(build_scan_result(), 0, "scan"),
    )

    text = audit_path.read_text(encoding="utf-8")
    assert '"action": "scan"' in text
    assert '"target": "https://example.com/"' in text


def test_scan_writes_scan_and_fix_audit_events(monkeypatch, workspace_temp_dir) -> None:
    audit_path = workspace_temp_dir / "audit.log"
    result = build_scan_result()
    written_audit = []

    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path=str(audit_path)))
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: result)
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    monkeypatch.setattr(main, "render_fix_decisions", lambda decisions: "decisions")
    monkeypatch.setattr(main, "execute_fix", lambda finding, plan, policy, backup_path=None: "generated")
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: written_audit.append(event))

    main.scan("https://example.com", generate_fixes=True)

    assert [event.action for event in written_audit] == ["scan", "fix"]
    assert written_audit[1].result == "generated"
    assert written_audit[1].finding_id == "f1"


def test_scan_uses_cli_audit_log_path(monkeypatch, workspace_temp_dir) -> None:
    audit_path = workspace_temp_dir / "custom-audit.log"
    result = build_scan_result()
    written_paths = []

    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path="outputs/audit.log"))
    monkeypatch.setattr(main, "scan_target", lambda url, timeout_seconds: result)
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "console")
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: written_paths.append(path))

    main.scan("https://example.com", audit_log=audit_path)

    assert written_paths[0] == audit_path


def test_fix_audit_event_summary_mentions_backup_and_artifact() -> None:
    result = build_scan_result()
    finding = result.findings[0]
    plan = result.fix_plans[0]
    decision = FixDecision(
        finding_id=finding.id,
        finding_title=finding.title,
        status="ready",
        reason="Wrote a local hardening artifact and remediation note.",
        next_step=plan.expected_impact,
        rollback_command=plan.rollback_command,
        backup_path="outputs/backups/f1.conf.bak",
        artifact_path="outputs/generated/f1.conf",
    )

    event = build_fix_audit_event(finding, plan, decision, 0)

    summary = describe_audit_event(event)
    assert "backup=outputs/backups/f1.conf.bak" in summary
    assert "artifact=outputs/generated/f1.conf" in summary
    assert event.details["backup_path"] == "outputs/backups/f1.conf.bak"
    assert event.details["artifact_path"] == "outputs/generated/f1.conf"
