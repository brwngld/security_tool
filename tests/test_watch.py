from pathlib import Path

from rich.console import Console

from app import main
from app.audit import describe_audit_event
from app.config import AppConfig
from app.context import ApplicationContext, DiscoveryReport
from app.diagnostics import DoctorCheck
from app.models import IncidentFinding, IncidentReport, IntegrityFinding, IntegrityReport, WatchFinding, WatchObservation, WatchReport
from app.watch import build_watch_report


def _build_incident_report() -> IncidentReport:
    return IncidentReport(
        source_files=["access.log"],
        total_lines=12,
        findings=[
            IncidentFinding(
                id="incident-scan-1",
                source_file="access.log",
                log_family="nginx-access",
                title="Suspicious probing",
                category="scanner",
                severity="high",
                confidence="high",
                description="Reconnaissance traffic was detected.",
                evidence={"score": 8},
                affected_ips=["10.0.0.1"],
                recommended_action="Add the IP to the denylist and inspect the upstream logs.",
                block_action="deny 10.0.0.1;",
                count=4,
            )
        ],
        suspect_ips=["10.0.0.1"],
        blocked_ips=["10.0.0.1"],
        notes=["Auto-block threshold reached for 10.0.0.1."],
    )


def _build_integrity_report() -> IntegrityReport:
    return IntegrityReport(
        root=".",
        baseline_path="baseline.json",
        monitored_paths=["app/main.py"],
        files=[],
        findings=[
            IntegrityFinding(
                id="integrity-changed-1",
                path="app/main.py",
                category="config",
                kind="application",
                severity="medium",
                confidence="high",
                title="Monitored file changed",
                description="The file hash or size differs from the baseline snapshot.",
                evidence={"path": "app/main.py"},
                recommended_action="Review the diff and restore from backup if it was not authorized.",
            )
        ],
        notes=["Compared against baseline baseline.json"],
    )


def test_build_watch_report_combines_sources_and_sets_response_label() -> None:
    report = build_watch_report(
        root=Path("."),
        context=ApplicationContext(root=".", discovery=DiscoveryReport(discovered=True, notes=["discovery note"])),
        mode="snapshot",
        interval_seconds=30.0,
        policy_path=Path("policy.json"),
        baseline_path=Path("baseline.json"),
        source_paths=[Path("access.log"), Path("app/main.py")],
        incident_report=_build_incident_report(),
        integrity_report=_build_integrity_report(),
        process_check=DoctorCheck(
            name="Process and port activity",
            status="warn",
            summary="1 suspicious listener(s)",
            details={"listeners": "0.0.0.0:8080", "outbound": "none", "processes": "gunicorn"},
        ),
        local_ports_check=DoctorCheck(
            name="Open local ports",
            status="info",
            summary="listening on localhost: 8000",
            details={"ports": "8000"},
        ),
        live_notes=["Captured live journalctl snapshot for nginx"],
        extra_notes=["Policy file loaded from policy.json"],
    )

    assert report.risk_level == "high"
    assert report.response_label == "recommend contain"
    assert report.risk_score > 0
    assert report.baseline_path == "baseline.json"
    assert any(finding.source == "incident" for finding in report.findings)
    assert any(finding.evidence.get("affected_ips") == "10.0.0.1" for finding in report.findings)
    assert any(finding.source == "integrity" for finding in report.findings)
    assert any(finding.source == "doctor" for finding in report.findings)
    assert any(observation.source == "capture" for observation in report.observations)
    assert any("Containment candidates identified" in note for note in report.notes)


def test_watch_command_repeats_in_follow_mode(monkeypatch, workspace_temp_dir) -> None:
    report = WatchReport(
        root=str(workspace_temp_dir),
        mode="follow",
        interval_seconds=1.0,
        observations=[
            WatchObservation(
                source="incident",
                kind="log analysis",
                status="ok",
                summary="No suspicious activity detected.",
                details={},
            )
        ],
        findings=[],
        notes=["No suspicious activity detected."],
    )

    recorded_console = Console(record=True, width=120)
    audit_events = []
    output_calls = []
    reports = [report, report.model_copy(update={"cycles": 2})]

    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path=str(workspace_temp_dir / "audit.log")))
    monkeypatch.setattr(main, "resolve_application_context", lambda url, root, env_file, nginx_config=None, require_target=False: ApplicationContext(root=str(workspace_temp_dir), discovery=DiscoveryReport()))
    monkeypatch.setattr(main, "run_watch_snapshot", lambda **kwargs: reports.pop(0))
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: audit_events.append((Path(path), event)))
    monkeypatch.setattr(main, "write_watch_outputs", lambda report, json_output_path, markdown_output_path, html_output_path: output_calls.append((json_output_path, markdown_output_path, html_output_path, report.cycles)))

    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    main.watch(
        workspace_temp_dir,
        follow=True,
        interval=1.0,
        max_cycles=2,
        audit_log=workspace_temp_dir / "outputs" / "watch-audit.log",
    )

    text = recorded_console.export_text()
    assert "Watch cycle 1 starting" in text
    assert "Watch max cycles reached (2); stopping." in text
    assert len(audit_events) == 2
    assert len(output_calls) == 2
    assert output_calls[0][3] == 1
    assert output_calls[1][3] == 2
    assert audit_events[0][1].action == "watch"
    assert audit_events[0][1].result == "log only"


def test_watch_command_compact_mode_shows_top_actions(monkeypatch, workspace_temp_dir) -> None:
    report = WatchReport(
        root=str(workspace_temp_dir),
        mode="snapshot",
        interval_seconds=1.0,
        compact=True,
        risk_level="high",
        response_label="recommend contain",
        observations=[],
        findings=[
            WatchFinding(
                id="watch-1",
                source="incident",
                category="scanner",
                severity="high",
                title="Repeated probing detected",
                description="A burst of suspicious requests was recorded.",
                evidence={"ip": "10.0.0.5"},
                recommended_action="Review the source IP and consider a denylist entry.",
                response_label="recommend contain",
            )
        ],
        notes=["Suspicious activity captured."],
    )

    recorded_console = Console(record=True, width=120)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path=str(workspace_temp_dir / "audit.log")))
    monkeypatch.setattr(main, "resolve_application_context", lambda url, root, env_file, nginx_config=None, require_target=False: ApplicationContext(root=str(workspace_temp_dir), discovery=DiscoveryReport()))
    monkeypatch.setattr(main, "run_watch_snapshot", lambda **kwargs: report)
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: None)
    monkeypatch.setattr(main, "write_watch_outputs", lambda *args, **kwargs: None)
    main.watch(
        workspace_temp_dir,
        compact=True,
        audit_log=workspace_temp_dir / "outputs" / "watch-audit.log",
    )

    text = recorded_console.export_text()
    assert "Watch Status" in text
    assert "Top Risks" in text
    assert "Recommended Next Actions" in text


def test_watch_audit_summary_mentions_risk_and_response() -> None:
    report = WatchReport(
        root=".",
        mode="snapshot",
        risk_level="high",
        response_label="recommend contain",
        findings=[],
        observations=[],
    )

    event = main.build_watch_audit_event(report, 0)
    summary = describe_audit_event(event)

    assert "risk=high" in summary
    assert "response=recommend contain" in summary
