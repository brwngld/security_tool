from pathlib import Path
import subprocess

from rich.console import Console

from app import main
from app.config import AppConfig
from app.context import ApplicationContext, DiscoveryReport
from app.hardening.incident import apply_nginx_denylist, write_fail2ban_artifact
from app.incident import analyze_incident_sources, collect_live_incident_sources
from app.models import IncidentFinding, IncidentReport, LocalFixResult


def test_analyze_incident_sources_detects_blockable_ips(workspace_temp_dir) -> None:
    access_log = workspace_temp_dir / "access.log"
    access_log.write_text(
        '10.0.0.1 - - [27/May/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "sqlmap/1.6"\n'
        '10.0.0.1 - - [27/May/2026:10:00:01 +0000] "GET /admin HTTP/1.1" 403 0 "-" "sqlmap/1.6"\n'
        '192.0.2.5 - - [27/May/2026:10:00:02 +0000] "POST /login HTTP/1.1" 401 0 "-" "curl/8.0"\n',
        encoding="utf-8",
    )

    report = analyze_incident_sources([access_log], root=workspace_temp_dir, block_threshold=5)

    assert report.total_lines == 3
    assert report.blocked_ips == ["10.0.0.1", "192.0.2.5"]
    assert any(finding.category == "scanner" for finding in report.findings)
    assert any(finding.category == "auth" for finding in report.findings)
    assert any(finding.log_family in {"nginx-access", "auth"} for finding in report.findings)
    assert "Auto-block threshold reached" in report.notes[0]


def test_analyze_incident_sources_handles_apache_and_auth_logs(workspace_temp_dir) -> None:
    apache_error = workspace_temp_dir / "apache-error.log"
    apache_error.write_text(
        "[Tue May 27 10:00:00.000000 2026] [client 203.0.113.10] client denied by server configuration: /var/www/html/.env\n",
        encoding="utf-8",
    )
    auth_log = workspace_temp_dir / "auth.log"
    auth_log.write_text(
        "May 27 10:00:00 host sshd[1234]: Failed password for invalid user admin from 198.51.100.22 port 22 ssh2\n",
        encoding="utf-8",
    )

    report = analyze_incident_sources([apache_error, auth_log], root=workspace_temp_dir, block_threshold=3)

    families = {finding.log_family for finding in report.findings}
    assert "apache-error" in families
    assert "ssh" in families
    assert "203.0.113.10" in report.blocked_ips
    assert "198.51.100.22" in report.blocked_ips


def test_analyze_incident_sources_detects_service_and_admin_signals(workspace_temp_dir) -> None:
    service_log = workspace_temp_dir / "app.log"
    service_log.write_text(
        "May 27 10:00:00 host gunicorn[100]: Worker timeout (pid: 10)\n"
        "May 27 10:00:01 host uwsgi[101]: harakiri triggered on worker 4\n"
        "May 27 10:00:02 host app: django.security.csrf: CSRF token missing or incorrect.\n"
        "May 27 10:00:03 host sshd[102]: Failed password for invalid user admin from 198.51.100.77 port 22 ssh2\n"
        "May 27 10:00:04 host sudo: pam_unix(sudo:session): session opened for user root by alice(uid=1000)\n",
        encoding="utf-8",
    )

    report = analyze_incident_sources([service_log], root=workspace_temp_dir, block_threshold=4)

    families = {finding.log_family for finding in report.findings}
    categories = {finding.category for finding in report.findings}

    assert {"gunicorn", "uwsgi", "auth-middleware", "ssh", "sudo"}.issubset(families)
    assert "auth" in categories
    assert "service" in categories
    assert "198.51.100.77" in report.blocked_ips


def test_apply_nginx_denylist_backups_and_writes_include(workspace_temp_dir, monkeypatch) -> None:
    nginx_config = workspace_temp_dir / "nginx.conf"
    nginx_config.write_text("server {\n    listen 80;\n}\n", encoding="utf-8")

    def fake_run(command, capture_output, text, check):
        return subprocess.CompletedProcess(command, 0, stdout="syntax is ok\n", stderr="")

    monkeypatch.setattr("app.hardening.incident.subprocess.run", fake_run)

    result = apply_nginx_denylist(nginx_config, ["10.0.0.1", "10.0.0.1"])

    assert result.status == "applied"
    assert result.backup_path is not None
    assert Path(result.backup_path).exists()
    assert "include" in nginx_config.read_text(encoding="utf-8")
    denylist_path = nginx_config.with_name("incident-denylist.conf")
    assert denylist_path.exists()
    assert "deny 10.0.0.1;" in denylist_path.read_text(encoding="utf-8")


def test_write_fail2ban_artifact_includes_detected_patterns(workspace_temp_dir) -> None:
    report = IncidentReport(
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
                evidence={"user_agents": "sqlmap/1.6"},
                affected_ips=["10.0.0.1"],
                recommended_action="Block it.",
                block_action="deny 10.0.0.1;",
                count=3,
            )
        ],
        blocked_ips=["10.0.0.1"],
    )

    output_path = workspace_temp_dir / "incident-fail2ban.conf"
    write_fail2ban_artifact(report, output_path)

    text = output_path.read_text(encoding="utf-8")
    assert "[Definition]" in text
    assert "failregex" in text
    assert "sqlmap" in text
    assert "logpath =" in text


def test_collect_live_incident_sources_tails_a_file(workspace_temp_dir) -> None:
    tail_file = workspace_temp_dir / "live.log"
    tail_file.write_text(
        "line-1\nline-2\nline-3\nline-4\nline-5\n",
        encoding="utf-8",
    )

    snapshots, notes = collect_live_incident_sources(
        root=workspace_temp_dir,
        line_count=2,
        tail_files=[tail_file],
        output_dir=workspace_temp_dir / "outputs" / "incident-live",
    )

    assert len(snapshots) == 1
    assert snapshots[0].exists()
    text = snapshots[0].read_text(encoding="utf-8")
    assert "line-4" in text
    assert "line-5" in text
    assert any("Captured tail snapshot" in note for note in notes)


def test_collect_live_incident_sources_captures_windows_event_log_snapshot(workspace_temp_dir, monkeypatch) -> None:
    def fake_run(command, capture_output, text, check):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="Event 1\nSuspicious authentication failure\n",
            stderr="",
        )

    monkeypatch.setattr("app.incident.subprocess.run", fake_run)

    snapshots, notes = collect_live_incident_sources(
        root=workspace_temp_dir,
        line_count=5,
        event_log_names=["System"],
        output_dir=workspace_temp_dir / "outputs" / "incident-live",
    )

    assert len(snapshots) == 1
    assert snapshots[0].exists()
    text = snapshots[0].read_text(encoding="utf-8")
    assert "Suspicious authentication failure" in text
    assert any("Captured live Windows Event Log snapshot" in note for note in notes)


def test_incident_command_applies_containment(monkeypatch, workspace_temp_dir) -> None:
    access_log = workspace_temp_dir / "access.log"
    access_log.write_text(
        '10.0.0.1 - - [27/May/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "sqlmap/1.6"\n',
        encoding="utf-8",
    )
    nginx_config = workspace_temp_dir / "nginx.conf"
    nginx_config.write_text("server {\n    listen 80;\n}\n", encoding="utf-8")

    report = IncidentReport(
        context=ApplicationContext(
            root=str(workspace_temp_dir),
            discovery=DiscoveryReport(discovered=True, nginx_config=str(nginx_config)),
        ),
        target="http://127.0.0.1:8000",
        source_files=[str(access_log)],
        total_lines=1,
        findings=[],
        suspect_ips=["10.0.0.1"],
        blocked_ips=["10.0.0.1"],
        notes=["Auto-block threshold reached for: 10.0.0.1"],
    )

    recorded_console = Console(record=True, width=120)
    audit_events = []
    applied_calls = []

    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path=str(workspace_temp_dir / "audit.log")))
    monkeypatch.setattr(main, "resolve_application_context", lambda url, root, env_file, nginx_config=None, require_target=False: report.context)
    monkeypatch.setattr(main, "analyze_incident_sources", lambda sources, **kwargs: report)
    monkeypatch.setattr(
        main,
        "apply_nginx_denylist",
        lambda config_path, blocked_ips: applied_calls.append((Path(config_path), list(blocked_ips)))
        or LocalFixResult(
            target_path=str(config_path),
            status="applied",
            reason="Added a denylist include for 1 blocked IPs and the validation check passed.",
            backup_path=str(config_path.with_suffix(".conf.bak")),
            validation_command=f"nginx -t -c {config_path}",
            validation_output="syntax is ok",
            notes=["Reload the service when you are ready."],
        ),
    )
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: audit_events.append(event))

    main.incident(None, logs=access_log, nginx_config=nginx_config, apply_blocks=True, yes=True)

    text = recorded_console.export_text()
    assert "Incident Response" in text
    assert applied_calls == [(nginx_config, ["10.0.0.1"])]
    assert audit_events
    assert audit_events[0].action == "incident"
    assert audit_events[0].result == "contained"
    assert "Containment" in text


def test_incident_command_uses_live_tail_snapshots(monkeypatch, workspace_temp_dir) -> None:
    live_log = workspace_temp_dir / "live.log"
    live_log.write_text(
        '10.0.0.9 - - [27/May/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "sqlmap/1.6"\n',
        encoding="utf-8",
    )

    recorded_console = Console(record=True, width=120)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(audit_log_path=str(workspace_temp_dir / "audit.log")))
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: None)

    main.incident(None, live=True, tail_file=[live_log], yes=True)

    text = recorded_console.export_text()
    assert "Live capture:" in text
    assert "Incident Response" in text
    assert "10.0.0.9" in text
