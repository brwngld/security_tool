from __future__ import annotations

import subprocess

from rich.console import Console

from app import main
from app.context import ApplicationContext
from app.doctor import DoctorCheck, DoctorReport, run_doctor_checks, run_server_checks
from app.environment import ResolvedScanTarget
from app.models import ScanResult, Target
from app.reports.console import render_doctor_report


def test_process_and_port_activity_flags_public_listener_and_outbound_connection(monkeypatch) -> None:
    netstat_output = (
        "  TCP    0.0.0.0:8080     0.0.0.0:0      LISTENING       4242\n"
        "  TCP    10.0.0.10:49160  93.184.216.34:443  ESTABLISHED     4242\n"
        "  UDP    127.0.0.1:68     *:*                                    512\n"
    )

    monkeypatch.setattr("app.doctor.platform.system", lambda: "Windows")
    monkeypatch.setattr("app.doctor.which", lambda command: "C:\\Windows\\System32\\netstat.exe" if command == "netstat" else None)
    monkeypatch.setattr(
        "app.doctor.subprocess.run",
        lambda command, capture_output, text, check: subprocess.CompletedProcess(command, 0, stdout=netstat_output, stderr=""),
    )

    from app.doctor import check_process_and_port_activity

    check = check_process_and_port_activity()

    assert check.name == "Process and port activity"
    assert check.status == "warn"
    assert "suspicious listener" in check.summary
    assert "listeners" in check.details
    assert "outbound" in check.details


def test_doctor_checks_flag_local_settings(workspace_temp_dir) -> None:
    env_file = workspace_temp_dir / "autoentrytrack.env"
    env_file.write_text(
        "APP_URL=http://127.0.0.1:8000\n"
        "DEBUG=True\n"
        "SECRET_KEY=short\n"
        "DATABASE_URL=postgres://db\n"
        "SMTP_PASSWORD=supersecret\n",
        encoding="utf-8",
    )
    (workspace_temp_dir / "policy.json").write_text("{}", encoding="utf-8")
    (workspace_temp_dir / "app").mkdir(parents=True, exist_ok=True)
    (workspace_temp_dir / "app" / "config.py").write_text("# app config\n", encoding="utf-8")
    (workspace_temp_dir / "nginx.conf").write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_tokens on;\n"
        "}\n",
        encoding="utf-8",
    )

    report = run_doctor_checks(root=workspace_temp_dir, env_file=env_file, port_candidates=[65500])
    checks = {check.name: check for check in report.checks}

    assert report.context is not None
    assert report.context.target is not None
    assert checks[".env"].status == "ok"
    assert checks["Scan target"].status == "ok"
    assert checks["Output folder"].status == "ok"
    assert checks["App config paths"].status == "ok"
    assert checks["Nginx config paths"].status == "ok"
    assert checks["Nginx hardening"].status == "warn"
    assert checks["Deployment profile"].status == "info"
    assert "likely" in checks["Deployment profile"].summary
    assert checks["Process and port activity"].status == "warn"
    assert checks["Open local ports"].status == "info"
    assert checks["DEBUG"].status == "warn"
    assert checks["SECRET_KEY"].status == "warn"
    assert checks["SERVER_NAME"].status == "warn"
    assert checks["DATABASE_URL"].status == "ok"
    assert checks["SMTP_PASSWORD"].status == "ok"
    assert report.readiness_score is not None
    assert report.readiness_score < 100
    assert report.readiness_state in {"warning", "danger"}
    assert report.readiness_notes
    assert any("Main drag from warnings" in note for note in report.readiness_notes)


def test_server_checks_focus_on_server_signals(workspace_temp_dir) -> None:
    env_file = workspace_temp_dir / "autoentrytrack.env"
    env_file.write_text("DEBUG=True\nSECRET_KEY=short\n", encoding="utf-8")
    nginx_config = workspace_temp_dir / "nginx.conf"
    nginx_config.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_tokens on;\n"
        "}\n",
        encoding="utf-8",
    )
    (workspace_temp_dir / "app").mkdir(parents=True, exist_ok=True)
    (workspace_temp_dir / "app" / "config.py").write_text("# app config\n", encoding="utf-8")

    report = run_server_checks(root=workspace_temp_dir, env_file=env_file, nginx_config=nginx_config, port_candidates=[65500])
    names = {check.name for check in report.checks}

    assert report.context is not None
    assert "DEBUG" not in names
    assert "SECRET_KEY" not in names
    assert ".env" in names
    assert "Deployment profile" in names
    assert "Output folder" in names
    assert "App config paths" in names
    assert "Process and port activity" in names
    assert "Open local ports" in names


def test_doctor_command_prints_safe_statuses(monkeypatch, workspace_temp_dir) -> None:
    report = DoctorReport(
        root=str(workspace_temp_dir),
        os_name="Windows",
        os_release="11",
        python_version="3.14.0",
        readiness_score=88,
        readiness_state="warning",
        readiness_notes=["Readiness score is a weighted average across 2 check(s).", "Main drag from warnings: DEBUG."],
        checks=[
            DoctorCheck(name="SECRET_KEY", status="ok", summary="present", details={"source": ".env"}),
            DoctorCheck(name="DEBUG", status="warn", summary="enabled", details={"source": ".env"}),
        ],
    )

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "run_doctor_checks", lambda env_file=None: report)

    main.doctor(env_file=workspace_temp_dir / "autoentrytrack.env")

    text = recorded_console.export_text()
    assert "Doctor" in text
    assert "SECRET_KEY" in text
    assert "present" in text
    assert "supersecret" not in text
    assert "Readiness state" in text
    assert "WARNING" in text
    assert "Readiness score" in text
    assert "weighted average" in text
    assert "Main drag from warnings" in text


def test_doctor_command_writes_html_output(monkeypatch, workspace_temp_dir) -> None:
    report = DoctorReport(
        root=str(workspace_temp_dir),
        os_name="Windows",
        os_release="11",
        python_version="3.14.0",
        readiness_score=88,
        readiness_state="ready",
        readiness_notes=["Readiness score is a weighted average across 1 check(s)."],
        checks=[DoctorCheck(name="SECRET_KEY", status="ok", summary="present", details={"source": ".env"})],
    )

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "run_doctor_checks", lambda env_file=None: report)

    output_path = workspace_temp_dir / "outputs" / "doctor.html"
    main.doctor(env_file=workspace_temp_dir / "autoentrytrack.env", html_output=output_path)

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "PsyberShield Doctor Report" in text
    assert "Readiness state" in text
    assert "Readiness score" in text
    assert "weighted average" in text


def test_render_doctor_report_shows_readiness_score() -> None:
    report = DoctorReport(
        root="C:/workspace",
        os_name="Windows",
        os_release="11",
        python_version="3.14.0",
        readiness_score=88,
        readiness_state="ready",
        readiness_notes=["Readiness score is a weighted average across 1 check(s)."],
        checks=[DoctorCheck(name="SECRET_KEY", status="ok", summary="present", details={"source": ".env"})],
    )

    console = Console(record=True, width=100)
    console.print(render_doctor_report(report))
    text = console.export_text()

    assert "Readiness score" in text
    assert "Readiness state" in text
    assert "88%" in text
    assert "weighted average" in text


def test_server_check_command_uses_server_view(monkeypatch, workspace_temp_dir) -> None:
    report = DoctorReport(
        root=str(workspace_temp_dir),
        os_name="Windows",
        os_release="11",
        python_version="3.14.0",
        checks=[
            DoctorCheck(name="App config paths", status="ok", summary="found", details={"paths": "app/config.py"}),
            DoctorCheck(name="Open local ports", status="info", summary="none found", details={}),
        ],
    )

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "run_server_checks", lambda env_file=None, nginx_config=None: report)
    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)

    main.server_check(env_file=workspace_temp_dir / "autoentrytrack.env", nginx_config=workspace_temp_dir / "nginx.conf")

    text = recorded_console.export_text()
    assert "Server" not in text
    assert "App config paths" in text
    assert "Open local ports" in text


def test_server_check_command_scans_the_discovered_target(monkeypatch, workspace_temp_dir) -> None:
    report = DoctorReport(
        root=str(workspace_temp_dir),
        os_name="Windows",
        os_release="11",
        python_version="3.14.0",
        context=ApplicationContext(
            root=str(workspace_temp_dir),
            target=ResolvedScanTarget(value="http://127.0.0.1:5000", source="discovery", key="discovered"),
        ),
        checks=[
            DoctorCheck(name="App config paths", status="ok", summary="found", details={"paths": "app/config.py"}),
        ],
    )

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "run_server_checks", lambda env_file=None, nginx_config=None: report)
    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.setattr(
        main,
        "scan_target",
        lambda target_url, timeout_seconds=10.0: ScanResult(target=Target(url=target_url, scheme="http", host="127.0.0.1")),
    )

    main.server_check(env_file=workspace_temp_dir / "autoentrytrack.env", nginx_config=workspace_temp_dir / "nginx.conf")

    text = recorded_console.export_text()
    assert "Discovery:" in text
    assert "Scanning discovered target:" in text
    assert "http://127.0.0.1:5000" in text
