from __future__ import annotations

import subprocess
from pathlib import Path

from rich.console import Console

from app import main
from app.config import AppConfig
from app.context import ApplicationContext, DiscoveryReport
from app.environment import ResolvedScanTarget
from app.hardening.local_fixes import apply_local_nginx_banner_fix, apply_local_nginx_hardening_fix, choose_local_fix_target
from app.models import Finding, FixPlan, LocalFixResult, ScanResult, Target


def test_choose_local_fix_target_prefers_the_server_banner_finding(workspace_temp_dir) -> None:
    nginx_config = workspace_temp_dir / "nginx.conf"
    nginx_config.write_text("server {\n    listen 80;\n}\n", encoding="utf-8")

    context = ApplicationContext(
        root=str(workspace_temp_dir),
        target=ResolvedScanTarget(value="http://127.0.0.1:8000", source="discovery", key="discovered"),
        discovery=DiscoveryReport(discovered=True, nginx_config=str(nginx_config)),
    )
    result = ScanResult(
        target=Target(url="http://127.0.0.1:8000", scheme="http", host="127.0.0.1"),
        context=context,
        findings=[
            Finding(
                id="cookie-1",
                target_url="http://127.0.0.1:8000",
                title="Weak cookie flags",
                description="Cookie flags are weak.",
                severity="low",
                category="cookies",
                fix_level=0,
                risk_level="low",
                expected_impact="Review the cookie builder.",
            )
        ],
    )

    assert choose_local_fix_target(result) is None

    result.findings.append(
        Finding(
            id="server-info-1",
            target_url="http://127.0.0.1:8000",
            title="Server information disclosure",
            description="The banner is exposed.",
            severity="low",
            category="server_info",
            fix_level=1,
            risk_level="low",
            expected_impact="Hide the server banner in the web server config first.",
        )
    )

    assert choose_local_fix_target(result) == nginx_config


def test_local_nginx_banner_fix_backups_before_editing(workspace_temp_dir, monkeypatch) -> None:
    nginx_config = workspace_temp_dir / "nginx.conf"
    original_text = "server {\n    listen 80;\n}\n"
    nginx_config.write_text(original_text, encoding="utf-8")

    def fake_run(command, capture_output, text, check):
        return subprocess.CompletedProcess(command, 0, stdout="syntax is ok\n", stderr="")

    monkeypatch.setattr("app.hardening.local_fixes.subprocess.run", fake_run)

    result = apply_local_nginx_banner_fix(nginx_config)

    assert result.status == "applied"
    assert result.backup_path == str(nginx_config.with_suffix(".conf.bak"))
    assert result.validation_command is not None
    assert "nginx -t -c" in result.validation_command
    assert "syntax is ok" in result.validation_output
    assert "server_tokens off;" in nginx_config.read_text(encoding="utf-8")
    assert Path(result.backup_path).read_text(encoding="utf-8") == original_text


def test_local_nginx_banner_fix_rolls_back_on_validation_failure(workspace_temp_dir, monkeypatch) -> None:
    nginx_config = workspace_temp_dir / "nginx.conf"
    original_text = "server {\n    listen 80;\n}\n"
    nginx_config.write_text(original_text, encoding="utf-8")

    def fake_run(command, capture_output, text, check):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="bad config\n")

    monkeypatch.setattr("app.hardening.local_fixes.subprocess.run", fake_run)

    result = apply_local_nginx_banner_fix(nginx_config)

    assert result.status == "rolled_back"
    assert result.backup_path == str(nginx_config.with_suffix(".conf.bak"))
    assert result.validation_output == "bad config"
    assert nginx_config.read_text(encoding="utf-8") == original_text


def test_local_nginx_hardening_fix_adds_security_headers(workspace_temp_dir, monkeypatch) -> None:
    nginx_config = workspace_temp_dir / "nginx.conf"
    original_text = "server {\n    listen 80;\n}\n"
    nginx_config.write_text(original_text, encoding="utf-8")

    def fake_run(command, capture_output, text, check):
        return subprocess.CompletedProcess(command, 0, stdout="syntax is ok\n", stderr="")

    monkeypatch.setattr("app.hardening.local_fixes.subprocess.run", fake_run)

    result = apply_local_nginx_hardening_fix(nginx_config, categories=["headers"])

    assert result.status == "applied"
    text = nginx_config.read_text(encoding="utf-8")
    assert "add_header X-Content-Type-Options" in text
    assert "add_header X-Frame-Options" in text
    assert "server_tokens off;" not in text


def test_fix_command_runs_the_local_lane(monkeypatch, workspace_temp_dir) -> None:
    nginx_config = workspace_temp_dir / "nginx.conf"
    nginx_config.write_text("server {\n    listen 80;\n}\n", encoding="utf-8")

    context = ApplicationContext(
        root=str(workspace_temp_dir),
        target=ResolvedScanTarget(value="http://127.0.0.1:8000", source="discovery", key="discovered"),
        discovery=DiscoveryReport(
            discovered=True,
            app_name="AutoEntryTrack",
            target_url="http://127.0.0.1:8000",
            local_url="http://127.0.0.1:8000",
            nginx_config=str(nginx_config),
        ),
    )
    scan_result = ScanResult(
        target=Target(url="http://127.0.0.1:8000", scheme="http", host="127.0.0.1"),
        context=context,
        findings=[
            Finding(
                id="server-info-1",
                target_url="http://127.0.0.1:8000",
                title="Server information disclosure",
                description="The banner is exposed.",
                severity="low",
                category="server_info",
                fix_level=1,
                risk_level="low",
                expected_impact="Hide the server banner in the web server config first.",
            )
        ],
        fix_plans=[
            FixPlan(
                finding_id="server-info-1",
                fix_level=1,
                risk_level="low",
                expected_impact="Hide the banner in the web server config first.",
                rollback_command="Restore the previous web server config.",
            )
        ],
    )

    recorded_console = Console(record=True, width=120)
    audit_events = []

    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(allowed_fix_level=1))
    monkeypatch.setattr(main, "resolve_application_context", lambda url, root, env_file, nginx_config=None, require_target=True: context)
    monkeypatch.setattr(main, "scan_target", lambda target_url, timeout_seconds: scan_result)
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "scan")
    monkeypatch.setattr(main, "ask_to_create_backup", lambda: True)
    monkeypatch.setattr(main, "ask_to_apply_local_fix", lambda: True)
    monkeypatch.setattr(
        main,
        "create_backup",
        lambda target_path, output_dir: workspace_temp_dir / "backups" / f"{target_path.name}.bak",
    )
    monkeypatch.setattr(
        main,
        "apply_local_nginx_hardening_fix",
        lambda target_path, categories=None, backup_path=None: LocalFixResult(
            target_path=str(target_path),
            status="applied",
            reason="Inserted server_tokens off; and the validation check passed.",
            backup_path=str(backup_path or (str(target_path) + ".bak")),
            validation_command=f"nginx -t -c {target_path}",
            validation_output="syntax is ok",
            notes=["Reload the service when you are ready."],
        ),
    )
    monkeypatch.setattr(
        main,
        "append_audit_event",
        lambda path, event: audit_events.append((Path(path), event)),
    )

    main.fix(local_fix=True, env_file=workspace_temp_dir / "autoentrytrack.env", nginx_config=nginx_config)

    text = recorded_console.export_text()
    assert "Backup created before apply" in text
    assert "Applying local fix" in text
    assert "Local Fix" in text
    assert audit_events
    assert audit_events[0][1].action == "local_fix"


def test_fix_command_blocks_when_the_discovered_target_is_missing(monkeypatch, workspace_temp_dir) -> None:
    missing_nginx_config = workspace_temp_dir / "nginx.conf"

    context = ApplicationContext(
        root=str(workspace_temp_dir),
        target=ResolvedScanTarget(value="http://127.0.0.1:8000", source="discovery", key="discovered"),
        discovery=DiscoveryReport(
            discovered=True,
            app_name="AutoEntryTrack",
            target_url="http://127.0.0.1:8000",
            local_url="http://127.0.0.1:8000",
            nginx_config=str(missing_nginx_config),
        ),
    )
    scan_result = ScanResult(
        target=Target(url="http://127.0.0.1:8000", scheme="http", host="127.0.0.1"),
        context=context,
        findings=[
            Finding(
                id="server-info-1",
                target_url="http://127.0.0.1:8000",
                title="Server information disclosure",
                description="The banner is exposed.",
                severity="low",
                category="server_info",
                fix_level=1,
                risk_level="low",
                expected_impact="Hide the server banner in the web server config first.",
            )
        ],
    )

    recorded_console = Console(record=True, width=120)
    backup_calls = []
    audit_events = []

    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "confirm_risky_command", lambda action, assume_yes=False: True)
    monkeypatch.setattr(main, "load_app_config", lambda policy_file: AppConfig(allowed_fix_level=1))
    monkeypatch.setattr(main, "resolve_application_context", lambda url, root, env_file, nginx_config=None, require_target=True: context)
    monkeypatch.setattr(main, "scan_target", lambda target_url, timeout_seconds: scan_result)
    monkeypatch.setattr(main, "render_policy", lambda policy: "policy")
    monkeypatch.setattr(main, "render_console", lambda result, include_fix_plans=False: "scan")
    monkeypatch.setattr(main, "create_backup", lambda target_path, output_dir: backup_calls.append(target_path) or (workspace_temp_dir / "backups" / f"{target_path.name}.bak"))
    monkeypatch.setattr(main, "apply_local_nginx_hardening_fix", lambda target_path, categories=None, backup_path=None: (_ for _ in ()).throw(AssertionError("apply should not run")))
    monkeypatch.setattr(
        main,
        "append_audit_event",
        lambda path, event: audit_events.append((Path(path), event)),
    )

    main.fix(local_fix=True, env_file=workspace_temp_dir / "autoentrytrack.env", nginx_config=missing_nginx_config)

    text = recorded_console.export_text()
    assert "does not exist" in text
    assert backup_calls == []
    assert audit_events
    assert audit_events[0][1].result == "blocked"
