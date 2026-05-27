from app.config import AppConfig
from app.hardening.executor import execute_fix
from app.hardening.local_notes import choose_first_move
from app.models import Finding, FixPlan


def test_executor_writes_a_local_remediation_note(workspace_temp_dir, monkeypatch) -> None:
    monkeypatch.chdir(workspace_temp_dir)
    finding = Finding(
        id="f1",
        target_url="https://example.com",
        title="missing header",
        description="test",
        severity="low",
        category="headers",
        fix_level=0,
        risk_level="low",
    )
    plan = FixPlan(
        finding_id="f1",
        fix_level=0,
        risk_level="low",
        rollback_command="Delete the note file.",
        expected_impact="Add the missing header later.",
    )
    policy = AppConfig(allowed_fix_level=0)

    backup_path = workspace_temp_dir / "outputs" / "backups" / "f1.conf.bak"
    assert execute_fix(finding, plan, policy, output_dir=workspace_temp_dir / "outputs" / "remediation", backup_path=backup_path) == "generated"
    artifact_path = workspace_temp_dir / "outputs" / "generated" / "f1.conf"
    assert artifact_path.exists()
    artifact_text = artifact_path.read_text(encoding="utf-8")
    assert "Turan reversible hardening artifact" in artifact_text
    assert "server_tokens off" in artifact_text or "Secure and HttpOnly" in artifact_text or "add_header" in artifact_text
    note_path = workspace_temp_dir / "outputs" / "remediation" / "f1.md"
    assert note_path.exists()
    note_text = note_path.read_text(encoding="utf-8")
    assert "Remediation note" in note_text
    assert "Severity summary" in note_text
    assert "First move" in note_text
    assert "Backup:" in note_text
    assert "Artifact:" in note_text
    assert "f1.conf.bak" in note_text
    assert "outputs/generated/f1.conf" in note_text


def test_executor_writes_category_specific_artifacts(workspace_temp_dir, monkeypatch) -> None:
    monkeypatch.chdir(workspace_temp_dir)
    policy = AppConfig(allowed_fix_level=0)

    scenarios = [
        (
            "headers",
            "add_header X-Frame-Options",
            "Hide the banner and add the common security headers",
        ),
        (
            "cookies",
            "Set-Cookie: session=...",
            "Set Secure and HttpOnly where the cookie is issued",
        ),
        (
            "server_info",
            "server_tokens off;",
            "Hide the server banner in the web server config",
        ),
        (
            "exposed_files",
            "location ~ /\\.(env|git|sql|bak)$ {",
            "Block direct access to sensitive files at the web root",
        ),
        (
            "tls",
            "Strict-Transport-Security",
            "Force HTTPS at the edge",
        ),
    ]

    for index, (category, expected_snippet, expected_reason) in enumerate(scenarios, start=1):
        finding = Finding(
            id=f"f{index}",
            target_url="https://example.com",
            title=category,
            description="test",
            severity="low",
            category=category,
            fix_level=0,
            risk_level="low",
        )
        plan = FixPlan(
            finding_id=f"f{index}",
            fix_level=0,
            risk_level="low",
            rollback_command="Delete the note file.",
            expected_impact=f"Fix {category} first.",
        )
        artifact_path = workspace_temp_dir / "outputs" / "generated" / f"f{index}.conf"
        assert execute_fix(finding, plan, policy, output_dir=workspace_temp_dir / "outputs" / "remediation", backup_path=artifact_path.with_suffix(".conf.bak")) == "generated"
        artifact_text = artifact_path.read_text(encoding="utf-8")
        assert expected_snippet in artifact_text
        assert expected_reason in artifact_text


def test_choose_first_move_matches_the_finding_category() -> None:
    header_finding = Finding(
        id="h1",
        target_url="https://example.com",
        title="header",
        description="test",
        severity="low",
        category="headers",
        fix_level=0,
        risk_level="low",
    )
    file_finding = Finding(
        id="e1",
        target_url="https://example.com",
        title="file",
        description="test",
        severity="low",
        category="exposed_files",
        fix_level=0,
        risk_level="low",
    )

    assert "Nginx" in choose_first_move(header_finding)
    assert "web root" in choose_first_move(file_finding)
