from rich.console import Console

from app import main
from app.secrets import analyze_secret_exposures


def test_analyze_secret_exposures_redacts_sensitive_values(workspace_temp_dir) -> None:
    env_file = workspace_temp_dir / ".env"
    env_file.write_text(
        "APP_URL=https://example.com\n"
        "PASSWORD=supersecret123\n"
        "API_KEY=abc123def456ghi789\n",
        encoding="utf-8",
    )
    log_file = workspace_temp_dir / "access.log"
    log_file.write_text(
        'Authorization: Bearer secret-token-123\n'
        'session=very-secret-cookie\n',
        encoding="utf-8",
    )

    report = analyze_secret_exposures(workspace_temp_dir)

    assert report.findings
    evidence_text = " ".join(str(finding.evidence) for finding in report.findings)
    assert "supersecret123" not in evidence_text
    assert "secret-token-123" not in evidence_text
    assert "very-secret-cookie" not in evidence_text


def test_secrets_command_renders_and_writes_outputs(monkeypatch, workspace_temp_dir) -> None:
    env_file = workspace_temp_dir / ".env"
    env_file.write_text("PASSWORD=supersecret123\n", encoding="utf-8")

    recorded_console = Console(record=True, width=120)
    output_calls = []
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "write_secret_outputs", lambda report, json_output_path, markdown_output_path, html_output_path: output_calls.append((json_output_path, markdown_output_path, html_output_path)))

    main.secrets(workspace_temp_dir, json_output=workspace_temp_dir / "outputs" / "secrets.json")

    text = recorded_console.export_text()
    assert "Secret Exposure" in text
    assert "supersecret123" not in text
    assert output_calls
