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


def test_analyze_secret_exposures_ignores_safe_values(workspace_temp_dir) -> None:
    notes_file = workspace_temp_dir / "notes.txt"
    notes_file.write_text("deployment complete\nmonitoring enabled\n", encoding="utf-8")

    report = analyze_secret_exposures(workspace_temp_dir)

    assert report.findings == []
    assert any("No obvious secret exposure" in note for note in report.notes)


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


def test_secrets_command_uses_default_outputs_when_none_are_provided(monkeypatch, workspace_temp_dir) -> None:
    env_file = workspace_temp_dir / ".env"
    env_file.write_text("PASSWORD=supersecret123\n", encoding="utf-8")

    recorded_console = Console(record=True, width=120)
    output_calls = []
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "default_output_path", lambda command_name, option_name, stamp=None: workspace_temp_dir / "outputs" / f"{command_name}-{option_name.strip('-').replace('-', '_')}.txt")
    monkeypatch.setattr(main, "write_secret_outputs", lambda report, json_output_path, markdown_output_path, html_output_path: output_calls.append((json_output_path, markdown_output_path, html_output_path)))

    main.secrets(workspace_temp_dir)

    assert output_calls
    json_path, markdown_path, html_path = output_calls[0]
    assert json_path == workspace_temp_dir / "outputs" / "secrets-json_output.txt"
    assert markdown_path == workspace_temp_dir / "outputs" / "secrets-markdown_output.txt"
    assert html_path == workspace_temp_dir / "outputs" / "secrets-html_output.txt"
    text = recorded_console.export_text()
    assert "Using default output path for --json-output" in text
    assert "Using default output path for --markdown-output" in text
    assert "Using default output path for --html-output" in text
