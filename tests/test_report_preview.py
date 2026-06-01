from rich.console import Console

from app import main


def test_report_previews_saved_markdown_and_copies_it(workspace_temp_dir, monkeypatch) -> None:
    report_file = workspace_temp_dir / "scan.md"
    output_file = workspace_temp_dir / "copy.md"
    report_file.write_text("# PsyberShield Report\n\nStored markdown body.\n", encoding="utf-8")

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)

    main.report(report_file, markdown_output=output_file)

    text = recorded_console.export_text()
    assert "Stored Report" in text
    assert "Stored markdown body." in text
    assert output_file.read_text(encoding="utf-8") == report_file.read_text(encoding="utf-8")


def test_report_previews_saved_html_and_copies_it(workspace_temp_dir, monkeypatch) -> None:
    report_file = workspace_temp_dir / "scan.html"
    output_file = workspace_temp_dir / "copy.html"
    report_file.write_text("<html><body><h1>PsyberShield Deployment Readiness Review</h1></body></html>", encoding="utf-8")

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr(main, "console", recorded_console)

    main.report(report_file, html_output=output_file)

    text = recorded_console.export_text()
    assert "Stored Report" in text
    assert "html" in text.lower()
    assert output_file.read_text(encoding="utf-8") == report_file.read_text(encoding="utf-8")
