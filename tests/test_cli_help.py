from typer.testing import CliRunner

from app.main import app
from app import main


def test_top_level_help_mentions_preferred_command() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "preferred CLI command is pshield" in result.stdout
    assert "compatibility aliases" in result.stdout


def test_cli_main_expands_optional_output_arguments(monkeypatch) -> None:
    captured = []
    monkeypatch.setattr(main, "expand_optional_output_arguments", lambda argv: (["pshield", "scan", "--html-output", "outputs/scan.html"], ["Using default output path for --html-output: outputs/scan.html"]))
    monkeypatch.setattr(main, "app", lambda: captured.append(list(main.sys.argv)))
    monkeypatch.setattr(main.sys, "argv", ["pshield", "scan", "--html-output"])

    main.cli_main()

    assert captured == [["pshield", "scan", "--html-output", "outputs/scan.html"]]
