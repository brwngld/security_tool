from typer.testing import CliRunner

from app.main import app


def test_top_level_help_mentions_preferred_command() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "preferred CLI command is pshield" in result.stdout
    assert "compatibility aliases" in result.stdout
