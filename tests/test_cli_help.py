from pathlib import Path

import pytest
from typer.testing import CliRunner

from app.main import app
from app import main
import typer


def test_top_level_help_mentions_preferred_command() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "preferred CLI command is pshield" in result.stdout
    assert "compatibility aliases" in result.stdout
    assert "demo" in result.stdout
    assert "watch" in result.stdout
    assert "vuln" in result.stdout
    assert "web" in result.stdout
    assert "worker" in result.stdout
    assert "preset profiles" in result.stdout
    assert "safe-vps" in result.stdout


def test_cli_main_expands_optional_output_arguments(monkeypatch) -> None:
    captured = []
    monkeypatch.setattr(main, "expand_optional_output_arguments", lambda argv: (["pshield", "scan", "--html-output", "outputs/scan.html"], ["Using default output path for --html-output: outputs/scan.html"]))
    monkeypatch.setattr(main, "app", lambda: captured.append(list(main.sys.argv)))
    monkeypatch.setattr(main.sys, "argv", ["pshield", "scan", "--html-output"])

    main.cli_main()

    assert captured == [["pshield", "scan", "--html-output", "outputs/scan.html"]]


def test_demo_alias_runs_demo_site(monkeypatch) -> None:
    runner = CliRunner()
    captured = {}
    monkeypatch.setattr(main, "serve_demo_site", lambda port: captured.setdefault("port", port))

    result = runner.invoke(app, ["demo", "--port", "8123"])

    assert result.exit_code == 0
    assert captured["port"] == 8123


def test_build_auth_config_requires_login_url_or_storage_state_for_browser_auth() -> None:
    with pytest.raises(typer.BadParameter, match="Browser auth requires --login-url or --storage-state."):
        main.build_auth_config(
            login_url=None,
            auth_method="browser",
            username="alice",
            password=None,
            password_env=None,
            env_file=None,
            user_field="identifier",
            pass_field="password",
            cookie=None,
            session_file=None,
            save_session=False,
            storage_state=None,
            save_storage_state=False,
            browser_username_selector='input[name="identifier"]',
            browser_password_selector='input[name="password"]',
            browser_submit_selector=None,
            browser_headless=True,
            auth_check_url="/account",
        )


def test_browser_auth_summary_notes_resolve_login_url() -> None:
    notes = main.browser_auth_summary_notes(
        "https://example.com/base/",
        main.CrawlAuthConfig(
            auth_method="browser",
            login_url="/auth/login",
            storage_state=Path("browser\\storage_state.json"),
        ),
    )

    assert notes == [
        "Browser auth: enabled",
        "Browser auth mode: login flow with storage-state preload",
        "Browser login URL: https://example.com/auth/login",
        "Browser storage state: browser/storage_state.json",
    ]


def test_browser_auth_summary_notes_show_storage_state_mode() -> None:
    notes = main.browser_auth_summary_notes(
        "https://example.com/base/",
        main.CrawlAuthConfig(
            auth_method="browser",
            storage_state=Path("browser\\storage_state.json"),
        ),
    )

    assert notes == [
        "Browser auth: enabled",
        "Browser auth mode: storage-state reuse",
        "Browser storage state: browser/storage_state.json",
    ]
