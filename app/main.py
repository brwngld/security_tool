from __future__ import annotations

import re
import sys
from pathlib import Path

import typer
from rich.console import Console

from app.artifacts import load_scan_result
from app.audit import (
    append_audit_event,
    build_fix_audit_event,
    build_integrity_audit_event,
    build_incident_audit_event,
    build_local_fix_audit_event,
    build_scan_audit_event,
    filter_audit_events,
    read_audit_events,
    write_audit_events_json,
)
from app.doctor import run_doctor_checks, run_server_checks
from app.config import load_app_config
from app.approvals import (
    ask_to_apply_local_fix,
    ask_to_create_backup,
    confirm_risky_command,
    choose_interactive_fix_mode,
    choose_interactive_fix_selection,
)
from app.baseline import build_baseline_metadata, summarize_baseline_metadata, write_baseline_metadata
from app.comparison import compare_scan_files, summarize_comparison, summarize_crawl_coverage_delta
from app.context import resolve_application_context, summarize_application_context
from app.bundles import bundle_report_files
from app.drift import analyze_report_drift
from app.demo_site import serve_demo_site
from app.integrity import analyze_integrity_sources
from app.incident import analyze_incident_sources, collect_live_incident_sources, default_incident_sources
from app.notifications import send_report_notifications, summarize_notification_results
from app.secrets import analyze_secret_exposures
from app.timeline import load_timeline_report_from_path
from app.http.auth import CrawlAuthConfig
from app.hardening.backup import create_backup
from app.hardening.applied_artifacts import applied_artifact_path, create_applied_artifact_backup
from app.hardening.executor import evaluate_fix_plan, execute_fix
from app.hardening.incident import (
    apply_nginx_denylist,
    write_fail2ban_artifact,
    write_maintenance_mode_artifact,
    write_rate_limit_artifact,
)
from app.hardening.local_fixes import apply_local_nginx_hardening_fix, choose_local_fix_target
from app.output_paths import default_output_path, expand_optional_output_arguments, normalize_output_path
from app.models import LocalFixResult
from app.scanner import crawl_target, scan_target
from app.reports.comparison_report import write_html_comparison_report, write_markdown_comparison_report
from app.reports.console import (
    render_audit_log,
    render_application_context,
    render_comparison,
    render_console,
    render_crawl_summary,
    render_doctor_report,
    render_fix_decisions,
    render_bundle_report,
    render_drift_report,
    render_incident_report,
    render_integrity_report,
    render_interactive_fix_catalog,
    render_local_fix_preview,
    render_local_fix_result,
    render_policy,
    render_secret_report,
    render_timeline_report,
)
from app.reports.drift_report import write_html_drift_report, write_json_drift_report, write_markdown_drift_report
from app.reports.integrity_report import write_html_integrity_report, write_json_integrity_report, write_markdown_integrity_report
from app.reports.incident_report import write_html_incident_report, write_json_incident_report, write_markdown_incident_report
from app.reports.secret_report import write_html_secret_report, write_json_secret_report, write_markdown_secret_report
from app.reports.timeline_report import write_html_timeline_report, write_json_timeline_report, write_markdown_timeline_report
from app.reports.html_report import write_html_report
from app.reports.json_report import write_json_report
from app.reports.markdown_report import write_markdown_report
from app.reports.stored_report import render_stored_report_preview


app = typer.Typer(
    add_completion=False,
    rich_markup_mode="markdown",
    help=(
        "Turan web security scanner and local hardening assistant.\n\n"
        "**What it does now**\n"
        "- Normalizes a target URL\n"
        "- Fetches one page safely\n"
        "- Crawls in-scope links across multiple pages\n"
        "- Supports authenticated crawl sessions for protected pages\n"
        "- Can import and export saved session cookies\n"
        "- Can import and export browser storage-state files\n"
        "- Can drive browser logins for JS-heavy auth flows when needed\n"
        "- Checks security headers\n"
        "- Checks cookie flags\n"
        "- Flags server banners\n"
        "- Notes WAF/CDN signals\n"
        "- Summarizes TLS details\n"
        "- Probes a short list of exposed files\n"
        "- Proposes fixes for report-only findings\n"
        "- Can fall back to `APP_URL`, `TARGET_URL`, or `BASE_URL` from `.env` or `--env-file`\n"
        "- Can discover a local app target when no URL is supplied on a server\n"
        "- Writes JSON, Markdown, and HTML reports\n"
        "- Re-renders or previews saved reports from disk\n"
        "- Appends scan and fix events to an audit log\n"
        "- Shows audit history from the log\n"
        "- Shows a chronological timeline from a saved incident report and optional audit log\n"
        "- Saves baseline snapshots for later comparison\n"
        "- Compares two saved scan reports and crawl coverage deltas\n"
        "- Checks the local machine and app environment without a URL\n"
        "- Checks server-only paths and local config without a URL\n"
        "- Checks suspicious listeners and outbound connections on the local machine\n"
        "- Detects suspicious server or app activity from logs and can write denylist, fail2ban, rate-limit, and maintenance-mode containment artifacts\n"
        "- Monitors key files for integrity drift against a saved baseline\n"
        "- Detects drift between saved baseline and current reports across scans, files, logs, and config checks\n"
        "- Scans files for obvious secret exposure with redacted evidence\n"
        "- Packages related reports and containment artifacts into a ZIP bundle\n"
        "- Sends incident, integrity, and timeline notifications via webhooks, Slack, Discord, or email\n"
        "- Runs a local demo site for testing\n\n"
        "**Safety**\n"
        "- `--yes` skips the permission prompt for trusted automation\n\n"
        "**Browser auth**\n"
        "- `--auth-method browser` logs in with a browser session for JS-heavy auth flows\n"
        "- `--browser-username-selector` and `--browser-password-selector` target login fields\n"
        "- `--browser-submit-selector` clicks the submit control when needed\n"
        "- `--browser-headless/--browser-headed` chooses whether the browser runs visibly\n"
        "- install the optional browser extra with `pip install .[browser]`\n\n"
        "**Report outputs**\n"
        "- `--json-output`, `--markdown-output`, and `--html-output` can take a path or auto-create one under `outputs/`\n"
        "- `--json-output` writes machine-readable scan data\n"
        "- `--markdown-output` writes a quick human-readable report\n"
        "- `--html-output` writes the polished browser report\n"
        "- `report` accepts `.json`, `.md`, and `.html` files\n"
        "- Windows-rooted output paths like `\\outputs\\scan.html` are treated as project-relative and are explained in the terminal\n\n"
        "**Audit**\n"
        "- `--audit-log` writes scan and baseline events to a chosen file\n"
        "- `audit --audit-log` reads a specific audit log file\n"
        "- `audit --log-file` still works as a backwards-compatible alias\n\n"
        "- `audit --json-output` writes filtered audit history as JSON\n\n"
        "**Doctor**\n"
        "- `doctor` checks the local machine, config paths, and safe status signals\n\n"
        "**Server check**\n"
        "- `server-check` checks the server-facing config and local service signals\n\n"
        "**Fix application**\n"
        "- `--preview-fixes` shows the planned changes only\n"
        "- `--interactive` lets you choose generate artifacts or fix locally, then pick fixes from a paged list\n"
        "- `--generate-fixes` creates a backup, then generates allowed safe fix artifacts as local remediation notes\n"
        "- `--apply-fixes` still works as a backwards-compatible alias for `--generate-fixes` and is kept for older muscle memory\n\n"
        "- `fix --local` discovers a supported server file, backs it up, and applies one real local edit\n\n"
        "**Examples**\n"
        "```powershell\n"
        "scan http://127.0.0.1:8000\n"
        "scan\n"
        "crawl https://example.com\n"
        "crawl https://example.com --max-pages 20 --max-depth 2\n"
        "crawl http://127.0.0.1:8000\n"
        "scan --env-file /path/to/autoentrytrack/.env\n"
        "crawl https://example.com --seed-robots --seed-sitemap\n"
        "crawl https://example.com --login-url /auth/login --auth-method json --username alice --password-env TURAN_PASSWORD --auth-check-url /account\n"
        "crawl https://example.com --session-file sessions\\autoentrytrack.json --save-session --auth-check-url /account\n"
        "crawl https://example.com --storage-state browser\\storage_state.json --save-storage-state --auth-check-url /account\n"
        "crawl https://example.com --auth-method browser --browser-username-selector input[name='email'] --browser-password-selector input[name='password'] --username alice --password-env TURAN_PASSWORD --auth-check-url /account\n"
        "scan http://127.0.0.1:8000 --timeout 5\n"
        "scan http://127.0.0.1:8000 --policy policy.json\n"
        "scan http://127.0.0.1:8000 --yes\n"
        "scan http://127.0.0.1:8000 --preview-fixes\n"
        "scan http://127.0.0.1:8000 --interactive\n"
        "scan http://127.0.0.1:8000 --generate-fixes\n"
        "crawl https://example.com --yes\n"
        "fix --local\n"
        "fix --local --yes\n"
        "scan http://127.0.0.1:8000 --json-output outputs\\scan.json\n"
        "scan http://127.0.0.1:8000 --markdown-output outputs\\scan.md\n"
        "scan http://127.0.0.1:8000 --html-output outputs\\scan.html\n"
        "scan http://127.0.0.1:8000 --html-output\n"
        "crawl http://127.0.0.1:8000 --markdown-output outputs\\crawl.md\n"
        "crawl http://127.0.0.1:8000 --html-output\n"
        "crawl https://example.com --include /auth/ --exclude /logout\n"
        "report outputs\\scan.json --html-output outputs\\scan.html\n"
        "report outputs\\scan.md\n"
        "report outputs\\scan.html\n"
        "audit --audit-log outputs\\audit.log\n"
        "timeline outputs\\incident.json --audit-log outputs\\audit.log\n"
        "audit --log-file outputs\\audit.log\n"
        "audit --last 25\n"
        "audit --event scan\n"
        "audit --json-output outputs\\audit.json\n"
        "doctor\n"
        "doctor --env-file /path/to/autoentrytrack/.env\n"
        "server-check\n"
        "server-check --env-file /path/to/autoentrytrack/.env --nginx-config /etc/nginx/nginx.conf\n"
        "incident --logs outputs\\access.log --apply-blocks\n"
        "integrity . --baseline baselines\\integrity.json\n"
        "incident --logs C:\\logs --html-output\n"
        "baseline http://127.0.0.1:8000 --label vps-west\n"
        "baseline http://127.0.0.1:8000 --output baselines\\vps-west.json\n"
        "compare old.json new.json --markdown-output compare.md\n"
        "compare old.json new.json --html-output compare.html\n"
        "drift baselines\\scan.json outputs\\scan.json --json-output outputs\\drift.json\n"
        "secrets . --markdown-output outputs\\secrets.md\n"
        "bundle outputs\\incident.json --artifact outputs\\incident-fail2ban.conf --bundle-output outputs\\incident-bundle.zip\n"
        "demo-site --port 8000\n"
        "```"
    ),
)
console = Console()
CLI_OPTIONAL_OUTPUT_NOTES: list[str] = []


def flag_is_enabled(value: object) -> bool:
    return value is True


def path_option_value(value: object) -> Path | None:
    return value if isinstance(value, Path) else None


def timeout_option_value(value: object) -> float | None:
    return value if isinstance(value, (int, float)) else None


def text_option_value(value: object) -> str | None:
    return value if isinstance(value, str) else None


def list_option_value(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def display_path_value(value: str | Path | None) -> str | None:
    if value is None:
        return None
    path_value = Path(value)
    return path_value.as_posix()


def normalize_output_option(value: Path | None) -> tuple[Path | None, str | None]:
    normalized = normalize_output_path(value, cwd=Path.cwd())
    if normalized is None:
        return None, None
    return normalized.path, normalized.note


def print_optional_output_notes() -> None:
    while CLI_OPTIONAL_OUTPUT_NOTES:
        console.print(f"[info] {CLI_OPTIONAL_OUTPUT_NOTES.pop(0)}")


def int_option_value(value: object) -> int | None:
    return value if isinstance(value, int) else None


def compile_regex_options(values: list[str] | None, option_name: str) -> list[re.Pattern[str]] | None:
    if not values:
        return None
    try:
        return [re.compile(value) for value in values if value.strip()]
    except re.error as exc:
        raise typer.BadParameter(f"Invalid {option_name} pattern: {exc}") from exc


def build_auth_config(
    *,
    login_url: str | None,
    auth_method: str,
    username: str | None,
    password: str | None,
    password_env: str | None,
    user_field: str,
    pass_field: str,
    cookie: str | None,
    session_file: Path | None,
    save_session: bool,
    storage_state: Path | None,
    save_storage_state: bool,
    browser_username_selector: str | None,
    browser_password_selector: str | None,
    browser_submit_selector: str | None,
    browser_headless: bool,
    auth_check_url: str | None,
) -> CrawlAuthConfig | None:
    if not any(
        [
            login_url,
            username,
            password,
            password_env,
            user_field != "identifier",
            pass_field != "password",
            auth_method.strip().lower() != "json",
            cookie,
            session_file is not None,
            save_session,
            storage_state is not None,
            save_storage_state,
            browser_username_selector,
            browser_password_selector,
            browser_submit_selector,
            not browser_headless,
            auth_check_url,
        ]
    ):
        return None
    return CrawlAuthConfig(
        login_url=text_option_value(login_url),
        auth_method=auth_method.strip().lower() or "json",
        username=text_option_value(username),
        password=text_option_value(password),
        password_env=text_option_value(password_env),
        user_field=text_option_value(user_field) or "identifier",
        pass_field=text_option_value(pass_field) or "password",
        cookie=text_option_value(cookie),
        session_file=display_path_value(session_file),
        save_session=save_session,
        storage_state=display_path_value(storage_state),
        save_storage_state=save_storage_state,
        browser_username_selector=text_option_value(browser_username_selector),
        browser_password_selector=text_option_value(browser_password_selector),
        browser_submit_selector=text_option_value(browser_submit_selector),
        browser_headless=browser_headless,
        auth_check_url=text_option_value(auth_check_url),
    )


def parse_fix_selection(selection: str, max_items: int) -> list[int]:
    cleaned = selection.strip().lower()
    if not cleaned or cleaned in {"all", "*"}:
        return list(range(1, max_items + 1))
    if cleaned in {"none", "skip", "0"}:
        return []

    selected: set[int] = set()
    for raw_token in cleaned.replace(" ", "").split(","):
        token = raw_token.lstrip("#")
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                start, end = end, start
            for value in range(start, end + 1):
                if 1 <= value <= max_items:
                    selected.add(value)
            continue
        value = int(token)
        if 1 <= value <= max_items:
            selected.add(value)

    return sorted(selected)


def clean_file_label(label: str) -> str:
    cleaned = label.strip().lower()
    for character in ("\\", "/", " "):
        cleaned = cleaned.replace(character, "-")
    return "-".join(part for part in cleaned.split("-") if part)


def write_scan_outputs(
    result,
    include_fix_plans: bool,
    json_output_path: Path | None,
    markdown_output_path: Path | None,
    html_output_path: Path | None,
) -> None:
    if json_output_path is not None:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_json_report(result, json_output_path)
        console.print(f"Wrote JSON report to {json_output_path}")

    if markdown_output_path is not None:
        markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_markdown_report(result, markdown_output_path, include_fix_plans=include_fix_plans)
        console.print(f"Wrote Markdown report to {markdown_output_path}")

    if html_output_path is not None:
        html_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_html_report(result, html_output_path, include_fix_plans=include_fix_plans)
        console.print(f"Wrote HTML report to {html_output_path}")


def write_incident_outputs(
    report,
    json_output_path: Path | None,
    markdown_output_path: Path | None,
    html_output_path: Path | None,
    fail2ban_output_path: Path | None,
    rate_limit_output_path: Path | None,
    maintenance_output_path: Path | None,
) -> None:
    if json_output_path is not None:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_json_incident_report(report, json_output_path)
        console.print(f"Wrote JSON report to {json_output_path}")

    if markdown_output_path is not None:
        markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_markdown_incident_report(report, markdown_output_path)
        console.print(f"Wrote Markdown report to {markdown_output_path}")

    if html_output_path is not None:
        html_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_html_incident_report(report, html_output_path)
        console.print(f"Wrote HTML report to {html_output_path}")

    if fail2ban_output_path is not None:
        fail2ban_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_fail2ban_artifact(report, fail2ban_output_path)
        console.print(f"Wrote fail2ban-style artifact to {fail2ban_output_path}")

    if rate_limit_output_path is not None:
        rate_limit_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_rate_limit_artifact(report, rate_limit_output_path)
        console.print(f"Wrote rate-limit artifact to {rate_limit_output_path}")

    if maintenance_output_path is not None:
        maintenance_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_maintenance_mode_artifact(report, maintenance_output_path)
        console.print(f"Wrote maintenance-mode artifact to {maintenance_output_path}")


def write_integrity_outputs(
    report,
    json_output_path: Path | None,
    markdown_output_path: Path | None,
    html_output_path: Path | None,
) -> None:
    if json_output_path is not None:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_json_integrity_report(report, json_output_path)
        console.print(f"Wrote JSON report to {json_output_path}")

    if markdown_output_path is not None:
        markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_markdown_integrity_report(report, markdown_output_path)
        console.print(f"Wrote Markdown report to {markdown_output_path}")

    if html_output_path is not None:
        html_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_html_integrity_report(report, html_output_path)
        console.print(f"Wrote HTML report to {html_output_path}")


def write_timeline_outputs(
    report,
    json_output_path: Path | None,
    markdown_output_path: Path | None,
    html_output_path: Path | None,
) -> None:
    if json_output_path is not None:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_json_timeline_report(report, json_output_path)
        console.print(f"Wrote JSON report to {json_output_path}")

    if markdown_output_path is not None:
        markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_markdown_timeline_report(report, markdown_output_path)
        console.print(f"Wrote Markdown report to {markdown_output_path}")

    if html_output_path is not None:
        html_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_html_timeline_report(report, html_output_path)
        console.print(f"Wrote HTML report to {html_output_path}")


def write_drift_outputs(
    report,
    json_output_path: Path | None,
    markdown_output_path: Path | None,
    html_output_path: Path | None,
) -> None:
    if json_output_path is not None:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_json_drift_report(report, json_output_path)
        console.print(f"Wrote JSON report to {json_output_path}")

    if markdown_output_path is not None:
        markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_markdown_drift_report(report, markdown_output_path)
        console.print(f"Wrote Markdown report to {markdown_output_path}")

    if html_output_path is not None:
        html_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_html_drift_report(report, html_output_path)
        console.print(f"Wrote HTML report to {html_output_path}")


def write_secret_outputs(
    report,
    json_output_path: Path | None,
    markdown_output_path: Path | None,
    html_output_path: Path | None,
) -> None:
    if json_output_path is not None:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_json_secret_report(report, json_output_path)
        console.print(f"Wrote JSON report to {json_output_path}")

    if markdown_output_path is not None:
        markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_markdown_secret_report(report, markdown_output_path)
        console.print(f"Wrote Markdown report to {markdown_output_path}")

    if html_output_path is not None:
        html_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_html_secret_report(report, html_output_path)
        console.print(f"Wrote HTML report to {html_output_path}")


def send_notification_outputs(
    report,
    *,
    webhook_urls: list[str] | None = None,
    slack_webhook_urls: list[str] | None = None,
    discord_webhook_urls: list[str] | None = None,
    email_recipients: list[str] | None = None,
    email_sender: str | None = None,
    smtp_host: str | None = None,
    smtp_port: int = 587,
    smtp_username: str | None = None,
    smtp_password_env: str | None = None,
    root: Path | None = None,
    env_file: Path | None = None,
    timeout: float = 10.0,
    use_starttls: bool = True,
) -> None:
    results = send_report_notifications(
        report,
        webhook_urls=webhook_urls,
        slack_webhook_urls=slack_webhook_urls,
        discord_webhook_urls=discord_webhook_urls,
        email_recipients=email_recipients,
        email_sender=email_sender,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_username=smtp_username,
        smtp_password_env=smtp_password_env,
        root=root,
        env_file=env_file,
        timeout=timeout,
        use_starttls=use_starttls,
    )
    if not results:
        return
    console.print(f"[info] {summarize_notification_results(results)}")
    for result in results:
        if result.status == "sent":
            console.print(f"[green]{result.channel} notification sent to {result.target}[/green]")
        elif result.status == "skipped":
            console.print(f"[yellow]{result.channel} notification skipped for {result.target}: {result.detail}[/yellow]")
        else:
            console.print(f"[yellow]{result.channel} notification failed for {result.target}: {result.detail}[/yellow]")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    # Show the top-level help when the user runs Turan without a subcommand.
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


@app.command(help="Scan a target URL, or discover one from the local server layout when no URL is supplied.")
def scan(
    url: str | None = typer.Argument(None, metavar="URL", help="Target URL. If omitted, Turan looks for APP_URL, TARGET_URL, or BASE_URL in .env."),
    env_file: Path | None = typer.Option(None, "--env-file", help="Read target defaults from a specific .env file"),
    timeout: float | None = typer.Option(None, "--timeout", min=0.1, help="Request and TLS timeout in seconds"),
    yes: bool = typer.Option(False, "--yes", help="Skip the permission prompt for trusted automation"),
    policy_file: Path | None = typer.Option(None, "--policy", help="Load scan settings from a JSON file"),
    audit_log: Path | None = typer.Option(None, "--audit-log", help="Write audit events to a specific file"),
    login_url: str | None = typer.Option(None, "--login-url", help="Log in before scanning protected pages"),
    auth_method: str = typer.Option("json", "--auth-method", help="Login payload format: json or form"),
    username: str | None = typer.Option(None, "--username", help="Username, email, or identifier for the login payload"),
    password: str | None = typer.Option(None, "--password", help="Password for the login payload"),
    password_env: str | None = typer.Option(None, "--password-env", help="Read the password from this environment variable"),
    user_field: str = typer.Option("identifier", "--user-field", help="Field name for the username or identifier"),
    pass_field: str = typer.Option("password", "--pass-field", help="Field name for the password"),
    cookie: str | None = typer.Option(None, "--cookie", help="Raw Cookie header to preload into the session"),
    session_file: Path | None = typer.Option(None, "--session-file", help="Load and optionally save an auth session file"),
    save_session: bool = typer.Option(False, "--save-session/--no-save-session", help="Write the updated session back to --session-file"),
    storage_state: Path | None = typer.Option(None, "--storage-state", help="Load and optionally save a browser storage-state file"),
    save_storage_state: bool = typer.Option(False, "--save-storage-state/--no-save-storage-state", help="Write the updated browser storage state back to --storage-state"),
    browser_username_selector: str | None = typer.Option(None, "--browser-username-selector", help="CSS selector for the username field in browser auth"),
    browser_password_selector: str | None = typer.Option(None, "--browser-password-selector", help="CSS selector for the password field in browser auth"),
    browser_submit_selector: str | None = typer.Option(None, "--browser-submit-selector", help="CSS selector for the submit control in browser auth"),
    browser_headless: bool = typer.Option(True, "--browser-headless/--browser-headed", help="Run browser auth headless"),
    auth_check_url: str | None = typer.Option(None, "--auth-check-url", help="Protected URL to confirm the login worked"),
    preview_fixes: bool = typer.Option(False, "--preview-fixes", "--propose-fixes", help="Show proposed fixes for report-only findings"),
    interactive: bool = typer.Option(False, "--interactive", help="Choose generate artifacts or fix locally, then pick fixes by number"),
    generate_fixes: bool = typer.Option(
        False,
        "--generate-fixes",
        "--apply-fixes",
        help="Generate allowed safe fix artifacts as local remediation notes",
    ),
    json_output: Path | None = typer.Option(None, "--json-output", help="Write a JSON report"),
    markdown_output: Path | None = typer.Option(None, "--markdown-output", help="Write a Markdown report"),
    html_output: Path | None = typer.Option(None, "--html-output", help="Write an HTML report"),
) -> None:
    preview_fixes_enabled = flag_is_enabled(preview_fixes)
    interactive_enabled = flag_is_enabled(interactive)
    generate_fixes_enabled = flag_is_enabled(generate_fixes)
    save_session_enabled = flag_is_enabled(save_session)
    save_storage_state_enabled = flag_is_enabled(save_storage_state)

    if not confirm_risky_command("scan", assume_yes=yes):
        raise typer.Abort()

    if sum(int(flag) for flag in (preview_fixes_enabled, interactive_enabled, generate_fixes_enabled)) > 1:
        raise typer.BadParameter("Use only one of --preview-fixes, --interactive, or --generate-fixes.")

    policy_file_path = path_option_value(policy_file)
    env_file_path = path_option_value(env_file)
    audit_log_path, audit_log_note = normalize_output_option(path_option_value(audit_log))
    json_output_path, json_output_note = normalize_output_option(path_option_value(json_output))
    markdown_output_path, markdown_output_note = normalize_output_option(path_option_value(markdown_output))
    html_output_path, html_output_note = normalize_output_option(path_option_value(html_output))
    timeout_seconds_option = timeout_option_value(timeout)
    auth_config = build_auth_config(
        login_url=text_option_value(login_url),
        auth_method=text_option_value(auth_method) or "json",
        username=text_option_value(username),
        password=text_option_value(password),
        password_env=text_option_value(password_env),
        user_field=text_option_value(user_field) or "identifier",
        pass_field=text_option_value(pass_field) or "password",
        cookie=text_option_value(cookie),
        session_file=path_option_value(session_file),
        save_session=save_session_enabled,
        storage_state=path_option_value(storage_state),
        save_storage_state=save_storage_state_enabled,
        browser_username_selector=text_option_value(browser_username_selector),
        browser_password_selector=text_option_value(browser_password_selector),
        browser_submit_selector=text_option_value(browser_submit_selector),
        browser_headless=browser_headless,
        auth_check_url=text_option_value(auth_check_url),
    )
    if save_session_enabled and path_option_value(session_file) is None:
        raise typer.BadParameter("--save-session requires --session-file.")
    if save_storage_state_enabled and path_option_value(storage_state) is None:
        raise typer.BadParameter("--save-storage-state requires --storage-state.")

    policy = load_app_config(policy_file_path)
    timeout_seconds = timeout_seconds_option if timeout_seconds_option is not None else policy.timeout_seconds
    try:
        context = resolve_application_context(url, Path.cwd(), env_file_path, require_target=True)
    except ValueError as exc:
        if "No application target could be discovered." in str(exc):
            raise typer.BadParameter(str(exc)) from exc
        raise
    if context.target is None:
        raise typer.BadParameter("No scan target could be resolved.")
    if context.target.source == "discovery":
        console.print("No URL supplied. Discovery:")
        console.print(f"Discovery: {summarize_application_context(context)}")
        console.print(render_application_context(context))
    elif context.target.source != "command line":
        console.print(f"Using {context.target.key} from {context.target.source} for the scan target.")
    try:
        if auth_config is None:
            result = scan_target(context.target.value, timeout_seconds=timeout_seconds)
        else:
            result = scan_target(context.target.value, timeout_seconds=timeout_seconds, auth_config=auth_config)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    result.context = context
    console.print(render_policy(policy))
    console.print(render_console(result, include_fix_plans=preview_fixes_enabled or generate_fixes_enabled))
    write_audit_path = audit_log_path or Path(policy.audit_log_path)
    append_audit_event(write_audit_path, build_scan_audit_event(result, policy.allowed_fix_level, "scan"))
    if audit_log_note is not None:
        console.print(f"[info] {audit_log_note}")
    for note in (json_output_note, markdown_output_note, html_output_note):
        if note is not None:
            console.print(f"[info] {note}")
    print_optional_output_notes()

    if interactive_enabled or generate_fixes_enabled:
        decisions = []
        applied_count = 0
        selected_items = list(zip(result.findings, result.fix_plans))
        interactive_mode = None

        if interactive_enabled:
            if not result.fix_plans:
                console.print("No suggested fixes.")
                console.print(render_fix_decisions(decisions))
                write_scan_outputs(
                    result,
                    preview_fixes_enabled or interactive_enabled or generate_fixes_enabled,
                    json_output_path,
                    markdown_output_path,
                    html_output_path,
                )
                return
            console.print("Suggested fixes:")
            mode = choose_interactive_fix_mode()
            if mode == "skip":
                console.print("No fixes selected.")
                console.print(render_fix_decisions(decisions))
                write_scan_outputs(
                    result,
                    preview_fixes_enabled or interactive_enabled or generate_fixes_enabled,
                    json_output_path,
                    markdown_output_path,
                    html_output_path,
                )
                return
            selection_text = choose_interactive_fix_selection(result)
            try:
                selected_indices = parse_fix_selection(selection_text, len(selected_items))
            except ValueError as exc:
                raise typer.BadParameter("Enter fixes as all, none, a comma list, or a range like 1-3.") from exc
            selected_items = [selected_items[index - 1] for index in selected_indices if 1 <= index <= len(selected_items)]
            if not selected_items:
                console.print("No fixes selected.")
                console.print(render_fix_decisions(decisions))
                write_scan_outputs(
                    result,
                    preview_fixes_enabled or interactive_enabled or generate_fixes_enabled,
                    json_output_path,
                    markdown_output_path,
                    html_output_path,
                )
                return

            if mode == "local":
                interactive_mode = "local"
                supported_titles = []
                supported_categories = []
                unsupported_titles = []
                for finding, plan in selected_items:
                    if finding.category in {"server_info", "headers"}:
                        supported_titles.append(finding.title)
                        supported_categories.append(finding.category)
                    else:
                        unsupported_titles.append(finding.title)

                if unsupported_titles:
                    console.print(
                        "These selected fixes do not have a real local edit lane yet: "
                        + ", ".join(unsupported_titles)
                    )

                if not supported_titles:
                    local_fix_result = LocalFixResult(
                        target_path=context.discovery.nginx_config or context.discovery.systemd_service or context.root,
                        status="blocked",
                        reason="No selected fixes are available in the first local edit lane yet.",
                        notes=["Try Generate fix artifacts only for the non-local items."],
                    )
                    console.print(render_local_fix_result(local_fix_result))
                    append_audit_event(
                        write_audit_path,
                        build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
                    )
                    console.print(render_fix_decisions(decisions))
                    write_scan_outputs(
                        result,
                        preview_fixes_enabled or interactive_enabled or generate_fixes_enabled,
                        json_output_path,
                        markdown_output_path,
                        html_output_path,
                    )
                    return

                target_path = choose_local_fix_target(result)
                if target_path is None:
                    local_fix_result = LocalFixResult(
                        target_path=context.discovery.nginx_config or context.discovery.systemd_service or context.root,
                        status="blocked",
                        reason="No supported local fix target was discovered for the first live edit lane.",
                        notes=["Turan found the server layout, but not a supported file to edit yet."],
                    )
                    console.print(render_local_fix_result(local_fix_result))
                    append_audit_event(
                        write_audit_path,
                        build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
                    )
                    console.print(render_fix_decisions(decisions))
                    write_scan_outputs(
                        result,
                        preview_fixes_enabled or interactive_enabled or generate_fixes_enabled,
                        json_output_path,
                        markdown_output_path,
                        html_output_path,
                    )
                    return

                try:
                    backup_path = create_backup(target_path, target_path.parent)
                except PermissionError as exc:
                    local_fix_result = LocalFixResult(
                        target_path=str(target_path),
                        status="blocked",
                        reason=str(exc),
                        notes=["No file was changed."],
                    )
                    console.print(render_local_fix_result(local_fix_result))
                    append_audit_event(
                        write_audit_path,
                        build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
                    )
                    console.print(render_fix_decisions(decisions))
                    write_scan_outputs(
                        result,
                        preview_fixes_enabled or interactive_enabled or generate_fixes_enabled,
                        json_output_path,
                        markdown_output_path,
                        html_output_path,
                    )
                    return
                validation_command = f"nginx -t -c {target_path.as_posix()}"
                console.print(
                    render_local_fix_preview(
                        target_path,
                        backup_path,
                        validation_command,
                        supported_titles,
                    )
                )
                if not ask_to_apply_local_fix():
                    local_fix_result = LocalFixResult(
                        target_path=str(target_path),
                        status="skipped",
                        reason="Skipped by user.",
                        backup_path=display_path_value(backup_path),
                        notes=["No file was changed."],
                    )
                    console.print(render_local_fix_result(local_fix_result))
                    append_audit_event(
                        write_audit_path,
                        build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
                    )
                    console.print(render_fix_decisions(decisions))
                    write_scan_outputs(
                        result,
                        preview_fixes_enabled or interactive_enabled or generate_fixes_enabled,
                        json_output_path,
                        markdown_output_path,
                        html_output_path,
                    )
                    return

                console.print(f"Applying local fix to {target_path.as_posix()}")
                local_fix_result = apply_local_nginx_hardening_fix(target_path, supported_categories, backup_path)
                console.print(render_local_fix_result(local_fix_result))
                append_audit_event(
                    write_audit_path,
                    build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
                )
                console.print(render_fix_decisions(decisions))
                write_scan_outputs(
                    result,
                    preview_fixes_enabled or interactive_enabled or generate_fixes_enabled,
                    json_output_path,
                    markdown_output_path,
                    html_output_path,
                )
                return
            interactive_mode = "generate"

        for finding, plan in selected_items:
            decision = evaluate_fix_plan(finding, plan, policy)
            if decision.status == "ready":
                backup_path = None
                if generate_fixes_enabled or interactive_mode == "generate":
                    backup_path = create_applied_artifact_backup(finding)
                    console.print(f"Backup created before generate: {backup_path}")
                status = execute_fix(finding, plan, policy, backup_path=backup_path)
                if status == "generated":
                    artifact_path = applied_artifact_path(finding)
                    decision = decision.model_copy(
                        update={
                            "status": "generated",
                            "reason": "Wrote a local fix artifact and remediation note.",
                            "backup_path": display_path_value(backup_path),
                            "artifact_path": display_path_value(artifact_path),
                        }
                    )
                    console.print(
                        "Generated artifact: "
                        f"{display_path_value(artifact_path) or '-'} | "
                        f"Backup: {display_path_value(backup_path) or '-'}"
                    )
                    applied_count += 1
            decisions.append(decision)
            append_audit_event(write_audit_path, build_fix_audit_event(finding, plan, decision, policy.allowed_fix_level))
        console.print(render_fix_decisions(decisions))
        if applied_count:
            console.print(f"Generated {applied_count} safe local fix artifact(s).")

    write_scan_outputs(
        result,
        preview_fixes_enabled or interactive_enabled or generate_fixes_enabled,
        json_output_path,
        markdown_output_path,
        html_output_path,
    )


@app.command(help="Crawl in-scope links from a target URL or a discovered app target.")
def crawl(
    url: str | None = typer.Argument(None, metavar="URL", help="Start URL. If omitted, Turan looks for APP_URL, TARGET_URL, or BASE_URL in .env."),
    env_file: Path | None = typer.Option(None, "--env-file", help="Read target defaults from a specific .env file"),
    timeout: float | None = typer.Option(None, "--timeout", min=0.1, help="Request and TLS timeout in seconds"),
    yes: bool = typer.Option(False, "--yes", help="Skip the permission prompt for trusted automation"),
    policy_file: Path | None = typer.Option(None, "--policy", help="Load crawl settings from a JSON file"),
    audit_log: Path | None = typer.Option(None, "--audit-log", help="Write audit events to a specific file"),
    login_url: str | None = typer.Option(None, "--login-url", help="Log in before crawling protected pages"),
    auth_method: str = typer.Option("json", "--auth-method", help="Login payload format: json or form"),
    username: str | None = typer.Option(None, "--username", help="Username, email, or identifier for the login payload"),
    password: str | None = typer.Option(None, "--password", help="Password for the login payload"),
    password_env: str | None = typer.Option(None, "--password-env", help="Read the password from this environment variable"),
    user_field: str = typer.Option("identifier", "--user-field", help="Field name for the username or identifier"),
    pass_field: str = typer.Option("password", "--pass-field", help="Field name for the password"),
    cookie: str | None = typer.Option(None, "--cookie", help="Raw Cookie header to preload into the session"),
    session_file: Path | None = typer.Option(None, "--session-file", help="Load and optionally save an auth session file"),
    save_session: bool = typer.Option(False, "--save-session/--no-save-session", help="Write the updated session back to --session-file"),
    storage_state: Path | None = typer.Option(None, "--storage-state", help="Load and optionally save a browser storage-state file"),
    save_storage_state: bool = typer.Option(False, "--save-storage-state/--no-save-storage-state", help="Write the updated browser storage state back to --storage-state"),
    browser_username_selector: str | None = typer.Option(None, "--browser-username-selector", help="CSS selector for the username field in browser auth"),
    browser_password_selector: str | None = typer.Option(None, "--browser-password-selector", help="CSS selector for the password field in browser auth"),
    browser_submit_selector: str | None = typer.Option(None, "--browser-submit-selector", help="CSS selector for the submit control in browser auth"),
    browser_headless: bool = typer.Option(True, "--browser-headless/--browser-headed", help="Run browser auth headless"),
    auth_check_url: str | None = typer.Option(None, "--auth-check-url", help="Protected URL to confirm the login worked"),
    max_pages: int | None = typer.Option(None, "--max-pages", min=1, help="Maximum pages to visit"),
    max_depth: int | None = typer.Option(None, "--max-depth", min=0, help="Maximum crawl depth"),
    include: list[str] | None = typer.Option(None, "--include", help="Only follow URLs matching this regex; repeat the flag to add more"),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Skip URLs matching this regex; repeat the flag to add more"),
    same_host_only: bool = typer.Option(True, "--same-host-only/--allow-offsite", help="Limit crawling to the current host"),
    seed_robots: bool = typer.Option(False, "--seed-robots/--no-seed-robots", help="Seed crawl from robots.txt sitemap hints"),
    seed_sitemap: bool = typer.Option(False, "--seed-sitemap/--no-seed-sitemap", help="Seed crawl from sitemap.xml"),
    json_output: Path | None = typer.Option(None, "--json-output", help="Write a JSON report"),
    markdown_output: Path | None = typer.Option(None, "--markdown-output", help="Write a Markdown report"),
    html_output: Path | None = typer.Option(None, "--html-output", help="Write an HTML report"),
) -> None:
    if not confirm_risky_command("crawl", assume_yes=yes):
        raise typer.Abort()

    policy_file_path = path_option_value(policy_file)
    env_file_path = path_option_value(env_file)
    audit_log_path, audit_log_note = normalize_output_option(path_option_value(audit_log))
    json_output_path, json_output_note = normalize_output_option(path_option_value(json_output))
    markdown_output_path, markdown_output_note = normalize_output_option(path_option_value(markdown_output))
    html_output_path, html_output_note = normalize_output_option(path_option_value(html_output))
    timeout_seconds_option = timeout_option_value(timeout)
    include_patterns = compile_regex_options(include, "--include")
    exclude_patterns = compile_regex_options(exclude, "--exclude")
    save_session_enabled = flag_is_enabled(save_session)
    save_storage_state_enabled = flag_is_enabled(save_storage_state)
    auth_config = build_auth_config(
        login_url=text_option_value(login_url),
        auth_method=text_option_value(auth_method) or "json",
        username=text_option_value(username),
        password=text_option_value(password),
        password_env=text_option_value(password_env),
        user_field=text_option_value(user_field) or "identifier",
        pass_field=text_option_value(pass_field) or "password",
        cookie=text_option_value(cookie),
        session_file=path_option_value(session_file),
        save_session=save_session_enabled,
        storage_state=path_option_value(storage_state),
        save_storage_state=save_storage_state_enabled,
        browser_username_selector=text_option_value(browser_username_selector),
        browser_password_selector=text_option_value(browser_password_selector),
        browser_submit_selector=text_option_value(browser_submit_selector),
        browser_headless=browser_headless,
        auth_check_url=text_option_value(auth_check_url),
    )
    if save_session_enabled and path_option_value(session_file) is None:
        raise typer.BadParameter("--save-session requires --session-file.")
    if save_storage_state_enabled and path_option_value(storage_state) is None:
        raise typer.BadParameter("--save-storage-state requires --storage-state.")

    policy = load_app_config(policy_file_path)
    timeout_seconds = timeout_seconds_option if timeout_seconds_option is not None else policy.timeout_seconds
    max_pages_value = int_option_value(max_pages) if max_pages is not None else policy.max_pages
    max_depth_value = int_option_value(max_depth) if max_depth is not None else policy.max_crawl_depth

    try:
        context = resolve_application_context(url, Path.cwd(), env_file_path, require_target=True)
    except ValueError as exc:
        if "No application target could be discovered." in str(exc):
            raise typer.BadParameter(str(exc)) from exc
        raise
    if context.target is None:
        raise typer.BadParameter("No scan target could be resolved.")
    if context.target.source == "discovery":
        console.print("No URL supplied. Discovery:")
        console.print(f"Discovery: {summarize_application_context(context)}")
        console.print(render_application_context(context))
    elif context.target.source != "command line":
        console.print(f"Using {context.target.key} from {context.target.source} for the crawl target.")

    try:
        if auth_config is None:
            result = crawl_target(
                context.target.value,
                timeout_seconds=timeout_seconds,
                max_pages=max_pages_value,
                max_crawl_depth=max_depth_value,
                same_host_only=same_host_only,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns,
                seed_robots=seed_robots,
                seed_sitemap=seed_sitemap,
            )
        else:
            result = crawl_target(
                context.target.value,
                timeout_seconds=timeout_seconds,
                max_pages=max_pages_value,
                max_crawl_depth=max_depth_value,
                same_host_only=same_host_only,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns,
                seed_robots=seed_robots,
                seed_sitemap=seed_sitemap,
                auth_config=auth_config,
            )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    result.context = context
    console.print(render_policy(policy))
    console.print(render_crawl_summary(result))
    console.print(render_console(result, include_fix_plans=False))
    write_audit_path = audit_log_path or Path(policy.audit_log_path)
    append_audit_event(write_audit_path, build_scan_audit_event(result, policy.allowed_fix_level, "crawl"))
    if audit_log_note is not None:
        console.print(f"[info] {audit_log_note}")
    for note in (json_output_note, markdown_output_note, html_output_note):
        if note is not None:
            console.print(f"[info] {note}")
    print_optional_output_notes()
    write_scan_outputs(
        result,
        False,
        json_output_path,
        markdown_output_path,
        html_output_path,
    )


@app.command(help="Run the local demo site for testing the scanner.")
def demo_site(port: int = typer.Option(8000, "--port", min=1, max=65535, help="Port for the local demo site")) -> None:
    serve_demo_site(port)


@app.command(help="Show the append-only audit history.")
def audit(
    policy_file: Path | None = typer.Option(None, "--policy", help="Load scan settings from a JSON file"),
    log_file: Path | None = typer.Option(None, "--audit-log", "--log-file", help="Read a specific audit log file"),
    last: int | None = typer.Option(None, "--last", min=1, help="Show only the newest N events"),
    event: str | None = typer.Option(None, "--event", help="Filter by action name"),
    target: str | None = typer.Option(None, "--target", help="Filter by target text"),
    json_output: Path | None = typer.Option(None, "--json-output", help="Write the filtered audit history to JSON"),
) -> None:
    policy = load_app_config(path_option_value(policy_file))
    log_path, log_note = normalize_output_option(path_option_value(log_file))
    log_path = log_path or Path(policy.audit_log_path)
    last_count = int_option_value(last)
    event_value = text_option_value(event)
    target_value = text_option_value(target)

    events = read_audit_events(log_path)
    events = filter_audit_events(events, action=event_value, target=target_value)
    if last_count is not None:
        events = events[-last_count:]

    console.print(render_audit_log(events))
    json_output_path, json_output_note = normalize_output_option(path_option_value(json_output))
    if json_output_path is not None:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_audit_events_json(json_output_path, events)
        if json_output_note is not None:
            console.print(f"[info] {json_output_note}")
        console.print(f"Wrote audit JSON to {json_output_path}")
    if log_note is not None:
        console.print(f"[info] {log_note}")
    print_optional_output_notes()
    console.print(f"Read audit log from {log_path}")


@app.command(help="Show a chronological timeline from a saved incident report and optional audit log.")
def timeline(
    incident_report: Path = typer.Argument(..., metavar="INCIDENT_REPORT", help="Saved incident report JSON file"),
    audit_log: Path | None = typer.Option(None, "--audit-log", help="Merge events from a specific audit log"),
    json_output: Path | None = typer.Option(None, "--json-output", help="Write the timeline report to JSON"),
    markdown_output: Path | None = typer.Option(None, "--markdown-output", help="Write the timeline report to Markdown"),
    html_output: Path | None = typer.Option(None, "--html-output", help="Write the timeline report to HTML"),
    webhook_url: list[str] = typer.Option([], "--webhook-url", help="Send the timeline summary to a generic webhook URL"),
    slack_webhook_url: list[str] = typer.Option([], "--slack-webhook-url", help="Send the timeline summary to a Slack incoming webhook"),
    discord_webhook_url: list[str] = typer.Option([], "--discord-webhook-url", help="Send the timeline summary to a Discord webhook"),
    email_to: list[str] = typer.Option([], "--email-to", help="Send the timeline summary to these email recipients"),
    email_from: str | None = typer.Option(None, "--email-from", help="Sender address for email notifications"),
    smtp_host: str | None = typer.Option(None, "--smtp-host", help="SMTP host for email notifications"),
    smtp_port: int = typer.Option(587, "--smtp-port", min=1, max=65535, help="SMTP port for email notifications"),
    smtp_username: str | None = typer.Option(None, "--smtp-username", help="SMTP username for email notifications"),
    smtp_password_env: str | None = typer.Option(None, "--smtp-password-env", help="Environment variable name for the SMTP password"),
    smtp_starttls: bool = typer.Option(True, "--smtp-starttls/--no-smtp-starttls", help="Use STARTTLS before SMTP auth"),
) -> None:
    audit_log_path = path_option_value(audit_log)
    timeline_report = load_timeline_report_from_path(incident_report, audit_log_path)
    console.print(render_timeline_report(timeline_report))

    webhook_urls = [str(value).strip() for value in list_option_value(webhook_url) if str(value).strip()]
    slack_webhook_urls = [str(value).strip() for value in list_option_value(slack_webhook_url) if str(value).strip()]
    discord_webhook_urls = [str(value).strip() for value in list_option_value(discord_webhook_url) if str(value).strip()]
    email_recipients = [str(value).strip() for value in list_option_value(email_to) if str(value).strip()]
    json_output_path, json_output_note = normalize_output_option(path_option_value(json_output))
    markdown_output_path, markdown_output_note = normalize_output_option(path_option_value(markdown_output))
    html_output_path, html_output_note = normalize_output_option(path_option_value(html_output))

    for note in (json_output_note, markdown_output_note, html_output_note):
        if note is not None:
            console.print(f"[info] {note}")
    send_notification_outputs(
        timeline_report,
        webhook_urls=webhook_urls,
        slack_webhook_urls=slack_webhook_urls,
        discord_webhook_urls=discord_webhook_urls,
        email_recipients=email_recipients,
        email_sender=email_from,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_username=smtp_username,
        smtp_password_env=smtp_password_env,
        root=Path.cwd(),
        use_starttls=smtp_starttls,
    )
    print_optional_output_notes()
    write_timeline_outputs(timeline_report, json_output_path, markdown_output_path, html_output_path)


@app.command(help="Check the local machine and app environment.")
def doctor(
    env_file: Path | None = typer.Option(None, "--env-file", help="Read local status defaults from a specific .env file"),
) -> None:
    report = run_doctor_checks(env_file=path_option_value(env_file))
    console.print(render_doctor_report(report))


@app.command(name="server-check", help="Check the server-facing config, discover the app target, and scan it locally.")
def server_check(
    env_file: Path | None = typer.Option(None, "--env-file", help="Read server defaults from a specific .env file"),
    nginx_config: Path | None = typer.Option(None, "--nginx-config", help="Check a specific Nginx config file"),
    timeout: float | None = typer.Option(None, "--timeout", min=0.1, help="Request and TLS timeout in seconds for the internal scan"),
    yes: bool = typer.Option(False, "--yes", help="Skip the permission prompt for trusted automation"),
) -> None:
    if not confirm_risky_command("server-check", assume_yes=yes):
        raise typer.Abort()

    env_file_path = path_option_value(env_file)
    nginx_config_path = path_option_value(nginx_config)
    report = run_server_checks(env_file=env_file_path, nginx_config=nginx_config_path)
    console.print(render_doctor_report(report))
    context = report.context
    if context is not None and context.target is not None:
        timeout_seconds = timeout_option_value(timeout)
        timeout_seconds = timeout_seconds if timeout_seconds is not None else 10.0
        console.print(f"Discovery: {summarize_application_context(context)}")
        console.print(f"Scanning discovered target: {context.target.value}")
        result = scan_target(context.target.value, timeout_seconds=timeout_seconds)
        console.print(render_console(result, include_fix_plans=False))


@app.command(help="Detect suspicious server or app activity from logs and optionally apply Nginx containment presets.")
def incident(
    url: str | None = typer.Argument(
        None,
        metavar="URL",
        help="Target URL. If omitted, Turan discovers the local app target before analyzing logs.",
    ),
    logs: Path | None = typer.Option(None, "--logs", help="Log file or directory to analyze"),
    live: bool = typer.Option(False, "--live", help="Capture a fresh snapshot from live log sources before analysis"),
    journal_unit: list[str] = typer.Option([], "--journal-unit", help="Collect recent journalctl output for a systemd unit"),
    event_log_name: list[str] = typer.Option([], "--event-log-name", help="Collect a Windows Event Log channel snapshot"),
    tail_file: list[Path] = typer.Option([], "--tail-file", help="Include the tail of a specific log file"),
    tail_lines: int = typer.Option(250, "--tail-lines", min=1, help="Number of recent lines to capture for live sources"),
    env_file: Path | None = typer.Option(None, "--env-file", help="Read local defaults from a specific .env file"),
    nginx_config: Path | None = typer.Option(None, "--nginx-config", help="Apply containment to a specific Nginx config file"),
    block_threshold: int = typer.Option(5, "--block-threshold", min=1, help="Score needed before an IP is auto-blocked"),
    apply_blocks: bool = typer.Option(False, "--apply-blocks/--no-apply-blocks", help="Write the denylist and include it when suspicious IPs are found"),
    yes: bool = typer.Option(False, "--yes", help="Skip the permission prompt for trusted automation"),
    policy_file: Path | None = typer.Option(None, "--policy", help="Load incident settings from a JSON file"),
    audit_log: Path | None = typer.Option(None, "--audit-log", help="Write audit events to a specific file"),
    json_output: Path | None = typer.Option(None, "--json-output", help="Write a JSON report"),
    markdown_output: Path | None = typer.Option(None, "--markdown-output", help="Write a Markdown report"),
    html_output: Path | None = typer.Option(None, "--html-output", help="Write an HTML report"),
    fail2ban_output: Path | None = typer.Option(None, "--fail2ban-output", help="Write a fail2ban-style filter and jail snippet"),
    rate_limit_output: Path | None = typer.Option(None, "--rate-limit-output", help="Write an Nginx rate-limit containment preset"),
    maintenance_output: Path | None = typer.Option(None, "--maintenance-output", help="Write an Nginx maintenance-mode containment preset"),
    bundle_output: Path | None = typer.Option(None, "--bundle-output", help="Bundle the report and containment artifacts into a ZIP archive"),
    webhook_url: list[str] = typer.Option([], "--webhook-url", help="Send the incident summary to a generic webhook URL"),
    slack_webhook_url: list[str] = typer.Option([], "--slack-webhook-url", help="Send the incident summary to a Slack incoming webhook"),
    discord_webhook_url: list[str] = typer.Option([], "--discord-webhook-url", help="Send the incident summary to a Discord webhook"),
    email_to: list[str] = typer.Option([], "--email-to", help="Send the incident summary to these email recipients"),
    email_from: str | None = typer.Option(None, "--email-from", help="Sender address for email notifications"),
    smtp_host: str | None = typer.Option(None, "--smtp-host", help="SMTP host for email notifications"),
    smtp_port: int = typer.Option(587, "--smtp-port", min=1, max=65535, help="SMTP port for email notifications"),
    smtp_username: str | None = typer.Option(None, "--smtp-username", help="SMTP username for email notifications"),
    smtp_password_env: str | None = typer.Option(None, "--smtp-password-env", help="Environment variable name for the SMTP password"),
    smtp_starttls: bool = typer.Option(True, "--smtp-starttls/--no-smtp-starttls", help="Use STARTTLS before SMTP auth"),
) -> None:
    if not confirm_risky_command("incident response", assume_yes=yes):
        raise typer.Abort()

    policy_file_path = path_option_value(policy_file)
    env_file_path = path_option_value(env_file)
    nginx_config_path = path_option_value(nginx_config)
    logs_path = path_option_value(logs)
    journal_unit_values = [str(value) for value in list_option_value(journal_unit) if str(value).strip()]
    event_log_name_values = [str(value) for value in list_option_value(event_log_name) if str(value).strip()]
    tail_file_values = [value for value in list_option_value(tail_file) if isinstance(value, Path)]
    tail_lines_value = int_option_value(tail_lines) or 250
    block_threshold_value = int_option_value(block_threshold) or 5
    audit_log_path, audit_log_note = normalize_output_option(path_option_value(audit_log))
    json_output_path, json_output_note = normalize_output_option(path_option_value(json_output))
    markdown_output_path, markdown_output_note = normalize_output_option(path_option_value(markdown_output))
    html_output_path, html_output_note = normalize_output_option(path_option_value(html_output))
    fail2ban_output_path, fail2ban_output_note = normalize_output_option(path_option_value(fail2ban_output))
    rate_limit_output_path, rate_limit_output_note = normalize_output_option(path_option_value(rate_limit_output))
    maintenance_output_path, maintenance_output_note = normalize_output_option(path_option_value(maintenance_output))
    bundle_output_path, bundle_output_note = normalize_output_option(path_option_value(bundle_output))
    webhook_urls = [str(value).strip() for value in list_option_value(webhook_url) if str(value).strip()]
    slack_webhook_urls = [str(value).strip() for value in list_option_value(slack_webhook_url) if str(value).strip()]
    discord_webhook_urls = [str(value).strip() for value in list_option_value(discord_webhook_url) if str(value).strip()]
    email_recipients = [str(value).strip() for value in list_option_value(email_to) if str(value).strip()]

    policy = load_app_config(policy_file_path)
    context = resolve_application_context(url, Path.cwd(), env_file_path, nginx_config_path, require_target=False)
    if context.target is None and context.discovery.discovered:
        console.print("No URL supplied. Discovery:")
        console.print(f"Discovery: {summarize_application_context(context)}")
        console.print(render_application_context(context))
    elif context.target is not None and context.target.source != "command line":
        console.print(f"Using {context.target.key} from {context.target.source} for the incident target.")

    if logs_path is None:
        sources = default_incident_sources(Path.cwd(), context.target.value if context.target is not None else url)
    else:
        sources = [logs_path]

    live_enabled = flag_is_enabled(live) or bool(journal_unit_values or event_log_name_values or tail_file_values)
    live_notes: list[str] = []
    if live_enabled:
        live_sources, live_notes = collect_live_incident_sources(
            root=Path.cwd(),
            line_count=tail_lines_value,
            journal_units=journal_unit_values,
            event_log_names=event_log_name_values,
            tail_files=tail_file_values,
        )
        sources.extend(live_sources)
        if live_notes:
            console.print(f"Live capture: {len(live_sources)} snapshot(s)")

    report = analyze_incident_sources(
        sources,
        root=Path.cwd(),
        url=str(context.target.value) if context.target is not None else url,
        block_threshold=block_threshold_value,
        env_file=env_file_path,
        nginx_config=nginx_config_path,
    )
    report.context = context
    if report.target is None and context.target is not None:
        report.target = str(context.target.value)
    if live_enabled:
        report.notes.extend(live_notes)

    console.print(render_incident_report(report))

    containment_result = None
    if apply_blocks and report.blocked_ips:
        if nginx_config_path is None:
            nginx_config_path = Path(context.discovery.nginx_config) if context.discovery.nginx_config is not None else None
        if nginx_config_path is None:
            console.print("No Nginx config was available for containment.")
        elif yes or typer.confirm("Apply the Nginx denylist containment now?", default=False):
            containment_result = apply_nginx_denylist(nginx_config_path, report.blocked_ips)
            console.print(render_local_fix_result(containment_result))
            report.containment_applied = containment_result.status == "applied"
            report.containment_target = str(nginx_config_path)
            denylist_path = nginx_config_path.with_name("incident-denylist.conf")
            report.containment_artifact = str(denylist_path)
            report.notes.append(containment_result.reason)
            if containment_result.backup_path:
                report.notes.append(f"Backup: {containment_result.backup_path}")
        else:
            report.notes.append("Containment was not applied.")

    if fail2ban_output_path is not None:
        write_fail2ban_artifact(report, fail2ban_output_path)
        report.containment_artifact = str(fail2ban_output_path)
        if report.blocked_ips:
            report.notes.append(f"Fail2ban-style artifact written to {fail2ban_output_path}")

    write_audit_path = audit_log_path or Path(policy.audit_log_path)
    append_audit_event(write_audit_path, build_incident_audit_event(report, policy.allowed_fix_level))
    if audit_log_note is not None:
        console.print(f"[info] {audit_log_note}")
    for note in (json_output_note, markdown_output_note, html_output_note, fail2ban_output_note, rate_limit_output_note, maintenance_output_note):
        if note is not None:
            console.print(f"[info] {note}")
    if bundle_output_path is None and report.containment_applied:
        bundle_output_path = default_output_path("incident", "--bundle-output")
        bundle_output_note = f"Using default output path for --bundle-output: {bundle_output_path.as_posix()}"
    if bundle_output_path is not None:
        primary_report_path = json_output_path
        if primary_report_path is None:
            primary_report_path = default_output_path("incident", "--json-output")
            write_json_incident_report(report, primary_report_path)
            console.print(f"Wrote JSON report to {primary_report_path}")
        bundle_items = [
            path
            for path in (
                json_output_path,
                markdown_output_path,
                html_output_path,
                fail2ban_output_path,
                rate_limit_output_path,
                maintenance_output_path,
            )
            if path is not None
        ]
        if report.containment_artifact:
            bundle_items.append(Path(report.containment_artifact))
        bundle_report = bundle_report_files(primary_report_path, output_path=bundle_output_path, extra_artifacts=bundle_items)
        console.print(render_bundle_report(bundle_report))
        console.print(f"Wrote ZIP bundle to {bundle_output_path}")
    if bundle_output_note is not None:
        console.print(f"[info] {bundle_output_note}")
    send_notification_outputs(
        report,
        webhook_urls=webhook_urls,
        slack_webhook_urls=slack_webhook_urls,
        discord_webhook_urls=discord_webhook_urls,
        email_recipients=email_recipients,
        email_sender=email_from,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_username=smtp_username,
        smtp_password_env=smtp_password_env,
        root=Path.cwd(),
        env_file=env_file_path,
        use_starttls=smtp_starttls,
    )
    print_optional_output_notes()
    write_incident_outputs(
        report,
        json_output_path,
        markdown_output_path,
        html_output_path,
        fail2ban_output_path,
        rate_limit_output_path,
        maintenance_output_path,
    )


@app.command(help="Monitor key files for integrity drift and compare them against a saved baseline.")
def integrity(
    root: Path | None = typer.Argument(
        None,
        metavar="ROOT",
        help="Directory to monitor. Defaults to the current working directory.",
    ),
    baseline: Path | None = typer.Option(None, "--baseline", help="Compare against a saved integrity snapshot"),
    path: list[Path] = typer.Option([], "--path", help="Add a specific file or directory to monitor"),
    audit_log: Path | None = typer.Option(None, "--audit-log", help="Write the integrity event to a specific audit log"),
    json_output: Path | None = typer.Option(None, "--json-output", help="Write a JSON report here"),
    markdown_output: Path | None = typer.Option(None, "--markdown-output", help="Write a Markdown report here"),
    html_output: Path | None = typer.Option(None, "--html-output", help="Write an HTML report here"),
    webhook_url: list[str] = typer.Option([], "--webhook-url", help="Send the integrity summary to a generic webhook URL"),
    slack_webhook_url: list[str] = typer.Option([], "--slack-webhook-url", help="Send the integrity summary to a Slack incoming webhook"),
    discord_webhook_url: list[str] = typer.Option([], "--discord-webhook-url", help="Send the integrity summary to a Discord webhook"),
    email_to: list[str] = typer.Option([], "--email-to", help="Send the integrity summary to these email recipients"),
    email_from: str | None = typer.Option(None, "--email-from", help="Sender address for email notifications"),
    smtp_host: str | None = typer.Option(None, "--smtp-host", help="SMTP host for email notifications"),
    smtp_port: int = typer.Option(587, "--smtp-port", min=1, max=65535, help="SMTP port for email notifications"),
    smtp_username: str | None = typer.Option(None, "--smtp-username", help="SMTP username for email notifications"),
    smtp_password_env: str | None = typer.Option(None, "--smtp-password-env", help="Environment variable name for the SMTP password"),
    smtp_starttls: bool = typer.Option(True, "--smtp-starttls/--no-smtp-starttls", help="Use STARTTLS before SMTP auth"),
) -> None:
    root_path = Path.cwd() if root is None else Path(root)
    baseline_path = path_option_value(baseline)
    extra_paths = [Path(item) for item in list_option_value(path)]
    audit_log_path, audit_log_note = normalize_output_option(path_option_value(audit_log))
    json_output_path, json_output_note = normalize_output_option(path_option_value(json_output))
    markdown_output_path, markdown_output_note = normalize_output_option(path_option_value(markdown_output))
    html_output_path, html_output_note = normalize_output_option(path_option_value(html_output))
    webhook_urls = [str(value).strip() for value in list_option_value(webhook_url) if str(value).strip()]
    slack_webhook_urls = [str(value).strip() for value in list_option_value(slack_webhook_url) if str(value).strip()]
    discord_webhook_urls = [str(value).strip() for value in list_option_value(discord_webhook_url) if str(value).strip()]
    email_recipients = [str(value).strip() for value in list_option_value(email_to) if str(value).strip()]

    report = analyze_integrity_sources(root_path, baseline_path=baseline_path, extra_paths=extra_paths)
    console.print(render_integrity_report(report))

    write_audit_path = audit_log_path or Path("outputs") / "audit.log"
    append_audit_event(write_audit_path, build_integrity_audit_event(report))

    if audit_log_note is not None:
        console.print(f"[info] {audit_log_note}")
    for note in (json_output_note, markdown_output_note, html_output_note):
        if note is not None:
            console.print(f"[info] {note}")
    send_notification_outputs(
        report,
        webhook_urls=webhook_urls,
        slack_webhook_urls=slack_webhook_urls,
        discord_webhook_urls=discord_webhook_urls,
        email_recipients=email_recipients,
        email_sender=email_from,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_username=smtp_username,
        smtp_password_env=smtp_password_env,
        root=Path.cwd(),
        use_starttls=smtp_starttls,
    )
    print_optional_output_notes()
    write_integrity_outputs(report, json_output_path, markdown_output_path, html_output_path)


@app.command(help="Detect baseline drift across saved reports for scan, integrity, incident, or doctor data.")
def drift(
    baseline_report: Path = typer.Argument(..., metavar="BASELINE_REPORT", help="Saved baseline report JSON file"),
    current_report: Path = typer.Argument(..., metavar="CURRENT_REPORT", help="Saved current report JSON file"),
    json_output: Path | None = typer.Option(None, "--json-output", help="Write a JSON drift report here"),
    markdown_output: Path | None = typer.Option(None, "--markdown-output", help="Write a Markdown drift report here"),
    html_output: Path | None = typer.Option(None, "--html-output", help="Write an HTML drift report here"),
) -> None:
    drift_report = analyze_report_drift(Path(baseline_report), Path(current_report))
    console.print(render_drift_report(drift_report))

    json_output_path, json_output_note = normalize_output_option(path_option_value(json_output))
    markdown_output_path, markdown_output_note = normalize_output_option(path_option_value(markdown_output))
    html_output_path, html_output_note = normalize_output_option(path_option_value(html_output))

    for note in (json_output_note, markdown_output_note, html_output_note):
        if note is not None:
            console.print(f"[info] {note}")
    print_optional_output_notes()
    write_drift_outputs(drift_report, json_output_path, markdown_output_path, html_output_path)


@app.command(help="Scan files for obvious secret exposure and redact the findings in the report output.")
def secrets(
    root: Path | None = typer.Argument(None, metavar="ROOT", help="Directory to scan. Defaults to the current working directory."),
    path: list[Path] = typer.Option([], "--path", help="Add a specific file or directory to scan"),
    json_output: Path | None = typer.Option(None, "--json-output", help="Write a JSON secret exposure report here"),
    markdown_output: Path | None = typer.Option(None, "--markdown-output", help="Write a Markdown secret exposure report here"),
    html_output: Path | None = typer.Option(None, "--html-output", help="Write an HTML secret exposure report here"),
) -> None:
    root_path = Path.cwd() if root is None else Path(root)
    extra_paths = [Path(item) for item in list_option_value(path)]
    report = analyze_secret_exposures(root_path, extra_paths=extra_paths)
    console.print(render_secret_report(report))

    json_output_path, json_output_note = normalize_output_option(path_option_value(json_output))
    markdown_output_path, markdown_output_note = normalize_output_option(path_option_value(markdown_output))
    html_output_path, html_output_note = normalize_output_option(path_option_value(html_output))

    for note in (json_output_note, markdown_output_note, html_output_note):
        if note is not None:
            console.print(f"[info] {note}")
    print_optional_output_notes()
    write_secret_outputs(report, json_output_path, markdown_output_path, html_output_path)


@app.command(help="Bundle a report and related artifacts into a ZIP archive.")
def bundle(
    report_file: Path = typer.Argument(..., metavar="REPORT_FILE", help="Primary report file to bundle"),
    artifact: list[Path] = typer.Option([], "--artifact", help="Extra artifact file or directory to include"),
    bundle_output: Path | None = typer.Option(None, "--bundle-output", help="Write the ZIP bundle here"),
) -> None:
    bundle_path, bundle_note = normalize_output_option(path_option_value(bundle_output))
    extra_artifacts = [Path(item) for item in list_option_value(artifact)]
    report_bundle = bundle_report_files(report_file, output_path=bundle_path, extra_artifacts=extra_artifacts)
    console.print(render_bundle_report(report_bundle))
    if bundle_note is not None:
        console.print(f"[info] {bundle_note}")


@app.command(help="Apply one real local fix to a discovered server file.")
def fix(
    local_fix: bool = typer.Option(False, "--local", help="Run the first real local fix lane"),
    url: str | None = typer.Argument(None, metavar="URL", help="Target URL. If omitted, Turan discovers the local app target."),
    env_file: Path | None = typer.Option(None, "--env-file", help="Read target defaults from a specific .env file"),
    nginx_config: Path | None = typer.Option(None, "--nginx-config", help="Check a specific Nginx config file"),
    timeout: float | None = typer.Option(None, "--timeout", min=0.1, help="Request and TLS timeout in seconds for the discovery scan"),
    policy_file: Path | None = typer.Option(None, "--policy", help="Load scan settings from a JSON file"),
    audit_log: Path | None = typer.Option(None, "--audit-log", help="Write audit events to a specific file"),
    yes: bool = typer.Option(False, "--yes", help="Skip the permission prompt for trusted automation"),
) -> None:
    if not local_fix:
        raise typer.BadParameter("Use --local for the first real local fix lane.")

    if not confirm_risky_command("local fix", assume_yes=yes):
        raise typer.Abort()

    policy_file_path = path_option_value(policy_file)
    env_file_path = path_option_value(env_file)
    nginx_config_path = path_option_value(nginx_config)
    audit_log_path, audit_log_note = normalize_output_option(path_option_value(audit_log))
    timeout_seconds_option = timeout_option_value(timeout)

    policy = load_app_config(policy_file_path)
    timeout_seconds = timeout_seconds_option if timeout_seconds_option is not None else policy.timeout_seconds
    context = resolve_application_context(url, Path.cwd(), env_file_path, nginx_config=nginx_config_path, require_target=True)
    if context.target is None:
        raise typer.BadParameter("No scan target could be resolved.")

    if context.target.source == "discovery":
        console.print("No URL supplied. Discovery:")
        console.print(f"Discovery: {summarize_application_context(context)}")
        console.print(render_application_context(context))
    elif context.target.source != "command line":
        console.print(f"Using {context.target.key} from {context.target.source} for the local fix scan target.")

    result = scan_target(context.target.value, timeout_seconds=timeout_seconds)
    result.context = context
    console.print(render_policy(policy))
    console.print(render_console(result, include_fix_plans=True))

    target_path = choose_local_fix_target(result)
    write_audit_path = audit_log_path or Path(policy.audit_log_path)
    if audit_log_note is not None:
        console.print(f"[info] {audit_log_note}")
    print_optional_output_notes()
    if target_path is None:
        local_fix_result = LocalFixResult(
            target_path=context.discovery.nginx_config or context.discovery.systemd_service or context.root,
            status="blocked",
            reason="No supported local fix target was discovered for the first live edit lane.",
            notes=["Turan found the server layout, but not a supported file to edit yet."],
        )
        console.print(render_local_fix_result(local_fix_result))
        append_audit_event(
            write_audit_path,
            build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
        )
        return

    if not target_path.exists():
        local_fix_result = LocalFixResult(
            target_path=str(target_path),
            status="blocked",
            reason="The discovered local fix target does not exist.",
            notes=["No file was changed."],
        )
        console.print(render_local_fix_result(local_fix_result))
        append_audit_event(
            write_audit_path,
            build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
        )
        return

    if not ask_to_create_backup():
        local_fix_result = LocalFixResult(
            target_path=str(target_path),
            status="skipped",
            reason="Backup declined.",
            notes=["No file was changed."],
        )
        console.print(render_local_fix_result(local_fix_result))
        append_audit_event(
            write_audit_path,
            build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
        )
        return

    try:
        backup_path = create_backup(target_path, target_path.parent)
    except PermissionError as exc:
        local_fix_result = LocalFixResult(
            target_path=str(target_path),
            status="blocked",
            reason=str(exc),
            notes=["No file was changed."],
        )
        console.print(render_local_fix_result(local_fix_result))
        append_audit_event(
            write_audit_path,
            build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
        )
        return
    console.print(f"Backup created before apply: {display_path_value(backup_path) or backup_path.as_posix()}")
    if not ask_to_apply_local_fix():
        local_fix_result = LocalFixResult(
            target_path=str(target_path),
            status="skipped",
            reason="Skipped by user.",
            notes=["No file was changed."],
        )
        console.print(render_local_fix_result(local_fix_result))
        append_audit_event(
            write_audit_path,
            build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
        )
        return

    console.print(f"Applying local fix to {target_path.as_posix()}")
    supported_categories = [finding.category for finding in result.findings if finding.category in {"server_info", "headers"}]
    local_fix_result = apply_local_nginx_hardening_fix(target_path, supported_categories, backup_path)
    console.print(render_local_fix_result(local_fix_result))
    append_audit_event(
        write_audit_path,
        build_local_fix_audit_event(str(context.target.value), local_fix_result, policy.allowed_fix_level),
    )


@app.command(help="Render or preview a saved scan report from disk.")
def report(
    report_file: Path,
    json_output: Path | None = typer.Option(None, "--json-output", help="Write a JSON report"),
    markdown_output: Path | None = typer.Option(None, "--markdown-output", help="Write a Markdown report"),
    html_output: Path | None = typer.Option(None, "--html-output", help="Write an HTML report"),
) -> None:
    report_path = path_option_value(report_file)
    suffix = report_path.suffix.lower()
    json_output_path, json_output_note = normalize_output_option(path_option_value(json_output))
    markdown_output_path, markdown_output_note = normalize_output_option(path_option_value(markdown_output))
    html_output_path, html_output_note = normalize_output_option(path_option_value(html_output))

    if suffix == ".json":
        result = load_scan_result(report_path)
        console.print(render_console(result, include_fix_plans=bool(result.fix_plans)))
        for note in (json_output_note, markdown_output_note, html_output_note):
            if note is not None:
                console.print(f"[info] {note}")
        print_optional_output_notes()
        write_scan_outputs(result, bool(result.fix_plans), json_output_path, markdown_output_path, html_output_path)
        return

    console.print(render_stored_report_preview(report_path))

    if suffix in {".md", ".markdown"} and markdown_output_path is not None:
        markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_output_path.write_text(report_path.read_text(encoding="utf-8"), encoding="utf-8")
        if markdown_output_note is not None:
            console.print(f"[info] {markdown_output_note}")
        console.print(f"Wrote Markdown report to {markdown_output_path}")

    if suffix in {".html", ".htm"} and html_output_path is not None:
        html_output_path.parent.mkdir(parents=True, exist_ok=True)
        html_output_path.write_text(report_path.read_text(encoding="utf-8"), encoding="utf-8")
        if html_output_note is not None:
            console.print(f"[info] {html_output_note}")
        console.print(f"Wrote HTML report to {html_output_path}")

    print_optional_output_notes()


@app.command(help="Save a scan snapshot as a baseline report.")
def baseline(
    url: str,
    timeout: float | None = typer.Option(None, "--timeout", min=0.1, help="Request and TLS timeout in seconds"),
    policy_file: Path | None = typer.Option(None, "--policy", help="Load scan settings from a JSON file"),
    audit_log: Path | None = typer.Option(None, "--audit-log", help="Write audit events to a specific file"),
    label: str | None = typer.Option(None, "--label", help="Save the baseline under a friendly name"),
    output: Path | None = typer.Option(None, "--output", help="Write the baseline JSON here"),
) -> None:
    label_value = text_option_value(label)
    output_path, output_note = normalize_output_option(path_option_value(output))
    audit_log_path, audit_log_note = normalize_output_option(path_option_value(audit_log))
    policy = load_app_config(path_option_value(policy_file))
    timeout_seconds = timeout_option_value(timeout)
    timeout_seconds = timeout_seconds if timeout_seconds is not None else policy.timeout_seconds
    resolved_context = resolve_application_context(url, Path.cwd(), None, require_target=True)
    result = scan_target(url, timeout_seconds=timeout_seconds)
    result.context = resolved_context
    result.baseline_label = label_value
    console.print(render_policy(policy))
    console.print(render_console(result, include_fix_plans=bool(result.fix_plans)))
    write_audit_path = audit_log_path or Path(policy.audit_log_path)
    append_audit_event(write_audit_path, build_scan_audit_event(result, policy.allowed_fix_level, "baseline"))
    if audit_log_note is not None:
        console.print(f"[info] {audit_log_note}")
    baseline_name = clean_file_label(label_value) if label_value else result.target.host
    baseline_path = output_path if output_path is not None else Path("baselines") / f"{baseline_name}.json"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    write_json_report(result, baseline_path)
    if audit_log_note is not None:
        console.print(f"[info] {audit_log_note}")
    if output_note is not None:
        console.print(f"[info] {output_note}")
    print_optional_output_notes()
    metadata = build_baseline_metadata(resolved_context, label_value)
    if metadata:
        metadata_path = write_baseline_metadata(baseline_path, metadata)
        console.print(f"Wrote baseline metadata to {metadata_path}")
        console.print(f"Discovery: {summarize_baseline_metadata(metadata)}")
    console.print(f"Wrote baseline to {baseline_path}")


def compare_outputs(
    comparison,
    markdown_output_path: Path | None,
    html_output_path: Path | None,
) -> None:
    if markdown_output_path is not None:
        markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_markdown_comparison_report(comparison, markdown_output_path)
        console.print(f"Wrote comparison Markdown report to {markdown_output_path}")

    if html_output_path is not None:
        html_output_path.parent.mkdir(parents=True, exist_ok=True)
        write_html_comparison_report(comparison, html_output_path)
        console.print(f"Wrote comparison HTML report to {html_output_path}")


@app.command(help="Compare two saved scan reports.")
def compare(
    old_report: Path,
    new_report: Path,
    markdown_output: Path | None = typer.Option(None, "--markdown-output", help="Write a Markdown comparison report"),
    html_output: Path | None = typer.Option(None, "--html-output", help="Write an HTML comparison report"),
) -> None:
    comparison = compare_scan_files(old_report, new_report)
    console.print(render_comparison(comparison))
    console.print(summarize_comparison(comparison))
    crawl_note = summarize_crawl_coverage_delta(comparison)
    if crawl_note is not None:
        console.print(f"[info] {crawl_note}")
    markdown_output_path, markdown_output_note = normalize_output_option(path_option_value(markdown_output))
    html_output_path, html_output_note = normalize_output_option(path_option_value(html_output))
    for note in (markdown_output_note, html_output_note):
        if note is not None:
            console.print(f"[info] {note}")
    print_optional_output_notes()
    compare_outputs(comparison, markdown_output_path, html_output_path)


if __name__ == "__main__":
    sys.argv, CLI_OPTIONAL_OUTPUT_NOTES = expand_optional_output_arguments(sys.argv)
    app()
