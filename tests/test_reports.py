from rich.console import Console

from app.context import ApplicationContext
from app.config import AppConfig
from app.models import Finding, FixPlan, ScanResult, Target
from app.reports.console import render_console, render_fix_decisions, render_policy, render_crawl_summary
from app.reports.json_report import write_json_report
from app.reports.markdown_report import write_markdown_report


def build_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        context=ApplicationContext(
            root="C:/workspace",
            target=None,
        ),
        findings=[
            Finding(
                id="f1",
                target_url="https://example.com",
                title="Missing security header: x-content-type-options",
                description="The response does not include the x-content-type-options header.",
                severity="low",
                category="headers",
                fix_level=0,
                risk_level="low",
                expected_impact="Report only.",
            )
        ],
        fix_plans=[
            FixPlan(
                finding_id="f1",
                fix_level=0,
                risk_level="low",
                expected_impact="Report only.",
            )
        ],
        tls_summary={"status": "ok", "expires_on": "2030-01-30"},
    )


def build_mixed_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        findings=[
            Finding(
                id="f1",
                target_url="https://example.com",
                title="Missing security header: x-content-type-options",
                description="The response does not include the x-content-type-options header.",
                severity="low",
                category="headers",
                fix_level=0,
                risk_level="low",
                expected_impact="Report only.",
            ),
            Finding(
                id="f2",
                target_url="https://example.com",
                title="Weak cookie flags",
                description="A cookie is missing Secure or HttpOnly.",
                severity="low",
                category="cookies",
                fix_level=0,
                risk_level="low",
                expected_impact="Report only.",
            ),
            Finding(
                id="f3",
                target_url="https://example.com",
                title="Exposed file: .env",
                description="The file is reachable from the web root.",
                severity="medium",
                category="exposed_files",
                fix_level=0,
                risk_level="low",
                expected_impact="Report only.",
            ),
        ],
        fix_plans=[],
        tls_summary={"status": "ok", "expires_on": "2030-01-30"},
    )


def build_crawl_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        findings=[
            Finding(
                id="f1",
                target_url="https://example.com/",
                affected_urls=["https://example.com/", "https://example.com/about"],
                title="Missing security header: x-content-type-options",
                description="The response does not include the x-content-type-options header.",
                severity="low",
                category="headers",
                fix_level=0,
                risk_level="low",
                expected_impact="Report only.",
            ),
            Finding(
                id="f2",
                target_url="https://example.com/about",
                affected_urls=["https://example.com/", "https://example.com/about"],
                title="Weak cookie flags",
                description="A cookie is missing Secure or HttpOnly.",
                severity="low",
                category="cookies",
                fix_level=0,
                risk_level="low",
                expected_impact="Report only.",
            ),
        ],
        fix_plans=[],
        scanned_urls=["https://example.com/", "https://example.com/about"],
        crawl_seed_sources=["robots.txt", "sitemap.xml", "page links"],
        tls_summary={"status": "ok", "expires_on": "2030-01-30"},
    )


def test_write_json_report_creates_file(workspace_temp_dir) -> None:
    result = build_result()
    output_path = write_json_report(result, workspace_temp_dir / "report.json")

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert '"target"' in text
    assert '"context"' in text


def test_write_markdown_report_creates_file(workspace_temp_dir) -> None:
    result = build_result()
    output_path = write_markdown_report(result, workspace_temp_dir / "report.md", include_fix_plans=True)

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "# PsyberShield Report" in text
    assert "## Executive Summary" in text
    assert "## Severity Guide" in text
    assert "## What to Fix First" in text
    assert "Expires on: 2030-01-30" in text
    assert "## Proposed Fixes" in text
    assert "## Application Context" in text
    assert "C:/workspace" in text


def test_write_markdown_report_includes_scanned_urls(workspace_temp_dir) -> None:
    result = build_result()
    result.scanned_urls = [
        "https://example.com/",
        "https://example.com/about",
    ]
    result.crawl_seed_sources = ["page links"]
    result.notes = [
        "Why these pages? PsyberShield starts at https://example.com/ and follows in-scope links until it reaches the crawl limits.",
        "Scope: same-host only, max depth 2, max pages 20.",
    ]
    output_path = write_markdown_report(result, workspace_temp_dir / "crawl.md")

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "## Scanned URLs" in text
    assert "https://example.com/about" in text
    assert "Seed sources: page links" in text
    assert "## Notes" in text
    assert "Why these pages?" in text


def test_write_markdown_report_groups_findings_by_page(workspace_temp_dir) -> None:
    result = build_crawl_result()
    output_path = write_markdown_report(result, workspace_temp_dir / "crawl-findings.md")

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "## Findings" in text
    assert "Affected URLs:" in text
    assert "1. https://example.com/" in text
    assert "2. https://example.com/about" in text
    assert "## Executive Summary" in text


def test_render_console_shows_findings_table() -> None:
    result = build_result()
    result.notes = [
        "Browser auth: started.",
        "Browser auth: password resolved from env-file (C:/workspace/.env).",
    ]
    console = Console(record=True, width=160)
    console.print(render_console(result, include_fix_plans=True))
    text = console.export_text()

    assert "PsyberShield Scan" in text
    assert "Findings" in text
    assert "Missing security header: x-content-type-options" in text
    assert "Evidence" in text
    assert "Proposed Fixes" in text
    assert "Severity counts" in text
    assert "Top categories" in text
    assert "Exposed files" in text
    assert "Browser auth: started." in text
    assert "Browser auth: password resolved from env-file" in text


def test_render_console_groups_crawl_findings_by_page() -> None:
    result = build_crawl_result()
    result.notes = [
        "Scope: same-host only, max depth 2, max pages 20.",
        "Discovery seeds: robots.txt, sitemap.xml, page links.",
        "Why these pages? PsyberShield starts at https://example.com/ and follows in-scope links until it reaches the crawl limits.",
    ]
    console = Console(record=True, width=180)
    console.print(render_crawl_summary(result))
    text = console.export_text()

    assert "Seed sources" in text
    assert "robots.txt" in text
    assert "sitemap.xml" in text
    assert "page links" in text
    assert "Scope" in text
    assert "Discovery" in text
    assert "Why these pages?" in text


def test_render_console_orders_top_categories() -> None:
    result = build_mixed_result()
    console = Console(record=True, width=180)
    console.print(render_console(result))
    text = console.export_text()
    summary_slice = text[text.index("Top categories") : text.index("Exposed files")]

    assert summary_slice.index("headers") < summary_slice.index("cookies") < summary_slice.index("exposed_files")


def test_render_console_orders_severity_chips() -> None:
    result = build_mixed_result()
    console = Console(record=True, width=180)
    console.print(render_console(result))
    text = console.export_text()
    summary_slice = text[text.index("Severity counts") : text.index("Top categories")]

    assert summary_slice.index("medium") < summary_slice.index("low")


def test_render_policy_shows_active_settings() -> None:
    policy = AppConfig(timeout_seconds=3.5, max_pages=25, max_crawl_depth=1)
    console = Console(record=True, width=100)
    console.print(render_policy(policy))
    text = console.export_text()

    assert "Active Policy" in text
    assert "Allowed fix level" in text
    assert "3.5s" in text
    assert "Redact reports" in text
    assert "Redact logs" in text


def test_render_fix_decisions_shows_apply_plan() -> None:
    result = build_result()
    decision = type(
        "Decision",
        (),
            {
                "finding_title": result.findings[0].title,
                "confidence_label": "Report only",
                "status": "ready",
                "next_step": "Add header",
                "reason": "Policy allows this plan.",
                "backup_path": "outputs/backups/f1.conf.bak",
                "artifact_path": "outputs/generated/f1.conf",
            },
        )()
    console = Console(record=True, width=180)
    console.print(render_fix_decisions([decision]))
    text = console.export_text()

    assert "Apply Plan" in text
    assert "Report only" in text
    assert "ready" in text
    assert "Add header" in text
    assert "outputs/backups/f1.conf.bak" in text
    assert "outputs/generated/f1.conf" in text
