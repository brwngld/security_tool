from app.context import ApplicationContext
from app.models import Finding, FixPlan, ScanResult, Target
from app.reports.html_report import write_html_report


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
                evidence={"header": "x-content-type-options"},
            )
        ],
        fix_plans=[
            FixPlan(
                finding_id="f1",
                fix_level=0,
                risk_level="low",
                expected_impact="Add x-content-type-options.",
                rollback_command="Restore header config.",
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
                evidence={"header": "x-content-type-options"},
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
                evidence={"set_cookie": "session=abc"},
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
                evidence={"path": ".env"},
            ),
        ],
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
                evidence={"header": "x-content-type-options"},
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
                evidence={"set_cookie": "session=abc"},
            ),
        ],
        scanned_urls=["https://example.com/", "https://example.com/about"],
        crawl_seed_sources=["robots.txt", "sitemap.xml", "page links"],
        notes=[
            "Why these pages? PsyberShield starts at https://example.com/ and follows in-scope links until it reaches the crawl limits.",
            "Scope: same-host only, max depth 2, max pages 20.",
            "Discovery seeds: robots.txt, sitemap.xml, page links.",
        ],
        tls_summary={"status": "ok", "expires_on": "2030-01-30"},
    )


def test_write_html_report_creates_file(workspace_temp_dir) -> None:
    result = build_result()
    output_path = write_html_report(result, workspace_temp_dir / "report.html", include_fix_plans=True)

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "<title>PsyberShield Deployment Readiness Review</title>" in text
    assert "Executive Summary" in text
    assert "Severity Guide" in text
    assert "What to Fix First" in text
    assert "Action Queue" in text
    assert "Missing security header: x-content-type-options" in text
    assert "First Move" in text
    assert "Nginx" in text
    assert "headers" in text
    assert "1" in text
    assert "severity" in text.lower()
    assert "Application Context" in text
    assert "C:/workspace" in text


def test_write_html_report_orders_category_chips(workspace_temp_dir) -> None:
    result = build_mixed_result()
    output_path = write_html_report(result, workspace_temp_dir / "mixed.html")
    text = output_path.read_text(encoding="utf-8")

    assert text.index("headers") < text.index("cookies") < text.index("exposed_files")


def test_write_html_report_groups_findings_by_page(workspace_temp_dir) -> None:
    result = build_crawl_result()
    output_path = write_html_report(result, workspace_temp_dir / "crawl.html")
    text = output_path.read_text(encoding="utf-8")

    assert "Affected URLs" in text
    assert "Confidence" in text
    assert "https://example.com/" in text
    assert "https://example.com/about" in text
    assert "Seed sources: robots.txt, sitemap.xml, page links" in text
    assert "Notes" in text
    assert "Why these pages?" in text
    assert "Executive Summary" in text
