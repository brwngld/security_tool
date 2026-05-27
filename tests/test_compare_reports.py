from app.comparison import compare_scan_results
from app.context import ApplicationContext
from app.models import Finding, ScanResult, Target
from app.reports.comparison_report import write_html_comparison_report, write_markdown_comparison_report


def build_old_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        context=ApplicationContext(root="C:/workspace/old", target=None),
        scanned_urls=["https://example.com/", "https://example.com/about"],
        findings=[
            Finding(
                id="header-1",
                target_url="https://example.com",
                title="Missing security header: x-content-type-options",
                description="The response does not include the x-content-type-options header.",
                severity="low",
                category="headers",
                fix_level=0,
                risk_level="low",
                expected_impact="Add the missing header in the reverse proxy first.",
            )
        ],
    )


def build_new_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        context=ApplicationContext(root="C:/workspace/new", target=None),
        scanned_urls=["https://example.com/", "https://example.com/contact"],
        findings=[
            Finding(
                id="file-1",
                target_url="https://example.com",
                title="Exposed file: .env",
                description="The file is reachable from the web root.",
                severity="medium",
                category="exposed_files",
                fix_level=0,
                risk_level="low",
                expected_impact="Remove the exposed file or block it at the web root first.",
            )
        ],
    )


def test_write_markdown_comparison_report_creates_file(workspace_temp_dir) -> None:
    comparison = compare_scan_results(build_old_result(), build_new_result(), "old.json", "new.json")
    output_path = write_markdown_comparison_report(comparison, workspace_temp_dir / "compare.md")

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "# Turan Comparison" in text
    assert "## Comparison Context" in text
    assert "## Crawl Coverage" in text
    assert "Risk trend: worsened" in text
    assert "## New findings" in text


def test_write_html_comparison_report_creates_file(workspace_temp_dir) -> None:
    comparison = compare_scan_results(build_old_result(), build_new_result(), "old.json", "new.json")
    output_path = write_html_comparison_report(comparison, workspace_temp_dir / "compare.html")

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "Turan Comparison" in text
    assert "Comparison Context" in text
    assert "Crawl Coverage" in text
    assert "Fixed findings" in text
    assert "New findings" in text
