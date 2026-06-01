from rich.console import Console

from app.comparison import compare_scan_files, compare_scan_results, summarize_comparison, summarize_crawl_coverage_delta
from app.models import Finding, ScanResult, Target
from app.reports.console import render_comparison
from app.reports.json_report import write_json_report


def build_old_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
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
            ),
            Finding(
                id="cookie-1",
                target_url="https://example.com",
                title="Weak cookie flags",
                description="A cookie is missing Secure or HttpOnly.",
                severity="medium",
                category="cookies",
                fix_level=0,
                risk_level="low",
                expected_impact="Set Secure and HttpOnly where the cookie is issued first.",
            ),
        ],
    )


def build_new_result() -> ScanResult:
    return ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        scanned_urls=["https://example.com/", "https://example.com/contact"],
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
            ),
            Finding(
                id="file-1",
                target_url="https://example.com",
                title="Exposed file: .env",
                description="The file is reachable from the web root.",
                severity="low",
                category="exposed_files",
                fix_level=0,
                risk_level="low",
                expected_impact="Remove the exposed file or block it at the web root first.",
            ),
        ],
    )


def test_compare_scan_results_reports_changes() -> None:
    comparison = compare_scan_results(build_old_result(), build_new_result(), "old.json", "new.json")

    assert comparison.old_risk_score == 4
    assert comparison.new_risk_score == 2
    assert comparison.risk_trend == "improved"
    assert [item.title for item in comparison.fixed_findings] == ["Weak cookie flags"]
    assert [item.title for item in comparison.new_findings] == ["Exposed file: .env"]
    assert [item.title for item in comparison.unchanged_findings] == ["Missing security header: x-content-type-options"]
    assert comparison.old_scanned_urls == ["https://example.com/", "https://example.com/about"]
    assert comparison.new_scanned_urls == ["https://example.com/", "https://example.com/contact"]
    assert comparison.added_scanned_urls == ["https://example.com/contact"]
    assert comparison.removed_scanned_urls == ["https://example.com/about"]
    assert (
        summarize_comparison(comparison)
        == "risk score improved (4 -> 2); 1 fixed, 1 new; crawl pages 2 -> 2 (1 added, 1 removed)."
    )
    assert summarize_crawl_coverage_delta(comparison) == "Crawl coverage changed: 1 added, 1 removed."


def test_compare_scan_files_loads_saved_reports(workspace_temp_dir) -> None:
    old_path = workspace_temp_dir / "old.json"
    new_path = workspace_temp_dir / "new.json"
    write_json_report(build_old_result(), old_path)
    write_json_report(build_new_result(), new_path)

    comparison = compare_scan_files(old_path, new_path)
    console = Console(record=True, width=100)
    console.print(render_comparison(comparison))
    text = console.export_text()

    assert "Report Comparison" in text
    assert "Fixed Findings" in text
    assert "New Findings" in text
    assert "improved" in text
    assert "Crawl Coverage" in text


def test_compare_command_prints_crawl_delta_note(monkeypatch, workspace_temp_dir) -> None:
    old_path = workspace_temp_dir / "old.json"
    new_path = workspace_temp_dir / "new.json"
    write_json_report(build_old_result(), old_path)
    write_json_report(build_new_result(), new_path)

    recorded_console = Console(record=True, width=100)
    monkeypatch.setattr("app.main.console", recorded_console)
    monkeypatch.setattr("app.main.compare_outputs", lambda *args, **kwargs: None)

    from app.main import compare as compare_command

    compare_command(old_path, new_path)

    text = recorded_console.export_text()
    assert "Crawl coverage changed: 1 added, 1 removed." in text
