from rich.console import Console

from app import main
from app.doctor import DoctorCheck, DoctorReport
from app.drift import analyze_report_drift
from app.models import Finding, IncidentReport, ReportBundle, ReportBundleItem, ScanResult, SecretExposureFinding, SecretExposureReport, Target
from app.reports.json_report import write_json_report


def test_analyze_report_drift_reports_scan_changes(workspace_temp_dir) -> None:
    baseline = ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        findings=[
            Finding(
                id="header-1",
                target_url="https://example.com",
                title="Missing security header: x-content-type-options",
                description="Missing header.",
                severity="low",
                category="headers",
                fix_level=0,
                risk_level="low",
                expected_impact="Add the header.",
            )
        ],
        scanned_urls=["https://example.com/"],
    )
    current = ScanResult(
        target=Target(url="https://example.com", scheme="https", host="example.com"),
        findings=[
            Finding(
                id="header-1",
                target_url="https://example.com",
                title="Missing security header: x-content-type-options",
                description="Missing header.",
                severity="low",
                category="headers",
                fix_level=0,
                risk_level="low",
                expected_impact="Add the header.",
            ),
            Finding(
                id="cookie-1",
                target_url="https://example.com",
                title="Weak cookie flags",
                description="Cookie is missing flags.",
                severity="medium",
                category="cookies",
                fix_level=0,
                risk_level="low",
                expected_impact="Set the flags.",
            ),
        ],
        scanned_urls=["https://example.com/", "https://example.com/account"],
    )

    baseline_path = workspace_temp_dir / "baseline.json"
    current_path = workspace_temp_dir / "current.json"
    write_json_report(baseline, baseline_path)
    write_json_report(current, current_path)

    report = analyze_report_drift(baseline_path, current_path)

    assert report.report_type == "scan"
    assert "risk score" in report.summary.lower()
    assert report.findings
    assert any(finding.category == "crawl" for finding in report.findings)


def test_drift_command_renders_and_writes_outputs(monkeypatch, workspace_temp_dir) -> None:
    baseline = DoctorReport(
        root=str(workspace_temp_dir),
        os_name="Windows",
        os_release="11",
        python_version="3.14.0",
        checks=[DoctorCheck(name="SECRET_KEY", status="ok", summary="present", details={"source": ".env"})],
    )
    current = DoctorReport(
        root=str(workspace_temp_dir),
        os_name="Windows",
        os_release="11",
        python_version="3.14.0",
        checks=[DoctorCheck(name="SECRET_KEY", status="warn", summary="present but weak", details={"source": ".env"})],
    )

    baseline_path = workspace_temp_dir / "baseline.json"
    current_path = workspace_temp_dir / "current.json"
    baseline_path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")
    current_path.write_text(current.model_dump_json(indent=2), encoding="utf-8")

    recorded_console = Console(record=True, width=120)
    output_calls = []
    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "write_drift_outputs", lambda report, json_output_path, markdown_output_path, html_output_path: output_calls.append((json_output_path, markdown_output_path, html_output_path)))

    main.drift(baseline_path, current_path, json_output=workspace_temp_dir / "outputs" / "drift.json")

    text = recorded_console.export_text()
    assert "Baseline Drift" in text
    assert "SECRET_KEY changed" in text
    assert output_calls


def test_analyze_report_drift_handles_sparse_incident_reports(workspace_temp_dir) -> None:
    baseline = IncidentReport(
        target="http://127.0.0.1:8000",
        source_files=[],
        findings=[],
        blocked_ips=[],
        notes=[],
    )
    current = IncidentReport(
        target="http://127.0.0.1:8000",
        source_files=[],
        findings=[],
        blocked_ips=["10.0.0.1"],
        notes=[],
    )

    baseline_path = workspace_temp_dir / "baseline-incident.json"
    current_path = workspace_temp_dir / "current-incident.json"
    baseline_path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")
    current_path.write_text(current.model_dump_json(indent=2), encoding="utf-8")

    report = analyze_report_drift(baseline_path, current_path)

    assert report.report_type == "incident"
    assert any(finding.category == "containment" for finding in report.findings)


def test_analyze_report_drift_handles_secret_reports(workspace_temp_dir) -> None:
    baseline = SecretExposureReport(
        root=str(workspace_temp_dir),
        source_files=[".env"],
        findings=[
            SecretExposureFinding(
                id="secret-1",
                path=".env",
                line_number=1,
                category="secrets",
                severity="medium",
                confidence="high",
                title="SECRET_KEY exposed",
                evidence={"path": ".env"},
                recommended_action="Rotate the key.",
            )
        ],
        notes=[],
    )
    current = SecretExposureReport(
        root=str(workspace_temp_dir),
        source_files=[".env", "config.py"],
        findings=[
            SecretExposureFinding(
                id="secret-1",
                path=".env",
                line_number=1,
                category="secrets",
                severity="medium",
                confidence="high",
                title="SECRET_KEY exposed",
                evidence={"path": ".env"},
                recommended_action="Rotate the key.",
            ),
            SecretExposureFinding(
                id="secret-2",
                path="config.py",
                line_number=4,
                category="secrets",
                severity="high",
                confidence="high",
                title="DATABASE_URL exposed",
                evidence={"path": "config.py"},
                recommended_action="Move credentials out of the file.",
            ),
        ],
        notes=[],
    )

    baseline_path = workspace_temp_dir / "baseline-secrets.json"
    current_path = workspace_temp_dir / "current-secrets.json"
    baseline_path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")
    current_path.write_text(current.model_dump_json(indent=2), encoding="utf-8")

    report = analyze_report_drift(baseline_path, current_path)

    assert report.report_type == "secrets"
    assert any(finding.kind == "secrets" for finding in report.findings)


def test_analyze_report_drift_handles_bundle_reports(workspace_temp_dir) -> None:
    baseline = ReportBundle(
        output_path=str(workspace_temp_dir / "bundle-old.zip"),
        source_report=str(workspace_temp_dir / "incident.json"),
        items=[
            ReportBundleItem(path=str(workspace_temp_dir / "incident.json"), arcname="incident.json", kind="report", size=128),
        ],
        notes=[],
    )
    current = ReportBundle(
        output_path=str(workspace_temp_dir / "bundle-new.zip"),
        source_report=str(workspace_temp_dir / "incident.json"),
        items=[
            ReportBundleItem(path=str(workspace_temp_dir / "incident.json"), arcname="incident.json", kind="report", size=128),
            ReportBundleItem(path=str(workspace_temp_dir / "incident-fail2ban.conf"), arcname="incident-fail2ban.conf", kind="artifact", size=64),
        ],
        notes=[],
    )

    baseline_path = workspace_temp_dir / "baseline-bundle.json"
    current_path = workspace_temp_dir / "current-bundle.json"
    baseline_path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")
    current_path.write_text(current.model_dump_json(indent=2), encoding="utf-8")

    report = analyze_report_drift(baseline_path, current_path)

    assert report.report_type == "bundle"
    assert any(finding.kind == "bundle" for finding in report.findings)
