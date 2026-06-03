import subprocess
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from app import main
from app.main import app
from app.models import SoftwareComponent, VulnerabilityReport
from app.vuln import match_local_advisories, scan_software_inventory


def test_scan_software_inventory_extracts_known_versions(workspace_temp_dir) -> None:
    outputs = {
        ("nginx", "-v"): subprocess.CompletedProcess(["nginx", "-v"], 0, "", "nginx version: nginx/1.24.0"),
        ("httpd", "-v"): subprocess.CompletedProcess(["httpd", "-v"], 1, "", ""),
        ("apache2", "-v"): subprocess.CompletedProcess(["apache2", "-v"], 1, "", ""),
        ("openssl", "version"): subprocess.CompletedProcess(["openssl", "version"], 0, "OpenSSL 3.2.1 30 Jan 2024", ""),
        ("python", "--version"): subprocess.CompletedProcess(["python", "--version"], 0, "Python 3.14.0", ""),
        ("node", "--version"): subprocess.CompletedProcess(["node", "--version"], 0, "v22.1.0", ""),
        ("npm", "--version"): subprocess.CompletedProcess(["npm", "--version"], 0, "10.7.0", ""),
        ("php", "-v"): subprocess.CompletedProcess(["php", "-v"], 0, "PHP 8.3.1 (cli)", ""),
    }

    def fake_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        key = tuple(command)
        if key not in outputs:
            raise FileNotFoundError(command[0])
        return outputs[key]

    report = scan_software_inventory(workspace_temp_dir, runner=fake_runner)

    versions = {component.name: component.version for component in report.components if component.status == "found"}
    assert versions["Nginx"] == "1.24.0"
    assert versions["OpenSSL"] == "3.2.1"
    assert versions["Python"] == "3.14.0"
    assert versions["Node.js"] == "22.1.0"
    assert report.cve_matching is True
    assert any("bundled offline advisory" in note for note in report.notes)


def test_match_local_advisories_flags_known_apache_and_openssl_versions() -> None:
    findings = match_local_advisories(
        [
            SoftwareComponent(name="Apache httpd", version="2.4.49", kind="web server", source="httpd -v"),
            SoftwareComponent(name="OpenSSL", version="3.0.6", kind="crypto library", source="openssl version"),
        ]
    )

    cves = {finding.cve_id for finding in findings}
    assert "CVE-2021-41773" in cves
    assert "CVE-2022-3602" in cves


def test_scan_software_inventory_can_disable_cve_matching(workspace_temp_dir) -> None:
    def fake_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if command == ["openssl", "version"]:
            return subprocess.CompletedProcess(command, 0, "OpenSSL 3.0.6 11 Oct 2022", "")
        raise FileNotFoundError(command[0])

    report = scan_software_inventory(workspace_temp_dir, runner=fake_runner, match_cves=False)

    assert report.cve_matching is False
    assert report.findings == []
    assert any("disabled" in note for note in report.notes)


def test_vuln_scan_command_renders_and_writes_outputs(monkeypatch, workspace_temp_dir) -> None:
    report = VulnerabilityReport(
        root=str(workspace_temp_dir),
        components=[
            SoftwareComponent(
                name="Nginx",
                version="1.24.0",
                kind="web server",
                source="nginx -v",
                status="found",
                evidence="nginx version: nginx/1.24.0",
            )
        ],
        findings=[],
        notes=["Inventory only."],
    )
    recorded_console = Console(record=True, width=120)
    output_calls = []
    audit_events = []

    monkeypatch.setattr(main, "console", recorded_console)
    monkeypatch.setattr(main, "scan_software_inventory", lambda root, match_cves=True: report)
    monkeypatch.setattr(main, "append_audit_event", lambda path, event: audit_events.append((Path(path), event)))
    monkeypatch.setattr(
        main,
        "write_vuln_outputs",
        lambda report, json_output_path, markdown_output_path, html_output_path: output_calls.append(
            (json_output_path, markdown_output_path, html_output_path)
        ),
    )

    main.vuln_scan(
        workspace_temp_dir,
        json_output=workspace_temp_dir / "outputs" / "vuln.json",
        markdown_output=workspace_temp_dir / "outputs" / "vuln.md",
        html_output=workspace_temp_dir / "outputs" / "vuln.html",
    )

    text = recorded_console.export_text()
    assert "PsyberShield Vulnerability Inventory" in text
    assert "Nginx" in text
    assert output_calls == [
        (
            workspace_temp_dir / "outputs" / "vuln.json",
            workspace_temp_dir / "outputs" / "vuln.md",
            workspace_temp_dir / "outputs" / "vuln.html",
        )
    ]
    assert audit_events[0][1].action == "vuln_scan"


def test_vuln_scan_help_is_available() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["vuln", "scan", "--help"])

    assert result.exit_code == 0
    assert "Inventory local software versions" in result.stdout
    assert "bundled offline advisories" in result.stdout
    assert "--inventory-only" in result.stdout
