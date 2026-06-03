from __future__ import annotations

from html import escape
from pathlib import Path

from app.models import VulnerabilityReport
from app.reports.branding import report_css, write_branded_json


def write_json_vuln_report(report: VulnerabilityReport, output_path: str | Path) -> Path:
    return write_branded_json(report, output_path, "vulnerability_inventory")


def write_markdown_vuln_report(report: VulnerabilityReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    found = [component for component in report.components if component.status == "found"]
    lines = [
        "# PsyberShield Vulnerability Inventory",
        "",
        f"Root: {report.root}",
        f"Components found: {len(found)}",
        f"CVE matching: {'enabled' if report.cve_matching else 'not enabled'}",
        f"Findings: {len(report.findings)}",
        "",
        "## Vulnerability Findings",
        "",
    ]
    if report.findings:
        for finding in report.findings:
            lines.append(f"- [{finding.severity}] {finding.cve_id}: {finding.title}")
            lines.append(f"  - Component: {finding.component}")
            lines.append(f"  - Installed version: {finding.installed_version or '-'}")
            lines.append(f"  - Affected versions: {finding.affected_versions}")
            lines.append(f"  - Fixed version: {finding.fixed_version or '-'}")
            lines.append(f"  - CVSS: {finding.cvss if finding.cvss is not None else '-'}")
            lines.append(f"  - Source: {finding.source or '-'}")
            lines.append(f"  - Confidence: {finding.confidence}")
            lines.append(f"  - Reference: {finding.reference}")
            lines.append(f"  - Recommended action: {finding.recommended_action}")
    else:
        lines.append("- No advisory matches.")
    lines.extend(
        [
            "",
        "## Software Inventory",
        "",
        ]
    )
    if report.components:
        for component in report.components:
            lines.append(f"- [{component.status}] {component.name}")
            lines.append(f"  - Version: {component.version or '-'}")
            lines.append(f"  - Specifier: {component.version_specifier or '-'}")
            lines.append(f"  - Kind: {component.kind or '-'}")
            lines.append(f"  - Ecosystem: {component.ecosystem or '-'}")
            lines.append(f"  - Source: {component.source or '-'}")
            lines.append(f"  - Evidence: {component.evidence or '-'}")
    else:
        lines.append("- No components were checked.")
    if report.notes:
        lines.extend(["", "## Notes", ""])
        for note in report.notes:
            lines.append(f"- {note}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_vuln_report(report: VulnerabilityReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    found = [component for component in report.components if component.status == "found"]
    rows = []
    for component in report.components:
        rows.append(
            "<tr>"
            f"<td>{escape(component.status)}</td>"
            f"<td>{escape(component.name)}</td>"
            f"<td>{escape(component.version or '-')}</td>"
            f"<td>{escape(component.version_specifier or '-')}</td>"
            f"<td>{escape(component.kind or '-')}</td>"
            f"<td>{escape(component.ecosystem or '-')}</td>"
            f"<td>{escape(component.source or '-')}</td>"
            f"<td>{escape(component.evidence or '-')}</td>"
            "</tr>"
        )
    finding_rows = []
    for finding in report.findings:
        finding_rows.append(
            "<tr>"
            f"<td>{escape(finding.severity)}</td>"
            f"<td>{escape(finding.cve_id)}</td>"
            f"<td>{escape(finding.component)}</td>"
            f"<td>{escape(finding.installed_version or '-')}</td>"
            f"<td>{escape(finding.fixed_version or '-')}</td>"
            f"<td>{escape(finding.source or '-')}</td>"
            f"<td>{escape(finding.confidence)}</td>"
            f"<td>{escape(str(finding.cvss) if finding.cvss is not None else '-')}</td>"
            f"<td><a href='{escape(finding.reference)}'>{escape(finding.reference)}</a></td>"
            f"<td>{escape(finding.recommended_action)}</td>"
            "</tr>"
        )
    notes = "".join(f"<li>{escape(note)}</li>" for note in report.notes) or "<li>None</li>"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PsyberShield Vulnerability Inventory</title>
  <style>
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #101820; color: #eef5f7; }}
    .page {{ max-width: 1120px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero, .card {{ background: rgba(18, 31, 41, 0.94); border: 1px solid rgba(148, 163, 184, 0.22); border-radius: 10px; padding: 18px 20px; margin-bottom: 18px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid rgba(148, 163, 184, 0.2); vertical-align: top; }}
    th {{ background: rgba(5, 12, 18, 0.72); }}
    li {{ margin: 6px 0; }}
  </style>
  <style>{report_css()}</style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <h1>PsyberShield Vulnerability Inventory</h1>
      <p><strong>Root:</strong> {escape(report.root)}</p>
      <p><strong>Components found:</strong> {len(found)}</p>
      <p><strong>CVE matching:</strong> {'enabled' if report.cve_matching else 'not enabled'}</p>
      <p><strong>Findings:</strong> {len(report.findings)}</p>
    </div>
    <div class="card">
      <h2>Vulnerability Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>CVE</th><th>Component</th><th>Installed</th><th>Fixed</th><th>Source</th><th>Confidence</th><th>CVSS</th><th>Reference</th><th>Action</th></tr>
        </thead>
        <tbody>
          {"".join(finding_rows) or "<tr><td colspan='10'>No advisory matches.</td></tr>"}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Software Inventory</h2>
      <table>
        <thead>
          <tr><th>Status</th><th>Name</th><th>Version</th><th>Specifier</th><th>Kind</th><th>Ecosystem</th><th>Source</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {"".join(rows) or "<tr><td colspan='8'>No components were checked.</td></tr>"}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Notes</h2>
      <ul>{notes}</ul>
    </div>
  </div>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    return path
