from __future__ import annotations

from html import escape
from pathlib import Path

from app.models import SecretExposureReport
from app.reports.branding import report_css, write_branded_json


def write_json_secret_report(report: SecretExposureReport, output_path: str | Path) -> Path:
    return write_branded_json(report, output_path, "secrets")


def write_markdown_secret_report(report: SecretExposureReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    lines = [
        "# PsyberShield Secret Exposure Report",
        "",
        f"Root: {report.root}",
        f"Source files: {len(report.source_files)}",
        f"Findings: {len(report.findings)}",
        "",
        "## Findings",
        "",
    ]
    if report.findings:
        for finding in report.findings:
            lines.append(f"- [{finding.severity}] {finding.path}:{finding.line_number} {finding.title}")
            lines.append(f"  - Category: {finding.category}")
            lines.append(f"  - Action: {finding.recommended_action}")
            if finding.evidence:
                lines.append(
                    f"  - Evidence: {', '.join(f'{key}={value}' for key, value in finding.evidence.items() if value not in (None, ''))}"
                )
    else:
        lines.append("- No obvious secret exposure was detected.")
    if report.notes:
        lines.extend(["", "## Notes", ""])
        for note in report.notes:
            lines.append(f"- {note}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_secret_report(report: SecretExposureReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    rows = []
    for finding in report.findings:
        evidence = ", ".join(f"{key}={value}" for key, value in finding.evidence.items() if value not in (None, ""))
        rows.append(
            "<tr>"
            f"<td>{escape(finding.severity)}</td>"
            f"<td>{escape(finding.category)}</td>"
            f"<td>{escape(finding.path)}</td>"
            f"<td>{escape(str(finding.line_number))}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.recommended_action)}</td>"
            f"<td>{escape(evidence or '-')}</td>"
            "</tr>"
        )
    notes = "".join(f"<li>{escape(note)}</li>" for note in report.notes) or "<li>None</li>"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PsyberShield Secret Exposure Report</title>
  <style>
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif; background: #f8fafc; color: #0f172a; }}
    .page {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero, .card {{ background: white; border: 1px solid rgba(148, 163, 184, 0.18); border-radius: 20px; box-shadow: 0 12px 28px rgba(15, 23, 42, 0.06); padding: 18px 20px; margin-bottom: 18px; }}
    .hero {{ background: linear-gradient(135deg, #111827, #1f2937 55%, #7c2d12); color: #f8fafc; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid rgba(148, 163, 184, 0.2); vertical-align: top; }}
    th {{ background: #e2e8f0; }}
    li {{ margin: 6px 0; }}
  </style>
  <style>{report_css()}</style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <h1>PsyberShield Secret Exposure Report</h1>
      <p>Root: {escape(report.root)}</p>
      <p>Findings: {len(report.findings)}</p>
    </div>
    <div class="card">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Category</th><th>Path</th><th>Line</th><th>Title</th><th>Action</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {"".join(rows) or "<tr><td colspan='7'>No obvious secret exposure detected</td></tr>"}
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
