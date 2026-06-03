from __future__ import annotations

from html import escape
from pathlib import Path

from app.models import DriftReport
from app.reports.branding import report_css, write_branded_json


def write_json_drift_report(report: DriftReport, output_path: str | Path) -> Path:
    return write_branded_json(report, output_path, "drift")


def write_markdown_drift_report(report: DriftReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    lines = [
        "# PsyberShield Drift Report",
        "",
        f"Report type: {report.report_type}",
        f"Baseline: {report.baseline_report}",
        f"Current: {report.current_report}",
        f"Summary: {report.summary}",
        "",
        "## Findings",
        "",
    ]
    if report.findings:
        for finding in report.findings:
            lines.append(f"- [{finding.severity}] {finding.category}: {finding.title}")
            lines.append(f"  - Baseline: {finding.baseline_value or '-'}")
            lines.append(f"  - Current: {finding.current_value or '-'}")
            if finding.note:
                lines.append(f"  - Note: {finding.note}")
    else:
        lines.append("- No drift detected")
    if report.notes:
        lines.extend(["", "## Notes", ""])
        for note in report.notes:
            lines.append(f"- {note}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_drift_report(report: DriftReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    rows = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            f"<td>{escape(finding.severity)}</td>"
            f"<td>{escape(finding.category)}</td>"
            f"<td>{escape(finding.kind)}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.baseline_value or '-')}</td>"
            f"<td>{escape(finding.current_value or '-')}</td>"
            f"<td>{escape(finding.note or '-')}</td>"
            "</tr>"
        )
    notes = "".join(f"<li>{escape(note)}</li>" for note in report.notes) or "<li>None</li>"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PsyberShield Drift Report</title>
  <style>
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif; background: #f8fafc; color: #0f172a; }}
    .page {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero, .card {{ background: white; border: 1px solid rgba(148, 163, 184, 0.18); border-radius: 20px; box-shadow: 0 12px 28px rgba(15, 23, 42, 0.06); padding: 18px 20px; margin-bottom: 18px; }}
    .hero {{ background: linear-gradient(135deg, #0f172a, #1e293b 60%, #0f766e); color: #f8fafc; }}
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
      <h1>PsyberShield Drift Report</h1>
      <p>Type: {escape(report.report_type)}</p>
      <p>Baseline: {escape(report.baseline_report)}</p>
      <p>Current: {escape(report.current_report)}</p>
      <p>{escape(report.summary)}</p>
    </div>
    <div class="card">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Category</th><th>Kind</th><th>Title</th><th>Baseline</th><th>Current</th><th>Note</th></tr>
        </thead>
        <tbody>
          {"".join(rows) or "<tr><td colspan='7'>No drift detected</td></tr>"}
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

