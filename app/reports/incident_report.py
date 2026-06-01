from __future__ import annotations

from html import escape
from pathlib import Path

from app.models import IncidentReport


def write_json_incident_report(report: IncidentReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def write_markdown_incident_report(report: IncidentReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    lines = [
        "# Turan Incident Report",
        "",
        f"Target: {report.target or 'not resolved'}",
        f"Sources: {len(report.source_files)}",
        f"Findings: {len(report.findings)}",
        f"Blocked IPs: {len(report.blocked_ips)}",
        "",
        "## Summary",
        "",
        f"- Total log lines scanned: {report.total_lines}",
        f"- Suspect IPs: {', '.join(report.suspect_ips) if report.suspect_ips else '-'}",
        f"- Containment applied: {'yes' if report.containment_applied else 'no'}",
    ]
    if report.context is not None:
        discovery = report.context.discovery
        lines.extend(
            [
                "",
                "## Application Context",
                "",
                f"- Root: {report.context.root}",
                f"- Target source: {report.context.target.source if report.context.target else 'not resolved'}",
                f"- Local URL: {discovery.local_url or '-'}",
                f"- Nginx config: {discovery.nginx_config or '-'}",
                f"- Systemd service: {discovery.systemd_service or '-'}",
            ]
        )
    if report.source_files:
        lines.extend(["", "## Sources", ""])
        for source in report.source_files:
            lines.append(f"- {source}")
    if report.findings:
        lines.extend(["", "## Findings", ""])
        for finding in report.findings:
            lines.append(f"- [{finding.severity}] {finding.title}")
            lines.append(f"  - Category: {finding.category}")
            lines.append(f"  - Log family: {finding.log_family or '-'}")
            lines.append(f"  - Confidence: {finding.confidence}")
            lines.append(f"  - Source: {finding.source_file}")
            lines.append(f"  - Count: {finding.count}")
            lines.append(f"  - Action: {finding.recommended_action}")
            if finding.block_action:
                lines.append(f"  - Block: {finding.block_action}")
            if finding.affected_ips:
                lines.append(f"  - IPs: {', '.join(finding.affected_ips)}")
            if finding.evidence:
                lines.append(f"  - Evidence: {', '.join(f'{key}={value}' for key, value in finding.evidence.items() if value not in (None, ''))}")
    if report.blocked_ips:
        lines.extend(["", "## Containment", "", f"- Blocked IPs: {', '.join(report.blocked_ips)}"])
        if report.containment_target:
            lines.append(f"- Containment target: {report.containment_target}")
        if report.containment_artifact:
            lines.append(f"- Containment artifact: {report.containment_artifact}")
    if report.notes:
        lines.extend(["", "## Notes", ""])
        for note in report.notes:
            lines.append(f"- {note}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_incident_report(report: IncidentReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    rows = []
    for finding in report.findings:
        evidence = ", ".join(f"{key}={value}" for key, value in finding.evidence.items() if value not in (None, ""))
        rows.append(
            "<tr>"
            f"<td>{escape(finding.severity)}</td>"
            f"<td>{escape(finding.category)}</td>"
            f"<td>{escape(finding.log_family or '-')}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.source_file)}</td>"
            f"<td>{escape(finding.recommended_action)}</td>"
            f"<td>{escape(evidence or '-')}</td>"
            "</tr>"
        )

    source_items = "".join(f"<li>{escape(source)}</li>" for source in report.source_files) or "<li>None</li>"
    blocked_items = "".join(f"<li>{escape(ip)}</li>" for ip in report.blocked_ips) or "<li>None</li>"
    note_items = "".join(f"<li>{escape(note)}</li>" for note in report.notes) or "<li>None</li>"

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Turan Incident Report</title>
  <style>
    body {{
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      margin: 0;
      background: linear-gradient(180deg, #0f172a 0%, #111827 30%, #f8fafc 30%, #eef2ff 100%);
      color: #0f172a;
    }}
    .page {{ max-width: 1200px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero {{
      background: linear-gradient(135deg, #111827, #1f2937 55%, #0f766e);
      color: #f8fafc;
      border-radius: 24px;
      padding: 24px;
      box-shadow: 0 24px 56px rgba(15, 23, 42, 0.2);
      margin-bottom: 18px;
    }}
    .card {{
      background: rgba(255, 255, 255, 0.92);
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 20px;
      padding: 18px 20px;
      margin-bottom: 18px;
    }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 16px; }}
    th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid rgba(148, 163, 184, 0.2); vertical-align: top; }}
    th {{ background: #e2e8f0; }}
    li {{ margin: 6px 0; }}
    .muted {{ color: #64748b; }}
  </style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <h1>Turan Incident Report</h1>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Target: {escape(report.target or 'not resolved')}</p>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Findings: {len(report.findings)} | Blocked IPs: {len(report.blocked_ips)} | Containment applied: {'yes' if report.containment_applied else 'no'}</p>
    </div>
    <div class="card">
      <h2>Sources</h2>
      <ul>{source_items}</ul>
    </div>
    <div class="card">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Category</th><th>Log family</th><th>Title</th><th>Source</th><th>Action</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {"".join(rows) or "<tr><td colspan='7'>No findings</td></tr>"}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Containment</h2>
      <ul>
        <li>Blocked IPs: {', '.join(escape(ip) for ip in report.blocked_ips) if report.blocked_ips else 'None'}</li>
        <li>Containment target: {escape(report.containment_target or '-')}</li>
        <li>Containment artifact: {escape(report.containment_artifact or '-')}</li>
      </ul>
    </div>
    <div class="card">
      <h2>Notes</h2>
      <ul>{note_items}</ul>
    </div>
  </div>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    return path
