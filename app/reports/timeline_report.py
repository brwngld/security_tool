from __future__ import annotations

from html import escape
from pathlib import Path

from app.models import TimelineReport


def write_json_timeline_report(report: TimelineReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def write_markdown_timeline_report(report: TimelineReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    lines = [
        "# PsyberShield Timeline",
        "",
        f"Incident report: {report.incident_report or '-'}",
        f"Audit log: {report.audit_log or '-'}",
        f"Events: {len(report.events)}",
        "",
        "## Timeline",
        "",
    ]
    if report.events:
        for event in report.events:
            timestamp = event.timestamp or "-"
            source = f" ({event.source})" if event.source else ""
            lines.append(f"- {timestamp} [{event.kind}] {event.title}{source}")
            if event.details:
                lines.append(
                    f"  - Details: {', '.join(f'{key}={value}' for key, value in event.details.items() if value not in (None, ''))}"
                )
    else:
        lines.append("- No events available")
    if report.notes:
        lines.extend(["", "## Notes", ""])
        for note in report.notes:
            lines.append(f"- {note}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_timeline_report(report: TimelineReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    rows = []
    for event in report.events:
        details = ", ".join(f"{key}={value}" for key, value in event.details.items() if value not in (None, ""))
        rows.append(
            "<tr>"
            f"<td>{escape(event.timestamp or '-')}</td>"
            f"<td>{escape(event.kind)}</td>"
            f"<td>{escape(event.title)}</td>"
            f"<td>{escape(event.source or '-')}</td>"
            f"<td>{escape(details or '-')}</td>"
            "</tr>"
        )

    notes = "".join(f"<li>{escape(note)}</li>" for note in report.notes) or "<li>None</li>"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PsyberShield Timeline</title>
  <style>
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
      color: #0f172a;
    }}
    .page {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero, .card {{
      background: rgba(255, 255, 255, 0.96);
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 20px;
      box-shadow: 0 12px 28px rgba(15, 23, 42, 0.06);
      padding: 18px 20px;
      margin-bottom: 18px;
    }}
    .hero {{
      background: linear-gradient(135deg, #0f172a, #1e293b 60%, #0f766e);
      color: #f8fafc;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid rgba(148, 163, 184, 0.2); vertical-align: top; }}
    th {{ background: #e2e8f0; }}
    li {{ margin: 6px 0; }}
    .muted {{ color: #64748b; }}
  </style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <h1>PsyberShield Timeline</h1>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Incident report: {escape(report.incident_report or '-')}</p>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Audit log: {escape(report.audit_log or '-')}</p>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Events: {len(report.events)}</p>
    </div>
    <div class="card">
      <h2>Chronology</h2>
      <table>
        <thead>
          <tr><th>Timestamp</th><th>Kind</th><th>Title</th><th>Source</th><th>Details</th></tr>
        </thead>
        <tbody>
          {"".join(rows) or "<tr><td colspan='5'>No events</td></tr>"}
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
