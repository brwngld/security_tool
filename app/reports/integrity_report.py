from __future__ import annotations

from html import escape
from pathlib import Path

from app.models import IntegrityReport


def write_json_integrity_report(report: IntegrityReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def write_markdown_integrity_report(report: IntegrityReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    lines = [
        "# Turan Integrity Report",
        "",
        f"Root: {report.root}",
        f"Baseline: {report.baseline_path or 'not supplied'}",
        f"Monitored paths: {len(report.monitored_paths)}",
        f"Files tracked: {len(report.files)}",
        f"Findings: {len(report.findings)}",
        "",
        "## Summary",
        "",
        f"- Notes: {'; '.join(report.notes) if report.notes else '-'}",
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
    if report.findings:
        lines.extend(["", "## Findings", ""])
        for finding in report.findings:
            lines.append(f"- [{finding.severity}] {finding.title}")
            lines.append(f"  - Path: {finding.path}")
            lines.append(f"  - Category: {finding.category}")
            lines.append(f"  - Kind: {finding.kind}")
            lines.append(f"  - Confidence: {finding.confidence}")
            lines.append(f"  - Action: {finding.recommended_action}")
            if finding.evidence:
                lines.append(
                    f"  - Evidence: {', '.join(f'{key}={value}' for key, value in finding.evidence.items() if value not in (None, ''))}"
                )
    if report.files:
        lines.extend(["", "## Monitored Files", ""])
        for file_item in report.files[:80]:
            lines.append(f"- [{file_item.status}] {file_item.path}")
            lines.append(f"  - Category: {file_item.category}")
            lines.append(f"  - Kind: {file_item.kind}")
            if file_item.sha256:
                lines.append(f"  - SHA256: {file_item.sha256}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_integrity_report(report: IntegrityReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    finding_rows = []
    for finding in report.findings:
        evidence = ", ".join(
            f"{key}={value}" for key, value in finding.evidence.items() if value not in (None, "")
        )
        finding_rows.append(
            "<tr>"
            f"<td>{escape(finding.severity)}</td>"
            f"<td>{escape(finding.category)}</td>"
            f"<td>{escape(finding.kind)}</td>"
            f"<td>{escape(finding.path)}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.recommended_action)}</td>"
            f"<td>{escape(evidence or '-')}</td>"
            "</tr>"
        )

    file_rows = []
    for file_item in report.files:
        file_rows.append(
            "<tr>"
            f"<td>{escape(file_item.status)}</td>"
            f"<td>{escape(file_item.category)}</td>"
            f"<td>{escape(file_item.kind)}</td>"
            f"<td>{escape(file_item.path)}</td>"
            f"<td>{escape(file_item.sha256 or '-')}</td>"
            f"<td>{escape(str(file_item.size) if file_item.size is not None else '-')}</td>"
            f"<td>{escape(file_item.modified_at or '-')}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Turan Integrity Report</title>
  <style>
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
      color: #0f172a;
    }}
    .page {{ max-width: 1200px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero, .card {{
      background: rgba(255, 255, 255, 0.95);
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
      <h1>Turan Integrity Report</h1>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Root: {escape(report.root)}</p>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Baseline: {escape(report.baseline_path or 'not supplied')}</p>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Files tracked: {len(report.files)} | Findings: {len(report.findings)}</p>
    </div>
    <div class="card">
      <h2>Notes</h2>
      <ul>{''.join(f'<li>{escape(note)}</li>' for note in report.notes) or '<li>None</li>'}</ul>
    </div>
    <div class="card">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Category</th><th>Kind</th><th>Path</th><th>Title</th><th>Action</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {"".join(finding_rows) or "<tr><td colspan='7'>No findings</td></tr>"}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Monitored Files</h2>
      <table>
        <thead>
          <tr><th>Status</th><th>Category</th><th>Kind</th><th>Path</th><th>SHA256</th><th>Size</th><th>Modified</th></tr>
        </thead>
        <tbody>
          {"".join(file_rows) or "<tr><td colspan='7'>No monitored files</td></tr>"}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    return path
