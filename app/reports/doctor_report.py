from __future__ import annotations

from html import escape
from pathlib import Path

from app.doctor import DoctorReport


def write_json_doctor_report(report: DoctorReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def write_markdown_doctor_report(report: DoctorReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    lines = [
        "# PsyberShield Doctor Report",
        "",
        f"Root: {report.root}",
        f"OS: {report.os_name} {report.os_release}",
        f"Python: {report.python_version}",
        f"Readiness score: {report.readiness_score}%" if report.readiness_score is not None else "Readiness score: not calculated",
    ]
    if report.readiness_notes:
        lines.extend(["", "## Readiness Breakdown", ""])
        for note in report.readiness_notes:
            lines.append(f"- {note}")
    if report.context is not None:
        discovery = report.context.discovery
        lines.extend(
            [
                "",
                "## Application Context",
                "",
                f"- Root: {report.context.root}",
                f"- Target: {report.context.target.value if report.context.target else 'not resolved'}",
                f"- Target source: {report.context.target.source if report.context.target else 'not resolved'}",
                f"- Discovered app: {discovery.app_name or '-'}",
                f"- Public URL: {discovery.public_url or '-'}",
                f"- Local URL: {discovery.local_url or '-'}",
                f"- Env file: {discovery.env_file or '-'}",
                f"- Env source: {discovery.env_source or '-'}",
                f"- Nginx config: {discovery.nginx_config or '-'}",
                f"- Systemd service: {discovery.systemd_service or '-'}",
            ]
        )
        if discovery.notes:
            lines.append(f"- Notes: {'; '.join(discovery.notes)}")
    lines.extend(["", "## Checks", ""])
    if report.checks:
        for check in report.checks:
            lines.append(f"- [{check.status}] {check.name}: {check.summary}")
    else:
        lines.append("- No checks ran.")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_doctor_report(report: DoctorReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    notes = "".join(f"<li>{escape(note)}</li>" for note in report.readiness_notes) or "<li>None</li>"
    checks_rows = []
    for check in report.checks:
        details = "; ".join(f"{key}={value}" for key, value in check.details.items()) if check.details else "-"
        checks_rows.append(
            "<tr>"
            f"<td>{escape(check.name)}</td>"
            f"<td>{escape(check.status)}</td>"
            f"<td>{escape(check.summary)}</td>"
            f"<td>{escape(details)}</td>"
            "</tr>"
        )
    context_block = ""
    if report.context is not None:
        discovery = report.context.discovery
        context_block = f"""
        <div class="card">
          <h2>Application Context</h2>
          <p><strong>Root:</strong> {escape(report.context.root)}</p>
          <p><strong>Target:</strong> {escape(report.context.target.value if report.context.target else 'not resolved')}</p>
          <p><strong>Target source:</strong> {escape(report.context.target.source if report.context.target else 'not resolved')}</p>
          <p><strong>Discovered app:</strong> {escape(discovery.app_name or '-')}</p>
          <p><strong>Public URL:</strong> {escape(discovery.public_url or '-')}</p>
          <p><strong>Local URL:</strong> {escape(discovery.local_url or '-')}</p>
          <p><strong>Env file:</strong> {escape(discovery.env_file or '-')}</p>
          <p><strong>Env source:</strong> {escape(discovery.env_source or '-')}</p>
          <p><strong>Nginx config:</strong> {escape(discovery.nginx_config or '-')}</p>
          <p><strong>Systemd service:</strong> {escape(discovery.systemd_service or '-')}</p>
        </div>
        """
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PsyberShield Doctor Report</title>
  <style>
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif; background: #0b1020; color: #e5eefb; }}
    .page {{ max-width: 1120px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero, .card {{ background: rgba(15, 23, 42, 0.92); border: 1px solid rgba(148, 163, 184, 0.18); border-radius: 20px; padding: 18px 20px; margin-bottom: 18px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid rgba(148, 163, 184, 0.2); vertical-align: top; }}
    th {{ background: rgba(15, 23, 42, 0.9); }}
    li {{ margin: 6px 0; }}
  </style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <h1>PsyberShield Doctor Report</h1>
      <p><strong>Root:</strong> {escape(report.root)}</p>
      <p><strong>OS:</strong> {escape(f'{report.os_name} {report.os_release}')}</p>
      <p><strong>Python:</strong> {escape(report.python_version)}</p>
      <p><strong>Readiness score:</strong> {escape(f'{report.readiness_score}%') if report.readiness_score is not None else 'not calculated'}</p>
    </div>
    <div class="card">
      <h2>Readiness Breakdown</h2>
      <ul>{notes}</ul>
    </div>
    {context_block}
    <div class="card">
      <h2>Checks</h2>
      <table>
        <thead>
          <tr><th>Name</th><th>Status</th><th>Summary</th><th>Details</th></tr>
        </thead>
        <tbody>
          {"".join(checks_rows) or "<tr><td colspan='4'>No checks ran.</td></tr>"}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    return path
