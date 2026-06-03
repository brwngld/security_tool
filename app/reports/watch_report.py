from __future__ import annotations

from html import escape
from pathlib import Path

from app.models import WatchReport
from app.reports.branding import report_css, write_branded_json


def _severity_rank(level: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(level, 5)


def _top_findings(report: WatchReport, limit: int = 5):
    return sorted(report.findings, key=lambda finding: (_severity_rank(finding.severity), finding.title))[:limit]


def _top_actions(report: WatchReport, limit: int = 5) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()
    for finding in _top_findings(report, limit=limit * 2):
        action = finding.recommended_action.strip()
        if action and action not in seen:
            seen.add(action)
            actions.append(action)
        if len(actions) >= limit:
            break
    return actions


def _top_categories(report: WatchReport, limit: int = 4):
    counts: dict[str, int] = {}
    for finding in report.findings:
        if finding.category:
            counts[finding.category] = counts.get(finding.category, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]


def write_json_watch_report(report: WatchReport, output_path: str | Path) -> Path:
    return write_branded_json(report, output_path, "watch")


def write_markdown_watch_report(report: WatchReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    lines = [
        "# PsyberShield Watch Report",
        "",
        f"Root: {report.root}",
        f"Mode: {report.mode}",
        f"Risk level: {report.risk_level}",
        f"Risk score: {report.risk_score}/100",
        f"Response: {report.response_label}",
        f"Compact: {'yes' if report.compact else 'no'}",
        f"Sources: {len(report.sources)}",
        f"Observations: {len(report.observations)}",
        f"Findings: {len(report.findings)}",
    ]
    if report.policy_path:
        lines.append(f"Policy: {report.policy_path}")
    if report.baseline_path:
        lines.append(f"Baseline: {report.baseline_path}")
    lines.extend(["", "## Response", ""])
    lines.append(f"- Recommended response: {report.response_label}")
    lines.append(f"- Risk score: {report.risk_score}/100")
    lines.append(f"- Risk level: {report.risk_level}")
    top_categories = _top_categories(report)
    if top_categories:
        lines.append(f"- Top categories: {', '.join(f'{category}={count}' for category, count in top_categories)}")
    top_actions = _top_actions(report)
    if top_actions:
        lines.append(f"- Top action: {top_actions[0]}")
    if report.findings:
        lines.extend(["", "## Top Risks", ""])
        for finding in _top_findings(report):
            lines.append(f"- [{finding.severity}] {finding.title}")
            lines.append(f"  - Source: {finding.source}")
            lines.append(f"  - Category: {finding.category}")
            lines.append(f"  - Recommended action: {finding.recommended_action or '-'}")
            if finding.evidence:
                lines.append(
                    f"  - Evidence: {', '.join(f'{key}={value}' for key, value in finding.evidence.items() if value not in (None, ''))}"
                )
    if top_actions:
        lines.extend(["", "## Recommended Next Actions", ""])
        for index, action in enumerate(top_actions, start=1):
            lines.append(f"{index}. {action}")
    if report.notes:
        lines.extend(["", "## Notes", ""])
        for note in report.notes:
            lines.append(f"- {note}")
    if report.observations:
        lines.extend(["", "## Observations", ""])
        for observation in report.observations:
            lines.append(f"- [{observation.status}] {observation.source} / {observation.kind}: {observation.summary}")
            if observation.details:
                lines.append(
                    f"  - Details: {', '.join(f'{key}={value}' for key, value in observation.details.items() if value not in (None, ''))}"
                )
    if report.findings:
        lines.extend(["", "## Findings", ""])
        for finding in report.findings:
            lines.append(f"- [{finding.severity}] {finding.title}")
            lines.append(f"  - Source: {finding.source}")
            lines.append(f"  - Category: {finding.category}")
            lines.append(f"  - Response: {finding.response_label}")
            lines.append(f"  - First move: {finding.recommended_action or '-'}")
            if finding.evidence:
                lines.append(
                    f"  - Evidence: {', '.join(f'{key}={value}' for key, value in finding.evidence.items() if value not in (None, ''))}"
                )
    if report.sources:
        lines.extend(["", "## Sources", ""])
        for source in report.sources:
            lines.append(f"- {source}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_watch_report(report: WatchReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    observation_rows = []
    for observation in report.observations:
        details = ", ".join(f"{key}={value}" for key, value in observation.details.items() if value not in (None, ""))
        observation_rows.append(
            "<tr>"
            f"<td>{escape(observation.source)}</td>"
            f"<td>{escape(observation.kind)}</td>"
            f"<td>{escape(observation.status)}</td>"
            f"<td>{escape(observation.summary)}</td>"
            f"<td>{escape(details or '-')}</td>"
            "</tr>"
        )

    finding_rows = []
    for finding in report.findings:
        evidence = ", ".join(f"{key}={value}" for key, value in finding.evidence.items() if value not in (None, ""))
        finding_rows.append(
            "<tr>"
            f"<td>{escape(finding.severity)}</td>"
            f"<td>{escape(finding.source)}</td>"
            f"<td>{escape(finding.category)}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.response_label)}</td>"
            f"<td>{escape(finding.recommended_action or '-')}</td>"
            f"<td>{escape(evidence or '-')}</td>"
            "</tr>"
        )

    note_items = "".join(f"<li>{escape(note)}</li>" for note in report.notes) or "<li>None</li>"
    source_items = "".join(f"<li>{escape(source)}</li>" for source in report.sources) or "<li>None</li>"
    top_actions = _top_actions(report)
    top_categories = _top_categories(report)
    top_risk_rows = []
    for finding in _top_findings(report):
        evidence = ", ".join(f"{key}={value}" for key, value in finding.evidence.items() if value not in (None, ""))
        top_risk_rows.append(
            "<tr>"
            f"<td class='severity-{escape(finding.severity)}'>{escape(finding.severity)}</td>"
            f"<td>{escape(finding.source)}</td>"
            f"<td>{escape(finding.category)}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td>{escape(finding.recommended_action or '-')}</td>"
            f"<td>{escape(evidence or '-')}</td>"
            "</tr>"
        )
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PsyberShield Watch Report</title>
  <style>
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background: linear-gradient(180deg, #020617 0%, #0f172a 35%, #f8fafc 35%, #eef2ff 100%);
      color: #0f172a;
    }}
    .page {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero {{
      background: linear-gradient(135deg, #020617, #1e293b 58%, #0f766e);
      color: #f8fafc;
      border-radius: 24px;
      padding: 24px;
      box-shadow: 0 28px 70px rgba(2, 6, 23, 0.34);
      margin-bottom: 18px;
    }}
    .card {{
      background: rgba(255, 255, 255, 0.94);
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 20px;
      padding: 18px 20px;
      margin-bottom: 18px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }}
    .metric {{
      background: #0f172a;
      color: #f8fafc;
      border-radius: 16px;
      padding: 14px 16px;
    }}
    .metric .label {{ color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; }}
    .metric .value {{ font-size: 1.2rem; font-weight: 700; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 16px; }}
    th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid rgba(148, 163, 184, 0.2); vertical-align: top; }}
    th {{ background: #e2e8f0; }}
    li {{ margin: 6px 0; }}
    .muted {{ color: #64748b; }}
    .severity-critical {{ background: #7f1d1d; color: #fff; font-weight: 700; }}
    .severity-high {{ background: #dc2626; color: #fff; font-weight: 700; }}
    .severity-medium {{ background: #f59e0b; color: #111827; font-weight: 700; }}
    .severity-low {{ background: #1d4ed8; color: #fff; font-weight: 700; }}
    .severity-info {{ background: #0f766e; color: #fff; font-weight: 700; }}
  </style>
  <style>{report_css()}</style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <h1>PsyberShield Watch Report</h1>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Root: {escape(report.root)}</p>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Mode: {escape(report.mode)} | Response: {escape(report.response_label)}</p>
      <p class="muted" style="color: rgba(248, 250, 252, 0.8);">Risk level: {escape(report.risk_level)} | Risk score: {report.risk_score}/100 | Findings: {len(report.findings)}</p>
      {f'<p class="muted" style="color: rgba(248, 250, 252, 0.8);">Baseline: {escape(report.baseline_path)}</p>' if report.baseline_path else ''}
    </div>
    <div class="card">
      <h2>Watch Status</h2>
      <div class="grid">
        <div class="metric"><div class="label">Risk</div><div class="value">{escape(report.risk_level.upper())}</div></div>
        <div class="metric"><div class="label">Response</div><div class="value">{escape(report.response_label)}</div></div>
        <div class="metric"><div class="label">Compact</div><div class="value">{'yes' if report.compact else 'no'}</div></div>
        <div class="metric"><div class="label">Top category</div><div class="value">{escape(', '.join(f'{category}={count}' for category, count in top_categories) if top_categories else '-')}</div></div>
      </div>
    </div>
    <div class="card">
      <h2>Sources</h2>
      <ul>{source_items}</ul>
    </div>
    <div class="card">
      <h2>Response</h2>
      <ul>
        <li>Recommended response: {escape(report.response_label)}</li>
        <li>Risk level: {escape(report.risk_level)}</li>
        <li>Risk score: {report.risk_score}/100</li>
        <li>Top categories: {escape(', '.join(f'{category}={count}' for category, count in top_categories) if top_categories else '-')}</li>
        <li>Top action: {escape(top_actions[0] if top_actions else '-')}</li>
      </ul>
    </div>
    <div class="card">
      <h2>Top Risks</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Source</th><th>Category</th><th>Title</th><th>Recommended action</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {"".join(top_risk_rows) or "<tr><td colspan='6'>No findings</td></tr>"}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Recommended Next Actions</h2>
      <ol>
        {''.join(f'<li>{escape(action)}</li>' for action in top_actions) or '<li>No action required</li>'}
      </ol>
    </div>
    <div class="card">
      <h2>Observations</h2>
      <table>
        <thead>
          <tr><th>Source</th><th>Kind</th><th>Status</th><th>Summary</th><th>Details</th></tr>
        </thead>
        <tbody>
          {"".join(observation_rows) or "<tr><td colspan='5'>No observations</td></tr>"}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Source</th><th>Category</th><th>Title</th><th>Response</th><th>First move</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {"".join(finding_rows) or "<tr><td colspan='7'>No findings</td></tr>"}
        </tbody>
      </table>
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
