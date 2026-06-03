from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, select_autoescape

from app.models import ComparisonResult
from app.reports.branding import report_css

_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PsyberShield Comparison</title>
  <style>
    :root {
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --line: rgba(148, 163, 184, 0.2);
      --accent: #0284c7;
      --good: #10b981;
      --bad: #dc2626;
      --chip: #e2e8f0;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background: linear-gradient(180deg, #ffffff 0%, var(--bg) 100%);
      color: var(--text);
    }
    .page { max-width: 1100px; margin: 0 auto; padding: 32px 20px 48px; }
    .hero, .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      box-shadow: 0 12px 28px rgba(15, 23, 42, 0.06);
    }
    .hero { padding: 24px; margin-bottom: 18px; }
    .title { margin: 0; font-size: 2rem; }
    .subtitle { margin: 8px 0 0; color: var(--muted); }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border-radius: 999px;
      padding: 6px 12px;
      background: var(--chip);
      font-weight: 700;
      font-size: 0.88rem;
    }
    .chip-good { background: rgba(16, 185, 129, 0.12); color: #047857; }
    .chip-bad { background: rgba(220, 38, 38, 0.12); color: #b91c1c; }
    .chip-neutral { background: rgba(100, 116, 139, 0.12); color: #334155; }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin-top: 14px;
    }
    .metric {
      padding: 12px 14px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: #f8fafc;
    }
    .metric-label {
      display: block;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-bottom: 4px;
      font-weight: 700;
    }
    .metric-value {
      display: block;
      font-size: 0.98rem;
      font-weight: 700;
      word-break: break-word;
    }
    .card { padding: 18px 20px; margin: 18px 0; }
    .section-label {
      display: inline-block;
      margin-bottom: 12px;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent);
      font-weight: 800;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 14px;
    }
    th, td {
      text-align: left;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }
    th {
      background: #f8fafc;
      color: var(--text);
      font-size: 0.92rem;
    }
    tr:last-child td { border-bottom: 0; }
    .empty {
      margin-top: 8px;
      padding: 14px 16px;
      border-radius: 12px;
      border: 1px dashed var(--line);
      color: var(--muted);
      background: #f8fafc;
    }
    .trend-good { color: var(--good); font-weight: 700; }
    .trend-bad { color: var(--bad); font-weight: 700; }
  </style>
  <style>{{ report_css() }}</style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <h1 class="title">PsyberShield Comparison</h1>
      <p class="subtitle">{{ comparison.old_report }} → {{ comparison.new_report }}</p>
      <div class="chips">
        <span class="chip chip-good">Fixed {{ comparison.fixed_findings|length }}</span>
        <span class="chip chip-bad">New {{ comparison.new_findings|length }}</span>
        <span class="chip">Risk {{ comparison.old_risk_score }} → {{ comparison.new_risk_score }}</span>
        <span class="chip">{% if comparison.risk_trend == "improved" %}<span class="trend-good">Improved</span>{% elif comparison.risk_trend == "worsened" %}<span class="trend-bad">Worsened</span>{% else %}Unchanged{% endif %}</span>
      </div>
    </div>

    <div class="card">
      <div class="section-label">Comparison Context</div>
      <div class="summary-grid">
        <div class="metric"><span class="metric-label">Old context</span><span class="metric-value">{{ comparison.old_context.discovery.app_name if comparison.old_context and comparison.old_context.discovery.app_name else "not captured" }}</span></div>
        <div class="metric"><span class="metric-label">New context</span><span class="metric-value">{{ comparison.new_context.discovery.app_name if comparison.new_context and comparison.new_context.discovery.app_name else "not captured" }}</span></div>
        <div class="metric"><span class="metric-label">Context detail</span><span class="metric-value">{{ comparison.context_changes[0] if comparison.context_changes else "unchanged" }}</span></div>
      </div>
    </div>

    <div class="card">
      <div class="section-label">Crawl Coverage</div>
      <div class="summary-grid">
        <div class="metric"><span class="metric-label">Old URLs</span><span class="metric-value">{{ comparison.old_scanned_urls|length }}</span></div>
        <div class="metric"><span class="metric-label">New URLs</span><span class="metric-value">{{ comparison.new_scanned_urls|length }}</span></div>
        <div class="metric"><span class="metric-label">Added URLs</span><span class="metric-value">{{ comparison.added_scanned_urls|length }}</span></div>
        <div class="metric"><span class="metric-label">Removed URLs</span><span class="metric-value">{{ comparison.removed_scanned_urls|length }}</span></div>
      </div>
      {% if comparison.added_scanned_urls %}
      <div class="empty" style="margin-top: 12px;">Added: {{ comparison.added_scanned_urls | join(", ") }}</div>
      {% endif %}
      {% if comparison.removed_scanned_urls %}
      <div class="empty" style="margin-top: 12px;">Removed: {{ comparison.removed_scanned_urls | join(", ") }}</div>
      {% endif %}
      {% if not comparison.added_scanned_urls and not comparison.removed_scanned_urls %}
      <div class="empty" style="margin-top: 12px;">Crawl coverage stayed the same.</div>
      {% endif %}
    </div>

    <div class="card">
      <div class="section-label">Fixed findings</div>
      {% if comparison.fixed_findings %}
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Severity</th>
            <th>Title</th>
          </tr>
        </thead>
        <tbody>
          {% for finding in comparison.fixed_findings %}
          <tr>
            <td>{{ finding.category }}</td>
            <td>{{ finding.severity }}</td>
            <td>{{ finding.title }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="empty">No findings were fixed in this comparison.</div>
      {% endif %}
    </div>

    <div class="card">
      <div class="section-label">New findings</div>
      {% if comparison.new_findings %}
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Severity</th>
            <th>Title</th>
          </tr>
        </thead>
        <tbody>
          {% for finding in comparison.new_findings %}
          <tr>
            <td>{{ finding.category }}</td>
            <td>{{ finding.severity }}</td>
            <td>{{ finding.title }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="empty">No new findings showed up here.</div>
      {% endif %}
    </div>

    <div class="card">
      <div class="section-label">Unchanged findings</div>
      {% if comparison.unchanged_findings %}
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Severity</th>
            <th>Title</th>
          </tr>
        </thead>
        <tbody>
          {% for finding in comparison.unchanged_findings %}
          <tr>
            <td>{{ finding.category }}</td>
            <td>{{ finding.severity }}</td>
            <td>{{ finding.title }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="empty">Nothing stayed the same in this comparison.</div>
      {% endif %}
    </div>
  </div>
</body>
</html>
"""


def write_markdown_comparison_report(comparison: ComparisonResult, output_path: str | Path) -> Path:
    path = Path(output_path)
    lines = [
        "# PsyberShield Comparison",
        "",
        f"Old report: {comparison.old_report}",
        f"New report: {comparison.new_report}",
        f"Risk trend: {comparison.risk_trend}",
        f"Risk score: {comparison.old_risk_score} -> {comparison.new_risk_score}",
        "",
        "## Comparison Context",
        "",
        f"- Old context: {comparison.old_context.discovery.app_name if comparison.old_context and comparison.old_context.discovery.app_name else 'not captured'}",
        f"- New context: {comparison.new_context.discovery.app_name if comparison.new_context and comparison.new_context.discovery.app_name else 'not captured'}",
        f"- Detail: {comparison.context_changes[0] if comparison.context_changes else 'unchanged'}",
        "",
        "## Crawl Coverage",
        "",
        f"- Old URLs: {len(comparison.old_scanned_urls)}",
        f"- New URLs: {len(comparison.new_scanned_urls)}",
        f"- Added URLs: {len(comparison.added_scanned_urls)}",
        f"- Removed URLs: {len(comparison.removed_scanned_urls)}",
    ]
    if comparison.added_scanned_urls:
        lines.extend(["", "- Added list:"])
        lines.extend([f"  - {url}" for url in comparison.added_scanned_urls])
    if comparison.removed_scanned_urls:
        lines.extend(["", "- Removed list:"])
        lines.extend([f"  - {url}" for url in comparison.removed_scanned_urls])
    if not comparison.added_scanned_urls and not comparison.removed_scanned_urls:
        lines.extend(["", "- Crawl coverage stayed the same."])

    lines.extend([
        "",
        "## Fixed findings",
    ])
    if comparison.fixed_findings:
        for finding in comparison.fixed_findings:
            lines.append(f"- [{finding.severity}] {finding.category}: {finding.title}")
    else:
        lines.append("- None")

    lines.extend(["", "## New findings"])
    if comparison.new_findings:
        for finding in comparison.new_findings:
            lines.append(f"- [{finding.severity}] {finding.category}: {finding.title}")
    else:
        lines.append("- None")

    lines.extend(["", "## Unchanged findings"])
    if comparison.unchanged_findings:
        for finding in comparison.unchanged_findings:
            lines.append(f"- [{finding.severity}] {finding.category}: {finding.title}")
    else:
        lines.append("- None")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_html_comparison_report(comparison: ComparisonResult, output_path: str | Path) -> Path:
    path = Path(output_path)
    environment = Environment(autoescape=select_autoescape())
    template = environment.from_string(_TEMPLATE)
    path.write_text(template.render(comparison=comparison, report_css=report_css), encoding="utf-8")
    return path
