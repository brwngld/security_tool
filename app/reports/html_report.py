from __future__ import annotations

from collections import Counter
from pathlib import Path

from jinja2 import Environment, select_autoescape

from app.hardening.recommendations import suggest_first_move
from app.models import ScanResult

_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PsyberShield Deployment Readiness Review</title>
  <style>
    :root {
      --bg: #eef2ff;
      --bg-2: #f8fafc;
      --panel: rgba(255, 255, 255, 0.9);
      --text: #0f172a;
      --muted: #64748b;
      --line: rgba(148, 163, 184, 0.22);
      --header: #0f172a;
      --accent: #0284c7;
      --accent-2: #14b8a6;
      --low: #dbeafe;
      --medium: #fef3c7;
      --high: #fee2e2;
      --critical: #fee2e2;
      --info: #e2e8f0;
    }
    * { box-sizing: border-box; }
    body {
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      margin: 0;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(14, 165, 233, 0.16), transparent 28%),
        radial-gradient(circle at top right, rgba(20, 184, 166, 0.1), transparent 24%),
        linear-gradient(180deg, #ffffff 0%, var(--bg) 45%, var(--bg-2) 100%);
    }
    .page {
      max-width: 1180px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }
    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1.6fr) minmax(260px, 0.9fr);
      gap: 18px;
      align-items: stretch;
      padding: 24px;
      border: 1px solid rgba(148, 163, 184, 0.16);
      border-radius: 26px;
      background:
        linear-gradient(135deg, rgba(15, 23, 42, 0.96), rgba(30, 41, 59, 0.9) 54%, rgba(2, 132, 199, 0.82));
      color: #f8fafc;
      box-shadow: 0 24px 60px rgba(15, 23, 42, 0.18);
      margin-bottom: 18px;
    }
    h1 {
      margin: 0;
      font-size: 2.35rem;
      letter-spacing: -0.03em;
    }
    h2 {
      margin: 0;
      font-size: 1.15rem;
      color: var(--header);
    }
    .subtitle { margin: 8px 0 0; color: rgba(248, 250, 252, 0.82); }
    .hero-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 16px;
    }
    .hero-panel {
      align-self: stretch;
      border-radius: 20px;
      padding: 18px;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.14);
      backdrop-filter: blur(10px);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 12px;
    }
    .hero-label {
      color: rgba(248, 250, 252, 0.7);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-weight: 700;
    }
    .hero-value {
      margin-top: 4px;
      font-size: 1rem;
      font-weight: 600;
      color: #fff;
      word-break: break-word;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 18px 20px;
      margin: 18px 0;
      box-shadow: 0 10px 28px rgba(15, 23, 42, 0.06);
      backdrop-filter: blur(10px);
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .metric {
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 16px;
      padding: 14px 15px;
      background: linear-gradient(180deg, #ffffff, #f8fafc);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.78);
    }
    .metric-critical { border-left: 4px solid #dc2626; }
    .metric-high { border-left: 4px solid #f97316; }
    .metric-medium { border-left: 4px solid #d97706; }
    .metric-low { border-left: 4px solid #2563eb; }
    .metric-info { border-left: 4px solid #64748b; }
    .metric-accent { border-left: 4px solid #0ea5e9; }
    .metric-positive { border-left: 4px solid #10b981; }
    .metric-label {
      display: block;
      color: var(--muted);
      font-size: 0.8rem;
      margin-bottom: 4px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
    }
    .metric-value { display: block; font-size: 1.05rem; font-weight: 700; }
    .metric-subtext { display: block; margin-top: 4px; color: var(--muted); font-size: 0.84rem; }
    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }
    .section-hint { color: var(--muted); font-size: 0.92rem; }
    .summary-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }
    .context-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .context-item {
      padding: 12px 14px;
      border-radius: 14px;
      background: #ffffff;
      border: 1px solid rgba(148, 163, 184, 0.18);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.75);
    }
    .context-label {
      display: block;
      color: var(--muted);
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
      margin-bottom: 4px;
    }
    .context-value {
      font-size: 0.96rem;
      font-weight: 600;
      word-break: break-word;
    }
    .crawl-list {
      margin: 12px 0 0;
      padding-left: 20px;
      color: var(--text);
    }
    .crawl-list li {
      margin: 6px 0;
      word-break: break-word;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.78);
      border: 1px solid rgba(148, 163, 184, 0.18);
      font-size: 0.82rem;
      font-weight: 700;
      color: var(--header);
    }
    .chip-dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: var(--accent);
    }
    .chip-count {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 22px;
      padding: 1px 7px;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.08);
      font-size: 0.78rem;
      font-weight: 800;
    }
    table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      margin-top: 10px;
      overflow: hidden;
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.76);
    }
    th, td {
      text-align: left;
      padding: 12px 14px;
      border-bottom: 1px solid rgba(148, 163, 184, 0.15);
      vertical-align: top;
    }
    th {
      background: linear-gradient(180deg, #f8fafc, #eef2ff);
      color: var(--header);
      font-size: 0.92rem;
    }
    tr:last-child td { border-bottom: 0; }
    tbody tr:hover td { background: rgba(14, 165, 233, 0.04); }
    .muted { color: var(--muted); }
    .pill {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 999px;
      background: #e5e7eb;
      margin-right: 6px;
      font-size: 0.82rem;
      line-height: 1.3;
      font-weight: 700;
    }
    .sev-low { background: var(--low); color: #1d4ed8; }
    .sev-medium { background: var(--medium); color: #92400e; }
    .sev-high { background: var(--high); color: #b91c1c; }
    .sev-critical { background: var(--critical); color: #991b1b; }
    .sev-info { background: var(--info); color: #334155; }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      margin: 0;
      background: #f8fafc;
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 10px;
      padding: 10px 12px;
    }
    .section-label {
      display: inline-block;
      margin-bottom: 10px;
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--accent);
      font-weight: 700;
    }
    .empty-state {
      padding: 16px 18px;
      border-radius: 14px;
      border: 1px dashed rgba(148, 163, 184, 0.38);
      color: var(--muted);
      background: rgba(248, 250, 252, 0.8);
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <div>
        <h1>PsyberShield Deployment Readiness Review</h1>
        <p class="subtitle">Target: {{ result.target.url }}</p>
        <div class="hero-meta">
          <span class="pill">Findings {{ result.findings|length }}</span>
          <span class="pill">Notes {{ result.notes|length }}</span>
          <span class="pill">Confidence {{ (result.scan_confidence * 100) | round(0) | int }}%</span>
        </div>
      </div>
      <div class="hero-panel">
        <div>
          <div class="hero-label">Generated for</div>
          <div class="hero-value">Local review</div>
        </div>
        <div>
          <div class="hero-label">WAF signals</div>
          <div class="hero-value">{{ result.waf_signals|join(", ") if result.waf_signals else "None noted" }}</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="section-header">
        <h2>Summary</h2>
        <div class="section-hint">Quick read before you scroll into the findings</div>
      </div>
      <div class="summary-grid">
        <div class="metric metric-accent"><span class="metric-label">Findings</span><span class="metric-value">{{ result.findings|length }}</span><span class="metric-subtext">All issues found in this pass</span></div>
        <div class="metric metric-info"><span class="metric-label">Notes</span><span class="metric-value">{{ result.notes|length }}</span><span class="metric-subtext">Useful context and scan clues</span></div>
        <div class="metric metric-positive"><span class="metric-label">TLS</span><span class="metric-value">{{ result.tls_summary.get("status", "-") }}</span><span class="metric-subtext">{% if result.tls_summary.get("expires_on") %}Expires {{ result.tls_summary.get("expires_on") }}{% else %}No TLS detail captured{% endif %}</span></div>
        <div class="metric metric-low"><span class="metric-label">Low</span><span class="metric-value">{{ result.findings | selectattr("severity", "equalto", "low") | list | length }}</span><span class="metric-subtext">Small but worth fixing</span></div>
        <div class="metric metric-medium"><span class="metric-label">Medium</span><span class="metric-value">{{ result.findings | selectattr("severity", "equalto", "medium") | list | length }}</span><span class="metric-subtext">Needs a closer look</span></div>
        <div class="metric metric-high"><span class="metric-label">High / Critical</span><span class="metric-value">{{ (result.findings | selectattr("severity", "equalto", "high") | list | length) + (result.findings | selectattr("severity", "equalto", "critical") | list | length) }}</span><span class="metric-subtext">None in the current slice is expected to be fatal</span></div>
      </div>
      <div class="summary-chips">
        {% if category_chips %}
          {% for chip in category_chips[:4] %}
            <span class="chip"><span class="chip-dot"></span>{{ chip.name }} <span class="chip-count">{{ chip.count }}</span></span>
          {% endfor %}
        {% else %}
          <span class="chip"><span class="chip-dot"></span>No categories yet</span>
        {% endif %}
        <span class="chip"><span class="chip-dot"></span>Exposed files: {{ result.findings | selectattr("category", "equalto", "exposed_files") | list | length }}</span>
      </div>
    </div>

    {% if result.context %}
    <div class="card">
      <div class="section-header">
        <h2>Application Context</h2>
        <div class="section-hint">This is the discovery trail PsyberShield used when no URL was supplied</div>
      </div>
      <div class="context-grid">
        <div class="context-item"><span class="context-label">Root</span><span class="context-value">{{ result.context.root }}</span></div>
        <div class="context-item"><span class="context-label">Target</span><span class="context-value">{{ result.context.target.value if result.context.target else "not resolved" }}</span></div>
        <div class="context-item"><span class="context-label">Target source</span><span class="context-value">{{ result.context.target.source if result.context.target else "not resolved" }}</span></div>
        <div class="context-item"><span class="context-label">Discovered app</span><span class="context-value">{{ result.context.discovery.app_name or "-" }}</span></div>
        <div class="context-item"><span class="context-label">Public URL</span><span class="context-value">{{ result.context.discovery.public_url or "-" }}</span></div>
        <div class="context-item"><span class="context-label">Local URL</span><span class="context-value">{{ result.context.discovery.local_url or "-" }}</span></div>
        <div class="context-item"><span class="context-label">Env file</span><span class="context-value">{{ result.context.discovery.env_file or "-" }}</span></div>
        <div class="context-item"><span class="context-label">Env source</span><span class="context-value">{{ result.context.discovery.env_source or "-" }}</span></div>
        <div class="context-item"><span class="context-label">Nginx config</span><span class="context-value">{{ result.context.discovery.nginx_config or "-" }}</span></div>
        <div class="context-item"><span class="context-label">Systemd service</span><span class="context-value">{{ result.context.discovery.systemd_service or "-" }}</span></div>
      </div>
      {% if result.context.discovery.notes %}
      <div class="empty-state" style="margin-top: 12px;">{{ result.context.discovery.notes | join("; ") }}</div>
      {% endif %}
    </div>
    {% endif %}

    {% if result.scanned_urls|length > 1 %}
    <div class="card">
      <div class="section-header">
        <h2>Scanned URLs</h2>
        <div class="section-hint">These are the in-scope pages PsyberShield visited in crawl mode</div>
      </div>
      <ol class="crawl-list">
        {% for url in result.scanned_urls %}
        <li>{{ url }}</li>
        {% endfor %}
      </ol>
      {% if result.crawl_seed_sources %}
      <div class="empty-state" style="margin-top: 12px;">Seed sources: {{ result.crawl_seed_sources | join(", ") }}</div>
      {% endif %}
    </div>
    {% endif %}

    <div class="card">
      <div class="section-header">
        <h2>Findings</h2>
        <div class="section-hint">Severity colors make the noisy stuff easier to scan</div>
      </div>
      {% if result.findings %}
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Category</th>
            <th>Title</th>
            <th>Confidence</th>
            <th>First Move</th>
            <th>Evidence</th>
            <th>Impact</th>
            <th>Affected URLs</th>
          </tr>
        </thead>
        <tbody>
          {% for finding in result.findings %}
          <tr>
            <td><span class="pill sev-{{ finding.severity }}">{{ finding.severity }}</span></td>
            <td>{{ finding.category }}</td>
            <td>{{ finding.title }}</td>
            <td><span class="pill">{{ finding.confidence }}</span></td>
            <td>{{ suggest_first_move(finding) }}</td>
            <td><pre>{{ finding.evidence|tojson(indent=2) }}</pre></td>
            <td>{{ finding.expected_impact or "-" }}</td>
            <td>
              {% if finding.affected_urls %}
                {% for url in finding.affected_urls %}
                  {{ loop.index }}. {{ url }}{% if not loop.last %}<br>{% endif %}
                {% endfor %}
              {% else %}
                -
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
        <div class="empty-state">No findings showed up in this run.</div>
      {% endif %}
    </div>

    {% if include_fix_plans and result.fix_plans %}
    <div class="card">
      <div class="section-header">
        <h2>Proposed Fixes</h2>
        <div class="section-hint">Preview mode keeps this as a suggestion list</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Finding</th>
            <th>Next step</th>
            <th>Rollback</th>
            <th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {% for plan in result.fix_plans %}
          {% set title = result.findings | selectattr("id", "equalto", plan.finding_id) | map(attribute="title") | first %}
          <tr>
            <td>{{ title or plan.finding_id }}</td>
            <td>{{ plan.expected_impact }}</td>
            <td>{{ plan.rollback_command or "-" }}</td>
            <td><span class="pill sev-{{ plan.risk_level }}">{{ plan.risk_level }}</span></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}
  </div>
</body>
</html>
"""


def write_html_report(result: ScanResult, output_path: str | Path, include_fix_plans: bool = False) -> Path:
    path = Path(output_path)
    environment = Environment(autoescape=select_autoescape())
    environment.globals["suggest_first_move"] = suggest_first_move
    template = environment.from_string(_TEMPLATE)
    category_counts = Counter(finding.category for finding in result.findings)
    category_priority = {
        "headers": 0,
        "cookies": 1,
        "exposed_files": 2,
        "server_info": 3,
        "tls": 4,
        "connectivity": 5,
    }
    category_chips = [
        {"name": name, "count": count}
        for name, count in sorted(
            category_counts.items(),
            key=lambda item: (category_priority.get(item[0], 99), -item[1], item[0]),
        )
    ]
    rendered = template.render(
        result=result,
        include_fix_plans=include_fix_plans,
        category_chips=category_chips,
    )
    path.write_text(rendered, encoding="utf-8")
    return path

