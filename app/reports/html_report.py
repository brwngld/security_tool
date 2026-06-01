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
      --bg: #050816;
      --bg-2: #0f172a;
      --panel: rgba(15, 23, 42, 0.86);
      --text: #e5eefb;
      --muted: #9aa9c2;
      --line: rgba(148, 163, 184, 0.18);
      --header: #f8fafc;
      --accent: #f59e0b;
      --accent-2: #22c55e;
      --low: rgba(59, 130, 246, 0.18);
      --medium: rgba(245, 158, 11, 0.18);
      --high: rgba(248, 113, 113, 0.18);
      --critical: rgba(248, 113, 113, 0.22);
      --info: rgba(148, 163, 184, 0.18);
    }
    * { box-sizing: border-box; }
    body {
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      margin: 0;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(245, 158, 11, 0.12), transparent 26%),
        radial-gradient(circle at top right, rgba(34, 197, 94, 0.11), transparent 24%),
        linear-gradient(180deg, #020617 0%, var(--bg) 38%, var(--bg-2) 100%);
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
      border: 1px solid rgba(245, 158, 11, 0.2);
      border-radius: 24px;
      background:
        linear-gradient(135deg, rgba(2, 6, 23, 0.98), rgba(15, 23, 42, 0.94) 58%, rgba(30, 41, 59, 0.9));
      color: #f8fafc;
      box-shadow: 0 28px 70px rgba(2, 6, 23, 0.5);
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
      background: rgba(15, 23, 42, 0.5);
      border: 1px solid rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(14px);
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
      box-shadow: 0 14px 34px rgba(2, 6, 23, 0.24);
      backdrop-filter: blur(14px);
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .metric {
      border: 1px solid rgba(148, 163, 184, 0.16);
      border-radius: 16px;
      padding: 14px 15px;
      background: linear-gradient(180deg, rgba(15, 23, 42, 0.96), rgba(30, 41, 59, 0.92));
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
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
      background: rgba(2, 6, 23, 0.55);
      border: 1px solid rgba(148, 163, 184, 0.18);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
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
      background: rgba(15, 23, 42, 0.72);
      border: 1px solid rgba(148, 163, 184, 0.18);
      font-size: 0.82rem;
      font-weight: 700;
      color: var(--text);
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
      background: rgba(2, 6, 23, 0.72);
    }
    th, td {
      text-align: left;
      padding: 12px 14px;
      border-bottom: 1px solid rgba(148, 163, 184, 0.15);
      vertical-align: top;
    }
    th {
      background: linear-gradient(180deg, rgba(15, 23, 42, 0.96), rgba(30, 41, 59, 0.94));
      color: var(--header);
      font-size: 0.92rem;
    }
    tr:last-child td { border-bottom: 0; }
    tbody tr:hover td { background: rgba(245, 158, 11, 0.06); }
    .muted { color: var(--muted); }
    .pill {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 999px;
      background: rgba(148, 163, 184, 0.18);
      margin-right: 6px;
      font-size: 0.82rem;
      line-height: 1.3;
      font-weight: 700;
      color: var(--text);
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
      background: rgba(2, 6, 23, 0.75);
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 10px;
      padding: 10px 12px;
      color: var(--text);
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
      background: rgba(2, 6, 23, 0.65);
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <div class="page">
    <div class="hero">
      <div>
        <h1>PsyberShield Deployment Readiness Review</h1>
        <p class="subtitle">Control-room view for the current deployment target: {{ result.target.url }}</p>
        <div class="hero-meta">
          <span class="pill">Detections {{ result.findings|length }}</span>
          <span class="pill">Notes {{ result.notes|length }}</span>
          <span class="pill">Readiness {{ (result.scan_confidence * 100) | round(0) | int }}%</span>
        </div>
      </div>
      <div class="hero-panel">
        <div>
          <div class="hero-label">Mode</div>
          <div class="hero-value">Deployment review</div>
        </div>
        <div>
          <div class="hero-label">Priority signals</div>
          <div class="hero-value">{{ result.waf_signals|join(", ") if result.waf_signals else "None noted" }}</div>
        </div>
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

    <div class="card">
      <div class="section-header">
        <h2>Operational Snapshot</h2>
        <div class="section-hint">The posture view for the current target</div>
      </div>
      <div class="summary-grid">
        <div class="metric metric-accent"><span class="metric-label">Detections</span><span class="metric-value">{{ result.findings|length }}</span><span class="metric-subtext">All issues surfaced in this pass</span></div>
        <div class="metric metric-info"><span class="metric-label">Notes</span><span class="metric-value">{{ result.notes|length }}</span><span class="metric-subtext">Context and scan clues worth keeping</span></div>
        <div class="metric metric-positive"><span class="metric-label">TLS posture</span><span class="metric-value">{{ result.tls_summary.get("status", "-") }}</span><span class="metric-subtext">{% if result.tls_summary.get("expires_on") %}Expires {{ result.tls_summary.get("expires_on") }}{% else %}No TLS detail captured{% endif %}</span></div>
        <div class="metric metric-low"><span class="metric-label">Low</span><span class="metric-value">{{ result.findings | selectattr("severity", "equalto", "low") | list | length }}</span><span class="metric-subtext">Worth fixing before handoff</span></div>
        <div class="metric metric-medium"><span class="metric-label">Medium</span><span class="metric-value">{{ result.findings | selectattr("severity", "equalto", "medium") | list | length }}</span><span class="metric-subtext">Needs a closer look</span></div>
        <div class="metric metric-high"><span class="metric-label">High / Critical</span><span class="metric-value">{{ (result.findings | selectattr("severity", "equalto", "high") | list | length) + (result.findings | selectattr("severity", "equalto", "critical") | list | length) }}</span><span class="metric-subtext">Anything here needs priority handling</span></div>
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

    {% if result.scanned_urls|length > 1 %}
    <div class="card">
      <div class="section-header">
        <h2>Route Coverage</h2>
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
        <h2>Action Queue</h2>
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

