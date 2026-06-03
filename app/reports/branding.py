from __future__ import annotations

import json
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any


APP_NAME = "PsyberShield"
APP_TAGLINE = "Security Visibility and Response for Small Servers and Web Applications"


def report_metadata(report_type: str) -> dict[str, str]:
    return {
        "app": APP_NAME,
        "tagline": APP_TAGLINE,
        "report_type": report_type,
        "generated_at": datetime.now(UTC).isoformat(),
    }


def write_branded_json(report: Any, output_path: str | Path, report_type: str) -> Path:
    path = Path(output_path)
    if hasattr(report, "model_dump"):
        payload = report.model_dump(mode="json")
    else:
        payload = dict(report)
    if isinstance(payload, dict):
        payload = {"report_metadata": report_metadata(report_type), **payload}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    return path


def markdown_header(title: str, report_type: str) -> list[str]:
    metadata = report_metadata(report_type)
    return [
        f"# // {title}",
        "",
        f"- App: {metadata['app']}",
        f"- Mode: {metadata['tagline']}",
        f"- Report type: {metadata['report_type']}",
        f"- Generated: {metadata['generated_at']}",
    ]


def report_css() -> str:
    return """
    :root {
      --bg: #080c10;
      --panel: #0d1117;
      --surface: #111820;
      --border: #1e2d3d;
      --border-hi: #2a3f54;
      --accent: #00d4ff;
      --accent-soft: rgba(0, 212, 255, 0.12);
      --orange: #ff6b35;
      --success: #00ff88;
      --warning: #ffb800;
      --danger: #ff3b3b;
      --text: #c8d8e8;
      --bright: #f5fbff;
      --muted: #7a9ab8;
      --dim: #4a6278;
      --mono: "IBM Plex Mono", "Cascadia Mono", "Consolas", monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background:
        radial-gradient(circle at 15% -10%, rgba(0, 212, 255, 0.08), transparent 28rem),
        linear-gradient(rgba(0, 212, 255, 0.028) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 212, 255, 0.028) 1px, transparent 1px),
        var(--bg);
      background-size: auto, 40px 40px, 40px 40px, auto;
      color: var(--text);
      font-family: var(--mono);
      font-size: 14px;
      letter-spacing: 0.01em;
    }
    a { color: var(--accent); }
    .page { max-width: 1220px; margin: 0 auto; padding: 36px 22px 64px; }
    .scanline {
      height: 1px;
      background: linear-gradient(90deg, transparent, var(--accent), transparent);
      opacity: 0.66;
    }
    .brand {
      color: var(--accent);
      font-size: 0.8rem;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      margin-bottom: 18px;
    }
    .brand::before { content: "> "; color: var(--orange); }
    .hero, .card {
      position: relative;
      overflow: hidden;
      background: rgba(13, 17, 23, 0.93);
      border: 1px solid var(--border);
      border-radius: 5px;
      padding: 22px 24px;
      margin-bottom: 18px;
      box-shadow: 0 28px 80px rgba(0, 0, 0, 0.2);
    }
    .card::before {
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 3px;
      background: var(--accent);
      opacity: 0.42;
    }
    h1, h2, h3 {
      margin-top: 0;
      color: var(--bright);
      font-family: var(--mono);
      font-weight: 700;
    }
    h1 { font-size: clamp(1.65rem, 2.8vw, 2.6rem); letter-spacing: -0.04em; }
    h2 {
      color: var(--accent);
      font-size: 0.9rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }
    h1::before, h2::before, h3::before { content: "// "; color: var(--dim); font-weight: 400; }
    p, li { line-height: 1.65; }
    .muted { color: var(--muted); }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 10px;
      margin-top: 16px;
    }
    .metric {
      border: 1px solid var(--border);
      border-radius: 4px;
      background: #070b0f;
      padding: 12px 14px;
    }
    .metric-label {
      display: block;
      color: var(--muted);
      font-size: 0.72rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    .metric-value {
      display: block;
      margin-top: 4px;
      color: var(--bright);
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #070b0f; }
    th, td {
      text-align: left;
      padding: 11px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      color: var(--accent);
      font-size: 0.76rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      background: #0a1117;
    }
    tr:hover td { background: rgba(0, 212, 255, 0.04); }
    .badge {
      display: inline-flex;
      padding: 0.24rem 0.5rem;
      border: 1px solid currentColor;
      border-radius: 3px;
      color: var(--muted);
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .severity-critical, .severity-high { color: var(--danger); box-shadow: 0 0 16px rgba(255, 59, 59, 0.18); }
    .severity-medium { color: var(--warning); box-shadow: 0 0 16px rgba(255, 184, 0, 0.16); }
    .severity-low { color: var(--accent); box-shadow: 0 0 16px rgba(0, 212, 255, 0.18); }
    .severity-info, .severity-ok { color: var(--success); box-shadow: 0 0 16px rgba(0, 255, 136, 0.14); }
    .footer { margin-top: 24px; color: var(--dim); font-size: 0.78rem; }
    """


def metric(label: str, value: Any) -> str:
    return (
        "<div class=\"metric\">"
        f"<span class=\"metric-label\">{escape(str(label))}</span>"
        f"<span class=\"metric-value\">{escape(str(value))}</span>"
        "</div>"
    )


def badge(value: str, class_prefix: str = "severity") -> str:
    normalized = value.lower().replace(" ", "-")
    return f"<span class=\"badge {class_prefix}-{escape(normalized)}\">{escape(value)}</span>"


def html_shell(title: str, report_type: str, hero: str, sections: list[str]) -> str:
    metadata = report_metadata(report_type)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>{report_css()}</style>
</head>
<body>
  <div class="scanline"></div>
  <main class="page">
    <div class="brand">{APP_NAME}</div>
    <section class="hero">
      <h1>{escape(title)}</h1>
      <p class="muted">{escape(APP_TAGLINE)}</p>
      {hero}
    </section>
    {"".join(sections)}
    <div class="footer">Generated by {escape(metadata['app'])} at {escape(metadata['generated_at'])}</div>
  </main>
</body>
</html>"""


def card(title: str, body: str) -> str:
    return f"<section class=\"card\"><h2>{escape(title)}</h2>{body}</section>"
