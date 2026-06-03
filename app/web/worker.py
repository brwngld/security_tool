from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import read_audit_events, write_audit_events_json
from app.baseline import build_baseline_metadata, write_baseline_metadata
from app.bundles import bundle_report_files
from app.comparison import compare_scan_files
from app.doctor import run_doctor_checks, run_server_checks
from app.drift import analyze_report_drift
from app.engine import crawl_target, scan_target
from app.http.auth import CrawlAuthConfig
from app.incident import analyze_incident_sources, default_incident_sources
from app.integrity import analyze_integrity_sources, write_integrity_snapshot
from app.reports.comparison_report import write_html_comparison_report, write_markdown_comparison_report
from app.reports.branding import report_css
from app.reports.doctor_report import write_html_doctor_report, write_json_doctor_report, write_markdown_doctor_report
from app.reports.drift_report import write_html_drift_report, write_json_drift_report, write_markdown_drift_report
from app.reports.html_report import write_html_report
from app.reports.incident_report import write_html_incident_report, write_json_incident_report, write_markdown_incident_report
from app.reports.integrity_report import write_html_integrity_report, write_json_integrity_report, write_markdown_integrity_report
from app.reports.json_report import write_json_report
from app.reports.markdown_report import write_markdown_report
from app.reports.secret_report import write_html_secret_report, write_json_secret_report, write_markdown_secret_report
from app.reports.timeline_report import write_html_timeline_report, write_json_timeline_report, write_markdown_timeline_report
from app.reports.vuln_report import write_html_vuln_report, write_json_vuln_report, write_markdown_vuln_report
from app.reports.watch_report import write_html_watch_report, write_json_watch_report, write_markdown_watch_report
from app.secrets import analyze_secret_exposures
from app.timeline import load_timeline_report_from_path
from app.vuln import scan_software_inventory
from app.watch import run_watch_snapshot
from app.web.config import WebConfig, load_web_config
from app.web.db import create_schema, make_session_factory
from app.web.models import Job
from app.web.services import record_audit_event, record_report


def run_worker(*, once: bool = False, poll_seconds: float = 5.0, config: WebConfig | None = None) -> None:
    active_config = config or load_web_config()
    create_schema(active_config)
    session_factory = make_session_factory(active_config)
    while True:
        with session_factory() as session:
            job = claim_next_job(session)
            if job is not None:
                run_job(session, job, active_config)
                session.commit()
        if once:
            return
        time.sleep(poll_seconds)


def claim_next_job(session: Session) -> Job | None:
    job = session.scalar(select(Job).where(Job.status == "queued").order_by(Job.created_at.asc()))
    if job is None:
        return None
    job.status = "running"
    job.started_at = datetime.now(UTC)
    session.flush()
    return job


def run_job(session: Session, job: Job, config: WebConfig) -> None:
    try:
        params = json.loads(job.params_json or "{}")
        output_dir = config.output_dir / f"job-{job.id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        handler = JOB_HANDLERS[job.job_type]
        summary = handler(session, job, params, output_dir)
        job.status = "succeeded"
        job.finished_at = datetime.now(UTC)
        record_audit_event(
            session,
            user_id=job.created_by_user_id,
            job_id=job.id,
            action=job.job_type,
            target=job.target_url or str(params.get("root") or ""),
            result="succeeded",
            details=summary,
        )
    except Exception as exc:
        job.status = "failed"
        job.error_message = str(exc)
        job.finished_at = datetime.now(UTC)
        record_audit_event(
            session,
            user_id=job.created_by_user_id,
            job_id=job.id,
            action=job.job_type,
            target=job.target_url or "",
            result="failed",
            details={"error": str(exc)},
        )


def _write_scan_like_reports(session: Session, job: Job, result, output_dir: Path, report_type: str) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{report_type}.json"
    markdown_path = output_dir / f"{report_type}.md"
    html_path = output_dir / f"{report_type}.html"
    write_json_report(result, json_path)
    write_markdown_report(result, markdown_path)
    write_html_report(result, html_path)
    summary = {"findings": len(result.findings), "notes": len(result.notes)}
    record_report(
        session,
        job_id=job.id,
        report_type=report_type,
        json_path=json_path,
        markdown_path=markdown_path,
        html_path=html_path,
        summary=summary,
    )
    return summary


def _path_or_none(value: Any) -> Path | None:
    if value in (None, ""):
        return None
    return Path(str(value))


def _paths_from_text(value: Any) -> list[Path]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [Path(str(item)) for item in value if str(item).strip()]
    text = str(value)
    separators = ["\n", ";", ","]
    values = [text]
    for separator in separators:
        values = [part for value_item in values for part in value_item.split(separator)]
    return [Path(part.strip()) for part in values if part.strip()]


def _text_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _build_auth_config(params: dict[str, Any]) -> CrawlAuthConfig | None:
    auth_method = _text_or_none(params.get("auth_method"))
    if auth_method in (None, "none"):
        has_session_input = any(
            _text_or_none(params.get(key))
            for key in (
                "login_url",
                "storage_state",
                "session_file",
                "cookie",
                "auth_env_ref",
                "username",
            )
        )
        if not has_session_input:
            return None
        auth_method = "json"
    if auth_method == "browser" and not (_text_or_none(params.get("login_url")) or _text_or_none(params.get("storage_state"))):
        raise ValueError("Browser auth requires a login URL or storage-state path.")
    return CrawlAuthConfig(
        login_url=_text_or_none(params.get("login_url")),
        auth_method=auth_method,
        username=_text_or_none(params.get("username")),
        password_env=_text_or_none(params.get("auth_env_ref")),
        env_file=_text_or_none(params.get("env_file")),
        cookie=_text_or_none(params.get("cookie")),
        session_file=_text_or_none(params.get("session_file")),
        storage_state=_text_or_none(params.get("storage_state")),
        browser_username_selector=_text_or_none(params.get("browser_username_selector")),
        browser_password_selector=_text_or_none(params.get("browser_password_selector")),
        browser_submit_selector=_text_or_none(params.get("browser_submit_selector")),
        browser_headless=bool(params.get("browser_headless", True)),
        auth_check_url=_text_or_none(params.get("auth_check_url")),
    )


def _write_model_reports(
    session: Session,
    job: Job,
    output_dir: Path,
    report_type: str,
    report: Any,
    *,
    json_writer,
    markdown_writer,
    html_writer,
    summary: dict[str, Any],
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{report_type}.json"
    markdown_path = output_dir / f"{report_type}.md"
    html_path = output_dir / f"{report_type}.html"
    json_writer(report, json_path)
    markdown_writer(report, markdown_path)
    html_writer(report, html_path)
    record_report(
        session,
        job_id=job.id,
        report_type=report_type,
        json_path=json_path,
        markdown_path=markdown_path,
        html_path=html_path,
        summary=summary,
    )
    return summary


def _write_audit_markdown(events, output_path: Path) -> Path:
    lines = ["# PsyberShield Audit Events", "", f"Events: {len(events)}", ""]
    for event in events:
        lines.append(f"- {event.timestamp} [{event.action}]")
        lines.append(f"  - Target: {event.target or '-'}")
        lines.append(f"  - Result: {event.result or '-'}")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def _write_audit_html(events, output_path: Path) -> Path:
    rows = []
    for event in events:
        rows.append(
            "<tr>"
            f"<td>{escape(str(event.timestamp))}</td>"
            f"<td>{escape(event.action)}</td>"
            f"<td>{escape(event.target or '-')}</td>"
            f"<td>{escape(event.result or '-')}</td>"
            "</tr>"
        )
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PsyberShield Audit Events</title>
  <style>
    body {{ margin: 0; font-family: Aptos, Segoe UI, sans-serif; background: #0b1116; color: #edf7f5; }}
    .page {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px; }}
    .card {{ background: #121c24; border: 1px solid #28404f; border-radius: 18px; padding: 20px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #28404f; vertical-align: top; }}
    th {{ color: #62d3a5; }}
  </style>
  <style>{report_css()}</style>
</head>
<body>
  <div class="page">
    <div class="card">
      <h1>PsyberShield Audit Events</h1>
      <p>Events: {len(events)}</p>
      <table>
        <thead><tr><th>Timestamp</th><th>Action</th><th>Target</th><th>Result</th></tr></thead>
        <tbody>{"".join(rows) or "<tr><td colspan='4'>No audit events</td></tr>"}</tbody>
      </table>
    </div>
  </div>
</body>
</html>"""
    output_path.write_text(html, encoding="utf-8")
    return output_path


def handle_scan(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    target_url = job.target_url or str(params["target_url"])
    result = scan_target(target_url, timeout_seconds=float(params.get("timeout_seconds", 10.0)), auth_config=_build_auth_config(params))
    return _write_scan_like_reports(session, job, result, output_dir, "scan")


def handle_crawl(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    target_url = job.target_url or str(params["target_url"])
    result = crawl_target(
        target_url,
        timeout_seconds=float(params.get("timeout_seconds", 10.0)),
        max_pages=int(params.get("max_pages", 100)),
        max_crawl_depth=int(params.get("max_depth", 2)),
        seed_robots=bool(params.get("seed_robots", True)),
        seed_sitemap=bool(params.get("seed_sitemap", True)),
        auth_config=_build_auth_config(params),
    )
    return _write_scan_like_reports(session, job, result, output_dir, "crawl")


def handle_vuln_scan(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    root = Path(str(params.get("root") or "."))
    report = scan_software_inventory(
        root,
        match_cves=True,
        include_osv=bool(params.get("include_osv", False)),
        osv_cache_dir=output_dir / "osv-cache",
    )
    json_path = output_dir / "vuln.json"
    markdown_path = output_dir / "vuln.md"
    html_path = output_dir / "vuln.html"
    write_json_vuln_report(report, json_path)
    write_markdown_vuln_report(report, markdown_path)
    write_html_vuln_report(report, html_path)
    summary = {"components": len(report.components), "findings": len(report.findings)}
    record_report(session, job_id=job.id, report_type="vuln_scan", json_path=json_path, markdown_path=markdown_path, html_path=html_path, summary=summary)
    return summary


def handle_secrets(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    root = Path(str(params.get("root") or "."))
    report = analyze_secret_exposures(root)
    json_path = output_dir / "secrets.json"
    markdown_path = output_dir / "secrets.md"
    html_path = output_dir / "secrets.html"
    write_json_secret_report(report, json_path)
    write_markdown_secret_report(report, markdown_path)
    write_html_secret_report(report, html_path)
    summary = {"source_files": len(report.source_files), "findings": len(report.findings)}
    record_report(session, job_id=job.id, report_type="secrets", json_path=json_path, markdown_path=markdown_path, html_path=html_path, summary=summary)
    return summary


def handle_baseline(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    target_url = job.target_url or str(params["target_url"])
    result = scan_target(target_url, timeout_seconds=float(params.get("timeout_seconds", 10.0)))
    result.baseline_label = str(params.get("label") or "")
    summary = _write_scan_like_reports(session, job, result, output_dir, "baseline")
    metadata = build_baseline_metadata(result.context, result.baseline_label)
    if metadata:
        write_baseline_metadata(output_dir / "baseline.json", metadata)
    return summary


def handle_compare(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    comparison = compare_scan_files(params["old_report"], params["new_report"])
    markdown_path = output_dir / "compare.md"
    html_path = output_dir / "compare.html"
    write_markdown_comparison_report(comparison, markdown_path)
    write_html_comparison_report(comparison, html_path)
    summary = {"new_findings": len(comparison.new_findings), "fixed_findings": len(comparison.fixed_findings)}
    record_report(session, job_id=job.id, report_type="compare", markdown_path=markdown_path, html_path=html_path, summary=summary)
    return summary


def handle_bundle(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle = bundle_report_files(params["report_path"], output_path=output_dir / "bundle.zip")
    summary = {"items": len(bundle.items), "output_path": bundle.output_path}
    record_report(session, job_id=job.id, report_type="bundle", summary=summary)
    return summary


def handle_doctor(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    report = run_doctor_checks(root=_path_or_none(params.get("root")), env_file=_path_or_none(params.get("env_file")))
    summary = {
        "checks": len(report.checks),
        "readiness_state": report.readiness_state,
        "readiness_score": report.readiness_score,
    }
    return _write_model_reports(
        session,
        job,
        output_dir,
        "doctor",
        report,
        json_writer=write_json_doctor_report,
        markdown_writer=write_markdown_doctor_report,
        html_writer=write_html_doctor_report,
        summary=summary,
    )


def handle_server_check(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    report = run_server_checks(
        root=_path_or_none(params.get("root")),
        env_file=_path_or_none(params.get("env_file")),
        nginx_config=_path_or_none(params.get("nginx_config")),
    )
    summary = {
        "checks": len(report.checks),
        "readiness_state": report.readiness_state,
        "readiness_score": report.readiness_score,
    }
    return _write_model_reports(
        session,
        job,
        output_dir,
        "server_check",
        report,
        json_writer=write_json_doctor_report,
        markdown_writer=write_markdown_doctor_report,
        html_writer=write_html_doctor_report,
        summary=summary,
    )


def handle_incident(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    root = _path_or_none(params.get("root")) or Path.cwd()
    sources = _paths_from_text(params.get("logs"))
    if not sources:
        sources = default_incident_sources(root, job.target_url or params.get("target_url"))
    report = analyze_incident_sources(
        sources,
        root=root,
        url=job.target_url or params.get("target_url"),
        block_threshold=int(params.get("block_threshold", 5)),
        env_file=_path_or_none(params.get("env_file")),
        nginx_config=_path_or_none(params.get("nginx_config")),
    )
    summary = {
        "findings": len(report.findings),
        "suspect_ips": len(report.suspect_ips),
        "containment_applied": report.containment_applied,
    }
    return _write_model_reports(
        session,
        job,
        output_dir,
        "incident",
        report,
        json_writer=write_json_incident_report,
        markdown_writer=write_markdown_incident_report,
        html_writer=write_html_incident_report,
        summary=summary,
    )


def handle_integrity(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    root = _path_or_none(params.get("root")) or Path.cwd()
    report = analyze_integrity_sources(
        root,
        baseline_path=_path_or_none(params.get("baseline_path")),
        extra_paths=_paths_from_text(params.get("extra_paths")),
    )
    summary = {"files": len(report.files), "findings": len(report.findings)}
    return _write_model_reports(
        session,
        job,
        output_dir,
        "integrity",
        report,
        json_writer=write_json_integrity_report,
        markdown_writer=write_markdown_integrity_report,
        html_writer=write_html_integrity_report,
        summary=summary,
    )


def handle_watch(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    root = _path_or_none(params.get("root")) or Path.cwd()
    report = run_watch_snapshot(
        root=root,
        env_file=_path_or_none(params.get("env_file")),
        nginx_config=_path_or_none(params.get("nginx_config")),
        logs=_paths_from_text(params.get("logs")),
        journal_units=[item.name for item in _paths_from_text(params.get("journal_unit"))],
        event_log_names=[item.name for item in _paths_from_text(params.get("event_log_name"))],
        tail_files=_paths_from_text(params.get("tail_file")),
        baseline_path=_path_or_none(params.get("baseline_path")),
        policy_path=_path_or_none(params.get("policy_path")),
        mode="snapshot",
        compact=bool(params.get("compact", True)),
    )
    summary = {"risk_level": report.risk_level, "risk_score": report.risk_score, "findings": len(report.findings)}
    return _write_model_reports(
        session,
        job,
        output_dir,
        "watch",
        report,
        json_writer=write_json_watch_report,
        markdown_writer=write_markdown_watch_report,
        html_writer=write_html_watch_report,
        summary=summary,
    )


def handle_drift(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    report = analyze_report_drift(Path(params["old_report"]), Path(params["new_report"]))
    summary = {"findings": len(report.findings), "report_type": report.report_type}
    return _write_model_reports(
        session,
        job,
        output_dir,
        "drift",
        report,
        json_writer=write_json_drift_report,
        markdown_writer=write_markdown_drift_report,
        html_writer=write_html_drift_report,
        summary=summary,
    )


def handle_timeline(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    report = load_timeline_report_from_path(params["incident_report"], _path_or_none(params.get("audit_log")))
    summary = {"events": len(report.events)}
    return _write_model_reports(
        session,
        job,
        output_dir,
        "timeline",
        report,
        json_writer=write_json_timeline_report,
        markdown_writer=write_markdown_timeline_report,
        html_writer=write_html_timeline_report,
        summary=summary,
    )


def handle_audit(session: Session, job: Job, params: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    audit_log = _path_or_none(params.get("audit_log")) or Path("outputs/audit.log")
    events = read_audit_events(audit_log)
    json_path = output_dir / "audit.json"
    markdown_path = output_dir / "audit.md"
    html_path = output_dir / "audit.html"
    write_audit_events_json(json_path, events)
    _write_audit_markdown(events, markdown_path)
    _write_audit_html(events, html_path)
    summary = {"events": len(events), "audit_log": str(audit_log)}
    record_report(
        session,
        job_id=job.id,
        report_type="audit",
        json_path=json_path,
        markdown_path=markdown_path,
        html_path=html_path,
        summary=summary,
    )
    return summary


JOB_HANDLERS = {
    "scan": handle_scan,
    "crawl": handle_crawl,
    "vuln_scan": handle_vuln_scan,
    "secrets": handle_secrets,
    "baseline": handle_baseline,
    "compare": handle_compare,
    "bundle": handle_bundle,
    "doctor": handle_doctor,
    "server_check": handle_server_check,
    "incident": handle_incident,
    "integrity": handle_integrity,
    "watch": handle_watch,
    "drift": handle_drift,
    "timeline": handle_timeline,
    "audit": handle_audit,
}
