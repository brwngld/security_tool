from __future__ import annotations

from collections import Counter
from pathlib import Path

from rich.console import Group
from rich.table import Table
from rich.text import Text

from app.audit import AuditEvent, describe_audit_event
from app.context import ApplicationContext
from app.doctor import DoctorCheck, DoctorReport
from app.config import AppConfig
from app.models import ComparisonResult, DriftReport, FixDecision, IncidentReport, IntegrityReport, LocalFixResult, ReportBundle, ScanResult, SecretExposureReport, TimelineReport


def summarize_evidence(evidence: dict[str, object]) -> str:
    pieces = []
    for key in ("header", "set_cookie", "path", "status_code", "url", "header_value", "error"):
        value = evidence.get(key)
        if value not in (None, ""):
            pieces.append(f"{key}={value}")
    if not pieces:
        return "-"
    return "; ".join(pieces[:2])


def summarize_counts(result: ScanResult) -> tuple[str, str, str]:
    severity_counts = Counter(finding.severity for finding in result.findings)
    category_counts = Counter(finding.category for finding in result.findings)
    category_priority = {
        "headers": 0,
        "cookies": 1,
        "exposed_files": 2,
        "server_info": 3,
        "tls": 4,
        "connectivity": 5,
    }
    severity_text = ", ".join(
        f"{name}={severity_counts.get(name, 0)}" for name in ("critical", "high", "medium", "low", "info")
    )
    top_categories = ", ".join(
        f"{name}={count}"
        for name, count in sorted(
            category_counts.items(),
            key=lambda item: (category_priority.get(item[0], 99), -item[1], item[0]),
        )[:3]
    ) or "-"
    exposed_files = str(category_counts.get("exposed_files", 0))
    return severity_text, top_categories, exposed_files


def render_category_chips(result: ScanResult) -> Text:
    category_counts = Counter(finding.category for finding in result.findings)
    category_priority = {
        "headers": 0,
        "cookies": 1,
        "exposed_files": 2,
        "server_info": 3,
        "tls": 4,
        "connectivity": 5,
    }
    chips = Text()
    ordered_categories = sorted(
        category_counts.items(),
        key=lambda item: (category_priority.get(item[0], 99), -item[1], item[0]),
    )[:3]
    if not ordered_categories:
        chips.append("-")
        return chips

    for index, (name, count) in enumerate(ordered_categories):
        if index:
            chips.append("  ")
        chips.append(" ")
        chips.append(name, style="bold black on bright_cyan")
        chips.append(" ")
        chips.append(str(count), style="bold white on blue")
        chips.append(" ")
    return chips


def render_severity_chips(result: ScanResult) -> Text:
    severity_counts = Counter(finding.severity for finding in result.findings)
    severity_priority = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    chips = Text()
    ordered_severities = sorted(
        severity_counts.items(),
        key=lambda item: (severity_priority.get(item[0], 99), -item[1], item[0]),
    )
    if not ordered_severities:
        chips.append("-")
        return chips

    for index, (name, count) in enumerate(ordered_severities):
        if index:
            chips.append("  ")
        chips.append(" ")
        chips.append(name, style="bold white on dark_red" if name == "critical" else "bold black on bright_yellow" if name == "medium" else "bold white on dark_blue")
        chips.append(" ")
        chips.append(str(count), style="bold white on grey23")
        chips.append(" ")
    return chips


def render_exposed_files_chip(result: ScanResult) -> Text:
    category_counts = Counter(finding.category for finding in result.findings)
    chips = Text()
    chips.append(" ")
    chips.append("exposed_files", style="bold black on bright_magenta")
    chips.append(" ")
    chips.append(str(category_counts.get("exposed_files", 0)), style="bold white on magenta")
    chips.append(" ")
    return chips


def summarize_affected_urls(affected_urls: list[str]) -> str:
    if not affected_urls:
        return "-"
    visible_urls = affected_urls[:2]
    lines = [f"{index + 1}. {url}" for index, url in enumerate(visible_urls)]
    remaining = len(affected_urls) - len(visible_urls)
    if remaining > 0:
        lines.append(f"+{remaining} more")
    return "\n".join(lines)


def render_policy(policy: AppConfig) -> Table:
    policy_table = Table(title="Active Policy")
    policy_table.add_column("Setting", style="cyan", no_wrap=True)
    policy_table.add_column("Value", style="white")
    policy_table.add_row("Allowed fix level", str(policy.allowed_fix_level))
    policy_table.add_row("Timeout", f"{policy.timeout_seconds:g}s")
    policy_table.add_row("Max pages", str(policy.max_pages))
    policy_table.add_row("Max crawl depth", str(policy.max_crawl_depth))
    policy_table.add_row("Level 2 approval", "required" if policy.require_approval_for_level_2 else "off")
    policy_table.add_row("Level 1 backup", "required" if policy.require_backup_for_level_1 else "off")
    policy_table.add_row("Redact reports", "on" if policy.redact_secrets_in_reports else "off")
    policy_table.add_row("Redact logs", "on" if policy.redact_secrets_in_logs else "off")
    return policy_table


def render_crawl_summary(result: ScanResult) -> Table:
    crawl = Table(title="Crawl Summary")
    crawl.add_column("Field", style="cyan", no_wrap=True)
    crawl.add_column("Value", style="white")
    crawl.add_row("Pages visited", str(len(result.scanned_urls)))
    crawl.add_row("Unique URLs", str(len(set(result.scanned_urls))))
    crawl.add_row("First page", result.scanned_urls[0] if result.scanned_urls else "-")
    crawl.add_row("Last page", result.scanned_urls[-1] if result.scanned_urls else "-")
    if len(result.scanned_urls) > 1:
        crawl.add_row("Seed sources", ", ".join(result.crawl_seed_sources) if result.crawl_seed_sources else "-")
    return crawl


def _render_findings_table(findings: list, title: str = "Findings") -> Table:
    findings_table = Table(title=title)
    findings_table.add_column("Severity", style="magenta", no_wrap=True)
    findings_table.add_column("Category", style="cyan", no_wrap=True)
    findings_table.add_column("Title", style="white")
    findings_table.add_column("Confidence", style="white", no_wrap=True)
    findings_table.add_column("Evidence", style="white")
    findings_table.add_column("Impact", style="white")
    include_affected_urls = any(getattr(finding, "affected_urls", []) for finding in findings)
    if include_affected_urls:
        findings_table.add_column("Affected URLs", style="white")

    if findings:
        for finding in findings:
            row = [
                finding.severity,
                finding.category,
                finding.title,
                finding.confidence,
                summarize_evidence(finding.evidence),
                finding.expected_impact or "-",
            ]
            if include_affected_urls:
                affected_urls = getattr(finding, "affected_urls", [])
                row.append(summarize_affected_urls(affected_urls))
            findings_table.add_row(*row)
    else:
        empty_row = ["-", "-", "No findings", "-", "-", "-"]
        if include_affected_urls:
            empty_row.append("-")
        findings_table.add_row(*empty_row)

    return findings_table


def render_console(result: ScanResult, include_fix_plans: bool = False) -> Group:
    _, _, _ = summarize_counts(result)
    summary = Table(title="Turan Scan")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Target", str(result.target.url))
    summary.add_row("Findings", str(len(result.findings)))
    summary.add_row("Notes", str(len(result.notes)))
    summary.add_row("WAF signals", ", ".join(result.waf_signals) if result.waf_signals else "-")
    summary.add_row("TLS", result.tls_summary.get("status", "-"))
    summary.add_row("Severity counts", render_severity_chips(result))
    summary.add_row("Top categories", render_category_chips(result))
    summary.add_row("Exposed files", render_exposed_files_chip(result))

    findings = _render_findings_table(result.findings)

    if not include_fix_plans:
        return Group(summary, findings)

    plans = Table(title="Proposed Fixes")
    plans.add_column("Finding", style="cyan", no_wrap=True)
    plans.add_column("Next step", style="white")
    plans.add_column("Rollback", style="white")

    if result.fix_plans:
        for plan in result.fix_plans:
            title = next((item.title for item in result.findings if item.id == plan.finding_id), plan.finding_id)
            plans.add_row(title, plan.expected_impact, plan.rollback_command or "-")
    else:
        plans.add_row("-", "No proposed fixes", "-")

    return Group(summary, findings, plans)


def render_fix_decisions(decisions: list[FixDecision]) -> Table:
    apply_table = Table(title="Apply Plan")
    apply_table.add_column("Finding", style="cyan", no_wrap=True)
    apply_table.add_column("Status", style="white", no_wrap=True)
    apply_table.add_column("Next step", style="white")
    apply_table.add_column("Reason", style="white")
    apply_table.add_column("Backup", style="white")
    apply_table.add_column("Artifact", style="white")

    if decisions:
        for decision in decisions:
            apply_table.add_row(
                decision.finding_title,
                decision.status,
                decision.next_step,
                decision.reason,
                decision.backup_path or "-",
                decision.artifact_path or "-",
            )
    else:
        apply_table.add_row("-", "ready", "No fixes to apply", "-", "-", "-")

    return apply_table


def render_interactive_fix_catalog(
    result: ScanResult,
    page_start: int = 0,
    page_size: int = 10,
) -> Table:
    total = len(result.fix_plans)
    if total > page_size:
        page_end = min(page_start + page_size, total)
        title = f"Suggested Fixes (Showing {page_start + 1}-{page_end} of {total})"
    else:
        title = "Suggested Fixes"

    catalog = Table(title=title)
    catalog.add_column("#", style="cyan", no_wrap=True)
    catalog.add_column("Finding", style="white")
    catalog.add_column("First move", style="white")
    catalog.add_column("Rollback", style="white")

    if result.fix_plans:
        page_items = list(zip(result.findings, result.fix_plans))[page_start:page_start + page_size]
        for index, (finding, plan) in enumerate(page_items, start=page_start + 1):
            catalog.add_row(f"#{index}", finding.title, plan.expected_impact, plan.rollback_command or "-")
    else:
        catalog.add_row("-", "No suggested fixes", "-", "-")

    return catalog


def render_local_fix_preview(
    target_path: Path,
    backup_path: Path,
    validation_command: str,
    findings: list[str],
) -> Table:
    preview = Table(title="Local Fix Preview")
    preview.add_column("#", style="cyan", no_wrap=True)
    preview.add_column("Finding", style="white")
    preview.add_column("Target file", style="white")
    preview.add_column("Backup path", style="white")
    preview.add_column("Validation command", style="white")
    preview.add_column("Rollback available", style="white", no_wrap=True)

    if findings:
        for index, finding in enumerate(findings, start=1):
            preview.add_row(
                f"#{index}",
                finding,
                target_path.as_posix(),
                backup_path.as_posix(),
                validation_command,
                "yes",
            )
    else:
        preview.add_row("-", "No supported local fixes selected", "-", "-", "-", "no")

    return preview


def render_local_fix_result(result: LocalFixResult) -> Table:
    table = Table(title="Local Fix")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Target file", result.target_path)
    table.add_row("Status", result.status)
    table.add_row("Reason", result.reason)
    table.add_row("Backup", result.backup_path or "-")
    table.add_row("Validation", result.validation_command or "-")
    table.add_row("Validation output", result.validation_output or "-")
    table.add_row("Notes", "; ".join(result.notes) if result.notes else "-")
    return table


def render_audit_log(events: list[AuditEvent]) -> Table:
    audit_table = Table(title="Audit Log")
    audit_table.add_column("Timestamp", style="cyan", no_wrap=True)
    audit_table.add_column("Action", style="white", no_wrap=True)
    audit_table.add_column("Target", style="white")
    audit_table.add_column("Result", style="white", no_wrap=True)
    audit_table.add_column("Summary", style="white")

    if events:
        for event in events:
            audit_table.add_row(
                event.timestamp,
                event.action,
                event.target,
                event.result,
                describe_audit_event(event),
            )
    else:
        audit_table.add_row("-", "-", "No audit events found", "-", "-")

    return audit_table


def render_doctor_status(status: str) -> Text:
    label = status.upper()
    if status == "ok":
        return Text(label, style="bold white on dark_green")
    if status == "warn":
        return Text(label, style="bold black on bright_yellow")
    if status == "info":
        return Text(label, style="bold black on bright_cyan")
    return Text(label, style="dim")


def render_doctor_details(check: DoctorCheck) -> str:
    if not check.details:
        return "-"
    return "; ".join(f"{key}={value}" for key, value in check.details.items())


def render_application_context(context: ApplicationContext) -> Table:
    discovery = context.discovery
    table = Table(title="Application Context")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Root", context.root)
    table.add_row("Target", context.target.value if context.target is not None else "not resolved")
    table.add_row("Target source", context.target.source if context.target is not None else "not resolved")
    table.add_row("Discovered app", discovery.app_name or "-")
    table.add_row("Public URL", discovery.public_url or "-")
    table.add_row("Local URL", discovery.local_url or "-")
    table.add_row("Env file", discovery.env_file or "-")
    table.add_row("Env source", discovery.env_source or "-")
    table.add_row("Nginx config", discovery.nginx_config or "-")
    table.add_row("Systemd service", discovery.systemd_service or "-")
    table.add_row("Notes", "; ".join(discovery.notes) if discovery.notes else "-")
    return table


def render_doctor_report(report: DoctorReport) -> Group:
    summary = Table(title="Doctor")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Root", report.root)
    summary.add_row("OS", f"{report.os_name} {report.os_release}")
    summary.add_row("Python", report.python_version)

    context_table = render_application_context(report.context) if report.context is not None else None

    checks = Table(title="Local Checks")
    checks.add_column("Area", style="cyan", no_wrap=True)
    checks.add_column("Status", style="white", no_wrap=True)
    checks.add_column("Summary", style="white")
    checks.add_column("Details", style="white")

    if report.checks:
        for check in report.checks:
            checks.add_row(check.name, render_doctor_status(check.status), check.summary, render_doctor_details(check))
    else:
        checks.add_row("-", "-", "No checks ran", "-")

    if context_table is not None:
        return Group(summary, context_table, checks)
    return Group(summary, checks)


def render_comparison(comparison: ComparisonResult) -> Group:
    summary = Table(title="Report Comparison")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Old report", comparison.old_report)
    summary.add_row("New report", comparison.new_report)
    summary.add_row("Context", "; ".join(comparison.context_changes) if comparison.context_changes else "unchanged")
    summary.add_row(
        "Crawl pages",
        f"{len(comparison.old_scanned_urls)} -> {len(comparison.new_scanned_urls)}",
    )
    summary.add_row("Fixed findings", str(len(comparison.fixed_findings)))
    summary.add_row("New findings", str(len(comparison.new_findings)))
    summary.add_row("Unchanged findings", str(len(comparison.unchanged_findings)))
    summary.add_row("Old risk score", str(comparison.old_risk_score))
    summary.add_row("New risk score", str(comparison.new_risk_score))
    summary.add_row("Risk trend", comparison.risk_trend)

    crawl = Table(title="Crawl Coverage")
    crawl.add_column("Field", style="cyan", no_wrap=True)
    crawl.add_column("Value", style="white")
    crawl.add_row("Old URLs", str(len(comparison.old_scanned_urls)))
    crawl.add_row("New URLs", str(len(comparison.new_scanned_urls)))
    crawl.add_row("Added URLs", str(len(comparison.added_scanned_urls)))
    crawl.add_row("Removed URLs", str(len(comparison.removed_scanned_urls)))
    crawl.add_row(
        "Added list",
        ", ".join(comparison.added_scanned_urls[:3]) + (" ..." if len(comparison.added_scanned_urls) > 3 else "")
        if comparison.added_scanned_urls
        else "-",
    )
    crawl.add_row(
        "Removed list",
        ", ".join(comparison.removed_scanned_urls[:3]) + (" ..." if len(comparison.removed_scanned_urls) > 3 else "")
        if comparison.removed_scanned_urls
        else "-",
    )

    fixed = Table(title="Fixed Findings")
    fixed.add_column("Category", style="cyan", no_wrap=True)
    fixed.add_column("Severity", style="white", no_wrap=True)
    fixed.add_column("Title", style="white")
    if comparison.fixed_findings:
        for finding in comparison.fixed_findings:
            fixed.add_row(finding.category, finding.severity, finding.title)
    else:
        fixed.add_row("-", "-", "No findings were fixed")

    new = Table(title="New Findings")
    new.add_column("Category", style="cyan", no_wrap=True)
    new.add_column("Severity", style="white", no_wrap=True)
    new.add_column("Title", style="white")
    if comparison.new_findings:
        for finding in comparison.new_findings:
            new.add_row(finding.category, finding.severity, finding.title)
    else:
        new.add_row("-", "-", "No new findings showed up")

    return Group(summary, crawl, fixed, new)


def render_incident_report(report: IncidentReport) -> Group:
    summary = Table(title="Incident Response")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Target", report.target or "not resolved")
    summary.add_row("Sources", str(len(report.source_files)))
    summary.add_row("Log lines", str(report.total_lines))
    summary.add_row("Findings", str(len(report.findings)))
    summary.add_row("Suspect IPs", ", ".join(report.suspect_ips) if report.suspect_ips else "-")
    summary.add_row("Blocked IPs", ", ".join(report.blocked_ips) if report.blocked_ips else "-")
    summary.add_row("Containment applied", "yes" if report.containment_applied else "no")

    sources = Table(title="Incident Sources")
    sources.add_column("Source", style="cyan")
    sources.add_column("Status", style="white")
    if report.source_files:
        for source in report.source_files[:10]:
            sources.add_row(source, "read")
        if len(report.source_files) > 10:
            sources.add_row("...", f"+{len(report.source_files) - 10} more")
    else:
        sources.add_row("-", "no sources")

    findings = Table(title="Incident Findings")
    findings.add_column("Severity", style="magenta", no_wrap=True)
    findings.add_column("Category", style="cyan", no_wrap=True)
    findings.add_column("Log family", style="white", no_wrap=True)
    findings.add_column("Title", style="white")
    findings.add_column("Source", style="white")
    findings.add_column("Action", style="white")
    findings.add_column("Evidence", style="white")

    if report.findings:
        for finding in report.findings:
            evidence = ", ".join(
                f"{key}={value}"
                for key, value in finding.evidence.items()
                if value not in (None, "")
            )
            findings.add_row(
                finding.severity,
                finding.category,
                finding.log_family or "-",
                finding.title,
                finding.source_file,
                finding.recommended_action or "-",
                evidence or "-",
            )
    else:
        findings.add_row("-", "-", "-", "No active attack indicators found", "-", "-", "-")

    containment = Table(title="Containment")
    containment.add_column("Field", style="cyan", no_wrap=True)
    containment.add_column("Value", style="white")
    containment.add_row("Containment target", report.containment_target or "-")
    containment.add_row("Containment artifact", report.containment_artifact or "-")
    containment.add_row("Notes", "; ".join(report.notes) if report.notes else "-")

    if report.context is not None:
        return Group(summary, render_application_context(report.context), sources, findings, containment)
    return Group(summary, sources, findings, containment)


def render_integrity_report(report: IntegrityReport) -> Group:
    summary = Table(title="File Integrity")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Root", report.root)
    summary.add_row("Baseline", report.baseline_path or "not supplied")
    summary.add_row("Monitored paths", str(len(report.monitored_paths)))
    summary.add_row("Files tracked", str(len(report.files)))
    summary.add_row("Findings", str(len(report.findings)))

    if report.context is not None:
        context_table = render_application_context(report.context)
    else:
        context_table = None

    findings = Table(title="Integrity Findings")
    findings.add_column("Severity", style="magenta", no_wrap=True)
    findings.add_column("Category", style="cyan", no_wrap=True)
    findings.add_column("Kind", style="white", no_wrap=True)
    findings.add_column("Path", style="white")
    findings.add_column("Action", style="white")

    if report.findings:
        for finding in report.findings:
            findings.add_row(
                finding.severity,
                finding.category,
                finding.kind,
                finding.path,
                finding.recommended_action or "-",
            )
    else:
        findings.add_row("-", "-", "-", "No integrity drift detected", "-")

    files = Table(title="Monitored Files")
    files.add_column("Status", style="white", no_wrap=True)
    files.add_column("Category", style="cyan", no_wrap=True)
    files.add_column("Kind", style="white", no_wrap=True)
    files.add_column("Path", style="white")
    files.add_column("SHA256", style="white")

    if report.files:
        for file_item in report.files[:20]:
            files.add_row(
                file_item.status,
                file_item.category,
                file_item.kind,
                file_item.path,
                file_item.sha256 or "-",
            )
        if len(report.files) > 20:
            files.add_row("...", "-", "-", f"+{len(report.files) - 20} more", "-")
    else:
        files.add_row("-", "-", "-", "No files monitored", "-")

    notes = Table(title="Notes")
    notes.add_column("Message", style="white")
    if report.notes:
        for note in report.notes[:6]:
            notes.add_row(note)
    else:
        notes.add_row("-")

    if context_table is not None:
        return Group(summary, context_table, findings, files, notes)
    return Group(summary, findings, files, notes)


def render_timeline_report(report: TimelineReport) -> Group:
    summary = Table(title="Timeline")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Incident report", report.incident_report or "-")
    summary.add_row("Audit log", report.audit_log or "-")
    summary.add_row("Events", str(len(report.events)))

    events = Table(title="Chronology")
    events.add_column("Timestamp", style="white", no_wrap=True)
    events.add_column("Kind", style="cyan", no_wrap=True)
    events.add_column("Title", style="white")
    events.add_column("Source", style="white")
    events.add_column("Details", style="white")

    if report.events:
        for event in report.events:
            details = ", ".join(f"{key}={value}" for key, value in event.details.items() if value not in (None, ""))
            events.add_row(event.timestamp or "-", event.kind, event.title, event.source or "-", details or "-")
    else:
        events.add_row("-", "-", "No events", "-", "-")

    notes = Table(title="Notes")
    notes.add_column("Message", style="white")
    if report.notes:
        for note in report.notes[:6]:
            notes.add_row(note)
    else:
        notes.add_row("-")

    return Group(summary, events, notes)


def render_drift_report(report: DriftReport) -> Group:
    summary = Table(title="Baseline Drift")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Report type", report.report_type)
    summary.add_row("Baseline", report.baseline_report)
    summary.add_row("Current", report.current_report)
    summary.add_row("Summary", report.summary)
    summary.add_row("Findings", str(len(report.findings)))

    findings = Table(title="Drift Findings")
    findings.add_column("Severity", style="magenta", no_wrap=True)
    findings.add_column("Category", style="cyan", no_wrap=True)
    findings.add_column("Kind", style="white", no_wrap=True)
    findings.add_column("Title", style="white")
    findings.add_column("Baseline", style="white")
    findings.add_column("Current", style="white")
    findings.add_column("Note", style="white")

    if report.findings:
        for finding in report.findings:
            findings.add_row(
                finding.severity,
                finding.category,
                finding.kind,
                finding.title,
                finding.baseline_value or "-",
                finding.current_value or "-",
                finding.note or "-",
            )
    else:
        findings.add_row("-", "-", "-", "No drift detected", "-", "-", "-")

    notes = Table(title="Notes")
    notes.add_column("Message", style="white")
    if report.notes:
        for note in report.notes[:6]:
            notes.add_row(note)
    else:
        notes.add_row("-")

    return Group(summary, findings, notes)


def render_secret_report(report: SecretExposureReport) -> Group:
    summary = Table(title="Secret Exposure")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Root", report.root)
    summary.add_row("Source files", str(len(report.source_files)))
    summary.add_row("Findings", str(len(report.findings)))

    findings = Table(title="Secret Findings")
    findings.add_column("Severity", style="magenta", no_wrap=True)
    findings.add_column("Category", style="cyan", no_wrap=True)
    findings.add_column("Path", style="white")
    findings.add_column("Line", style="white", no_wrap=True)
    findings.add_column("Title", style="white")
    findings.add_column("Action", style="white")

    if report.findings:
        for finding in report.findings:
            findings.add_row(
                finding.severity,
                finding.category,
                finding.path,
                str(finding.line_number),
                finding.title,
                finding.recommended_action or "-",
            )
    else:
        findings.add_row("-", "-", "No obvious secret exposures found", "-", "-", "-")

    notes = Table(title="Notes")
    notes.add_column("Message", style="white")
    if report.notes:
        for note in report.notes[:6]:
            notes.add_row(note)
    else:
        notes.add_row("-")

    return Group(summary, findings, notes)


def render_bundle_report(report: ReportBundle) -> Group:
    summary = Table(title="Report Bundle")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Source report", report.source_report)
    summary.add_row("Archive", report.output_path)
    summary.add_row("Items", str(len(report.items)))

    items = Table(title="Bundle Contents")
    items.add_column("Kind", style="cyan", no_wrap=True)
    items.add_column("Path", style="white")
    items.add_column("Archive name", style="white")
    items.add_column("Size", style="white", no_wrap=True)
    if report.items:
        for item in report.items:
            items.add_row(item.kind, item.path, item.arcname, str(item.size) if item.size is not None else "-")
    else:
        items.add_row("-", "No files bundled", "-", "-")

    notes = Table(title="Notes")
    notes.add_column("Message", style="white")
    if report.notes:
        for note in report.notes[:6]:
            notes.add_row(note)
    else:
        notes.add_row("-")

    return Group(summary, items, notes)
