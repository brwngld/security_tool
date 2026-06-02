from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from app.context import resolve_application_context
from app.diagnostics import DoctorCheck, check_local_ports, check_process_and_port_activity
from app.incident import analyze_incident_sources, collect_live_incident_sources, default_incident_sources
from app.integrity import analyze_integrity_sources
from app.models import (
    IncidentFinding,
    IntegrityFinding,
    WatchFinding,
    WatchObservation,
    WatchReport,
)


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "info": 1,
}


def response_label_for_severity(severity: str) -> str:
    if severity == "critical":
        return "safe contain"
    if severity == "high":
        return "recommend contain"
    if severity == "medium":
        return "report"
    return "log only"


def _watch_risk_level(findings: list[WatchFinding]) -> str:
    if not findings:
        return "low"
    return min(findings, key=lambda item: _SEVERITY_ORDER.get(item.severity, 99)).severity


def _watch_risk_score(findings: list[WatchFinding]) -> int:
    score = sum(_SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)
    return min(score, 100)


def _dedupe_notes(notes: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for note in notes:
        clean = note.strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        deduped.append(clean)
    return deduped


def _convert_incident_finding(finding: IncidentFinding) -> WatchFinding:
    response_label = response_label_for_severity(finding.severity)
    return WatchFinding(
        id=f"incident:{finding.id}",
        source="incident",
        category=finding.category,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        evidence=finding.evidence,
        recommended_action=finding.recommended_action,
        response_label=response_label,
    )


def _convert_integrity_finding(finding: IntegrityFinding) -> WatchFinding:
    response_label = response_label_for_severity(finding.severity)
    return WatchFinding(
        id=f"integrity:{finding.id}",
        source="integrity",
        category=finding.category,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        evidence=finding.evidence,
        recommended_action=finding.recommended_action,
        response_label=response_label,
    )


def _convert_process_check(check: DoctorCheck) -> list[WatchFinding]:
    if check.status != "warn":
        return []

    details = dict(check.details)
    severity = "high" if details.get("outbound", "none") != "none" else "medium"
    return [
        WatchFinding(
            id="doctor:process-and-port-activity",
            source="doctor",
            category="process-port",
            severity=severity,
            title=check.name,
            description=check.summary,
            evidence=details,
            recommended_action="Review the listed listeners and outbound connections before changing firewall policy.",
            response_label=response_label_for_severity(severity),
        )
    ]


def _observation_from_check(source: str, kind: str, check: DoctorCheck) -> WatchObservation:
    return WatchObservation(
        source=source,
        kind=kind,
        status=check.status,
        summary=check.summary,
        details=check.details,
    )


def build_watch_report(
    *,
    root: Path,
    context,
    mode: str,
    interval_seconds: float,
    policy_path: Path | None,
    source_paths: Iterable[Path],
    incident_report,
    integrity_report,
    process_check: DoctorCheck,
    local_ports_check: DoctorCheck,
    live_notes: Iterable[str] = (),
    extra_notes: Iterable[str] = (),
    cycles: int = 1,
) -> WatchReport:
    watch_findings: list[WatchFinding] = []
    observations: list[WatchObservation] = []
    notes: list[str] = []
    live_notes_list = [note for note in live_notes if str(note).strip()]

    if incident_report is not None:
        observations.append(
            WatchObservation(
                source="incident",
                kind="log analysis",
                status="warn" if incident_report.findings else "ok",
                summary=f"Analyzed {len(incident_report.source_files)} log source(s) and found {len(incident_report.findings)} finding(s).",
                details={
                    "sources": len(incident_report.source_files),
                    "total_lines": incident_report.total_lines,
                    "blocked_ips": len(incident_report.blocked_ips),
                },
            )
        )
        watch_findings.extend(_convert_incident_finding(finding) for finding in incident_report.findings)
        notes.extend(incident_report.notes)
        if incident_report.blocked_ips:
            notes.append(
                "Containment candidates identified: "
                + ", ".join(incident_report.blocked_ips)
                + ". PsyberShield watch stays log-only in v1."
            )

    if integrity_report is not None:
        observations.append(
            WatchObservation(
                source="integrity",
                kind="file drift",
                status="warn" if integrity_report.findings else ("info" if not integrity_report.baseline_path else "ok"),
                summary=(
                    f"Compared {len(integrity_report.files)} file snapshot(s) and found {len(integrity_report.findings)} drift finding(s)."
                    if integrity_report.baseline_path
                    else "Captured a fresh integrity snapshot; no baseline was supplied."
                ),
                details={
                    "root": integrity_report.root,
                    "baseline_path": integrity_report.baseline_path or "-",
                    "monitored_paths": len(integrity_report.monitored_paths),
                    "files": len(integrity_report.files),
                    "findings": len(integrity_report.findings),
                },
            )
        )
        watch_findings.extend(_convert_integrity_finding(finding) for finding in integrity_report.findings)
        notes.extend(integrity_report.notes)

    observations.append(_observation_from_check("doctor", "process/port activity", process_check))
    observations.append(_observation_from_check("doctor", "localhost ports", local_ports_check))
    watch_findings.extend(_convert_process_check(process_check))
    if local_ports_check.details:
        notes.append(local_ports_check.summary)

    if context is not None and context.discovery is not None and context.discovery.notes:
        observations.append(
            WatchObservation(
                source="context",
                kind="discovery",
                status="info",
                summary="Application context discovery notes were available.",
                details={"notes": "; ".join(context.discovery.notes)},
            )
        )
        notes.extend(context.discovery.notes)

    if live_notes_list:
        observations.append(
            WatchObservation(
                source="capture",
                kind="live snapshot",
                status="info",
                summary=f"Captured {len(live_notes_list)} live snapshot note(s).",
                details={"notes": "; ".join(live_notes_list)},
            )
        )
        notes.extend(live_notes_list)

    notes.extend(extra_notes)
    notes = _dedupe_notes(notes)
    source_list = sorted({str(path) for path in source_paths})
    risk_level = _watch_risk_level(watch_findings)
    risk_score = _watch_risk_score(watch_findings)
    response_label = response_label_for_severity(risk_level)

    return WatchReport(
        context=context,
        root=str(root),
        mode=mode,
        interval_seconds=interval_seconds,
        policy_path=str(policy_path) if policy_path is not None else None,
        sources=source_list,
        observations=observations,
        findings=watch_findings,
        risk_score=risk_score,
        risk_level=risk_level,
        response_label=response_label,
        notes=notes,
        cycles=cycles,
        last_run_at=datetime.now(UTC).isoformat(),
    )


def run_watch_snapshot(
    *,
    root: Path,
    env_file: Path | None = None,
    nginx_config: Path | None = None,
    logs: Iterable[Path] | None = None,
    journal_units: Iterable[str] | None = None,
    event_log_names: Iterable[str] | None = None,
    tail_files: Iterable[Path] | None = None,
    tail_lines: int = 250,
    baseline_path: Path | None = None,
    policy_path: Path | None = None,
    mode: str = "snapshot",
    interval_seconds: float = 0.0,
) -> WatchReport:
    root_path = Path(root)
    context = resolve_application_context(None, root_path, env_file, nginx_config, require_target=False)

    source_paths = list(logs or [])
    if not source_paths:
        source_paths = default_incident_sources(root_path, context.target.value if context.target is not None else None)

    live_notes: list[str] = []
    if journal_units or event_log_names or tail_files:
        live_sources, live_notes = collect_live_incident_sources(
            root=root_path,
            line_count=tail_lines,
            journal_units=journal_units,
            event_log_names=event_log_names,
            tail_files=tail_files,
            output_dir=root_path / "outputs" / "watch-live",
        )
        source_paths.extend(live_sources)

    incident_report = analyze_incident_sources(
        source_paths,
        root=root_path,
        url=str(context.target.value) if context.target is not None else None,
        env_file=env_file,
        nginx_config=nginx_config,
    )
    integrity_report = analyze_integrity_sources(root_path, baseline_path=baseline_path)
    process_check = check_process_and_port_activity()
    local_ports_check = check_local_ports()

    notes: list[str] = []
    if policy_path is not None:
        notes.append(f"Policy file loaded from {policy_path}")
    notes.extend(live_notes)

    return build_watch_report(
        root=root_path,
        context=context,
        mode=mode,
        interval_seconds=interval_seconds,
        policy_path=policy_path,
        source_paths=source_paths + [Path(path) for path in incident_report.source_files],
        incident_report=incident_report,
        integrity_report=integrity_report,
        process_check=process_check,
        local_ports_check=local_ports_check,
        live_notes=live_notes,
        extra_notes=notes,
    )
