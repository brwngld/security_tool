from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.audit import AuditEvent, describe_audit_event, read_audit_events
from app.models import IncidentFinding, IncidentReport, TimelineEvent, TimelineReport


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _format_timestamp(timestamp: datetime | None) -> str | None:
    return timestamp.isoformat() if timestamp is not None else None


def _latest_timestamp(events: list[TimelineEvent]) -> datetime | None:
    parsed = [_parse_timestamp(event.timestamp) for event in events if event.timestamp]
    parsed = [item for item in parsed if item is not None]
    if not parsed:
        return None
    return max(parsed)


def _finding_event(finding: IncidentFinding) -> TimelineEvent:
    timestamp = None
    for key in ("first_seen", "last_seen"):
        value = finding.evidence.get(key)
        if isinstance(value, str) and value.strip():
            timestamp = value.strip()
            break
    return TimelineEvent(
        timestamp=timestamp,
        kind="log finding",
        title=finding.title,
        source=finding.source_file,
        details={
            "category": finding.category,
            "severity": finding.severity,
            "log_family": finding.log_family,
            "action": finding.recommended_action,
            "block": finding.block_action,
        },
    )


def _containment_event(report: IncidentReport, existing_events: list[TimelineEvent]) -> TimelineEvent | None:
    if not report.containment_applied and not report.containment_artifact and not report.containment_target:
        return None
    latest = _latest_timestamp(existing_events)
    if latest is not None:
        latest = latest + timedelta(seconds=1)
    timestamp = _format_timestamp(latest)
    return TimelineEvent(
        timestamp=timestamp,
        kind="containment",
        title="Containment applied",
        source=report.containment_target or report.containment_artifact,
        details={
            "applied": report.containment_applied,
            "artifact": report.containment_artifact,
            "target": report.containment_target,
        },
    )


def _audit_event(event: AuditEvent) -> TimelineEvent:
    return TimelineEvent(
        timestamp=event.timestamp,
        kind="audit",
        title=f"{event.action} {event.result}",
        source=event.target,
        details={
            "action": event.action,
            "result": event.result,
            "severity": event.severity,
            "category": event.category,
            "details": describe_audit_event(event),
        },
    )


def build_timeline_report(
    incident_report: IncidentReport,
    *,
    incident_report_path: str | Path | None = None,
    audit_events: list[AuditEvent] | None = None,
    audit_log_path: str | Path | None = None,
) -> TimelineReport:
    events: list[TimelineEvent] = [_finding_event(finding) for finding in incident_report.findings]
    if audit_events:
        events.extend(_audit_event(event) for event in audit_events)
    containment_event = _containment_event(incident_report, events)
    if containment_event is not None:
        events.append(containment_event)

    events.sort(key=lambda event: _parse_timestamp(event.timestamp) or datetime.max.replace(tzinfo=UTC))

    notes: list[str] = []
    if not events:
        notes.append("No timeline events could be assembled from the provided report.")
    else:
        notes.append(f"Assembled {len(events)} event(s) in chronological order.")

    return TimelineReport(
        incident_report=str(incident_report_path) if incident_report_path is not None else incident_report.target,
        audit_log=str(audit_log_path) if audit_log_path is not None else None,
        events=events,
        notes=notes,
    )


def load_timeline_report_from_path(incident_report_path: str | Path, audit_log_path: str | Path | None = None) -> TimelineReport:
    incident_path = Path(incident_report_path)
    report = IncidentReport.model_validate_json(incident_path.read_text(encoding="utf-8"))
    audit_events = read_audit_events(audit_log_path) if audit_log_path is not None else None
    return build_timeline_report(
        report,
        incident_report_path=incident_path,
        audit_events=audit_events,
        audit_log_path=audit_log_path,
    )
