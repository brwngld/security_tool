from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from app.models import Finding, FixDecision, FixPlan, IncidentReport, IntegrityReport, ScanResult, VulnerabilityReport, WatchReport
from app.models import LocalFixResult


class AuditEvent(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    action: str
    target: str
    result: str
    actor: str = "local-user"
    finding_id: str | None = None
    finding_title: str | None = None
    category: str | None = None
    severity: str | None = None
    fix_level: int | None = None
    approval_status: str | None = None
    policy_level: int | None = None
    backup_path: str | None = None
    rollback_command: str | None = None
    notes: list[str] = Field(default_factory=list)
    details: dict[str, str | int | bool | None] = Field(default_factory=dict)


def append_audit_event(path: str | Path, event: AuditEvent) -> None:
    audit_path = Path(path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event.model_dump(), ensure_ascii=True) + "\n")


def write_audit_events_json(path: str | Path, events: list[AuditEvent]) -> None:
    audit_path = Path(path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [event.model_dump() for event in events]
    audit_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def read_audit_events(path: str | Path) -> list[AuditEvent]:
    audit_path = Path(path)
    if not audit_path.exists():
        return []

    events: list[AuditEvent] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(AuditEvent.model_validate_json(line))
        except Exception:
            continue
    return events


def filter_audit_events(
    events: list[AuditEvent],
    action: str | None = None,
    target: str | None = None,
) -> list[AuditEvent]:
    filtered = events
    if action:
        filtered = [event for event in filtered if event.action == action]
    if target:
        filtered = [event for event in filtered if target in event.target]
    return filtered


def build_scan_audit_event(result: ScanResult, policy_level: int, action: str) -> AuditEvent:
    return AuditEvent(
        action=action,
        target=str(result.target.url),
        result="completed",
        policy_level=policy_level,
        severity="info",
        details={
            "findings": len(result.findings),
            "notes": len(result.notes),
            "waf_signals": len(result.waf_signals),
            "tls_status": result.tls_summary.get("status", "-"),
        },
    )


def build_fix_audit_event(finding: Finding, plan: FixPlan, decision: FixDecision, policy_level: int) -> AuditEvent:
    return AuditEvent(
        action="fix",
        target=finding.target_url,
        result=decision.status,
        finding_id=finding.id,
        finding_title=finding.title,
        category=finding.category,
        severity=finding.severity,
        fix_level=plan.fix_level,
        approval_status=decision.status,
        policy_level=policy_level,
        backup_path=decision.backup_path or plan.backup_path,
        rollback_command=plan.rollback_command,
        details={
            "next_step": decision.next_step,
            "reason": decision.reason,
            "backup_path": decision.backup_path or plan.backup_path,
            "artifact_path": decision.artifact_path,
        },
    )


def build_local_fix_audit_event(target: str, result: LocalFixResult, policy_level: int | None = None) -> AuditEvent:
    return AuditEvent(
        action="local_fix",
        target=target,
        result=result.status,
        policy_level=policy_level,
        severity="info",
        backup_path=result.backup_path,
        details={
            "target_path": result.target_path,
            "reason": result.reason,
            "backup_path": result.backup_path,
            "validation_command": result.validation_command,
            "validation_output": result.validation_output,
        },
    )


def build_incident_audit_event(report: IncidentReport, policy_level: int | None = None) -> AuditEvent:
    target = report.target or report.containment_target or "incident"
    return AuditEvent(
        action="incident",
        target=target,
        result="contained" if report.containment_applied else "detected",
        policy_level=policy_level,
        severity="high" if report.blocked_ips else "medium",
        details={
            "sources": len(report.source_files),
            "findings": len(report.findings),
            "suspect_ips": len(report.suspect_ips),
            "blocked_ips": len(report.blocked_ips),
            "containment_applied": report.containment_applied,
            "containment_target": report.containment_target,
            "containment_artifact": report.containment_artifact,
        },
    )


def build_integrity_audit_event(report: IntegrityReport, policy_level: int | None = None) -> AuditEvent:
    target = report.root or "integrity"
    return AuditEvent(
        action="integrity",
        target=target,
        result="drift" if report.findings else "clean",
        policy_level=policy_level,
        severity="high" if report.findings else "info",
        details={
            "root": report.root,
            "baseline_path": report.baseline_path,
            "monitored_paths": len(report.monitored_paths),
            "files": len(report.files),
            "findings": len(report.findings),
        },
    )


def build_watch_audit_event(report: WatchReport, policy_level: int | None = None) -> AuditEvent:
    target = report.context.target.value if report.context is not None and report.context.target is not None else report.root
    return AuditEvent(
        action="watch",
        target=target,
        result=report.response_label,
        policy_level=policy_level,
        severity=report.risk_level,
        details={
            "mode": report.mode,
            "cycles": report.cycles,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level,
            "response": report.response_label,
            "sources": len(report.sources),
            "observations": len(report.observations),
            "findings": len(report.findings),
        },
    )


def build_vuln_audit_event(report: VulnerabilityReport, policy_level: int | None = None) -> AuditEvent:
    found_count = sum(1 for component in report.components if component.status == "found")
    return AuditEvent(
        action="vuln_scan",
        target=report.root,
        result="findings" if report.findings else "inventory",
        policy_level=policy_level,
        severity="high" if any(finding.severity in {"critical", "high"} for finding in report.findings) else "info",
        details={
            "components_checked": len(report.components),
            "components_found": found_count,
            "findings": len(report.findings),
            "cve_matching": report.cve_matching,
        },
    )


def describe_audit_event(event: AuditEvent) -> str:
    if event.action == "fix" and event.finding_title:
        pieces = [event.finding_title]
        backup_path = event.backup_path or event.details.get("backup_path")
        artifact_path = event.details.get("artifact_path")
        extras = []
        if backup_path:
            extras.append(f"backup={backup_path}")
        if artifact_path:
            extras.append(f"artifact={artifact_path}")
        if extras:
            pieces.append(f"({'; '.join(extras)})")
        return " ".join(pieces)
    if event.action == "watch":
        pieces = [
            f"risk={event.details.get('risk_level', event.severity or '-')}",
            f"response={event.result}",
            f"findings={event.details.get('findings', 0)}",
        ]
        return ", ".join(pieces)
    if event.details:
        keys = list(event.details.keys())[:2]
        return ", ".join(f"{key}={event.details[key]}" for key in keys)
    return "-"
