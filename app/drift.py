from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.comparison import compare_scan_results, summarize_comparison
from app.diagnostics import DoctorReport
from app.models import ComparisonResult, DriftFinding, DriftReport, IncidentReport, IntegrityReport, ScanResult


def _load_model(path: Path) -> Any:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        if "checks" in payload:
            return DoctorReport.model_validate(payload)
        if "files" in payload and "monitored_paths" in payload:
            return IntegrityReport.model_validate(payload)
        if "source_files" in payload and "blocked_ips" in payload:
            return IncidentReport.model_validate(payload)
        if "target" in payload and "fix_plans" in payload:
            return ScanResult.model_validate(payload)
    raise ValueError(f"Unsupported report format: {path}")


def _compare_scan_reports(baseline_path: Path, current_path: Path, baseline: ScanResult, current: ScanResult) -> DriftReport:
    comparison: ComparisonResult = compare_scan_results(baseline, current, str(baseline_path), str(current_path))
    findings: list[DriftFinding] = []
    if comparison.new_findings:
        findings.append(
            DriftFinding(
                id="drift-scan-new-findings",
                category="headers",
                kind="scan",
                severity="high" if any(item.severity in {"high", "critical"} for item in comparison.new_findings) else "medium",
                title=f"{len(comparison.new_findings)} new finding(s) appeared",
                baseline_value=str(len(comparison.fixed_findings)),
                current_value=str(len(comparison.new_findings)),
                note=", ".join(item.title for item in comparison.new_findings[:3]),
            )
        )
    if comparison.fixed_findings:
        findings.append(
            DriftFinding(
                id="drift-scan-fixed-findings",
                category="headers",
                kind="scan",
                severity="info",
                title=f"{len(comparison.fixed_findings)} finding(s) disappeared",
                baseline_value=str(len(comparison.fixed_findings)),
                current_value="0",
                note=", ".join(item.title for item in comparison.fixed_findings[:3]),
            )
        )
    if comparison.added_scanned_urls or comparison.removed_scanned_urls:
        findings.append(
            DriftFinding(
                id="drift-scan-crawl",
                category="crawl",
                kind="scan",
                severity="medium",
                title="Crawl coverage changed",
                baseline_value=str(len(comparison.old_scanned_urls)),
                current_value=str(len(comparison.new_scanned_urls)),
                note=f"{len(comparison.added_scanned_urls)} added, {len(comparison.removed_scanned_urls)} removed",
            )
        )
    if comparison.new_risk_score != comparison.old_risk_score:
        findings.append(
            DriftFinding(
                id="drift-scan-risk",
                category="risk",
                kind="scan",
                severity="high" if comparison.new_risk_score > comparison.old_risk_score else "low",
                title="Risk score changed",
                baseline_value=str(comparison.old_risk_score),
                current_value=str(comparison.new_risk_score),
                note=summarize_comparison(comparison),
            )
        )

    summary = summarize_comparison(comparison)
    return DriftReport(
        baseline_report=str(baseline_path),
        current_report=str(current_path),
        report_type="scan",
        summary=summary,
        findings=findings,
        notes=[summary],
    )


def _compare_integrity_reports(baseline_path: Path, current_path: Path, baseline: IntegrityReport, current: IntegrityReport) -> DriftReport:
    baseline_files = {item.path: item for item in baseline.files}
    current_files = {item.path: item for item in current.files}
    baseline_paths = set(baseline_files)
    current_paths = set(current_files)
    added = sorted(current_paths - baseline_paths)
    removed = sorted(baseline_paths - current_paths)
    changed = sorted(
        path for path in baseline_paths & current_paths if baseline_files[path].sha256 != current_files[path].sha256 or baseline_files[path].status != current_files[path].status
    )
    findings: list[DriftFinding] = []
    if changed:
        findings.append(
            DriftFinding(
                id="drift-integrity-changed",
                category="files",
                kind="integrity",
                severity="high",
                title=f"{len(changed)} file(s) changed",
                baseline_value=str(len(baseline.files)),
                current_value=str(len(current.files)),
                note=", ".join(changed[:3]),
            )
        )
    if removed:
        findings.append(
            DriftFinding(
                id="drift-integrity-removed",
                category="files",
                kind="integrity",
                severity="high" if any(baseline_files[path].category in {"config", "startup"} for path in removed) else "medium",
                title=f"{len(removed)} monitored file(s) disappeared",
                baseline_value=str(len(baseline.files)),
                current_value=str(len(current.files)),
                note=", ".join(removed[:3]),
            )
        )
    if added:
        findings.append(
            DriftFinding(
                id="drift-integrity-added",
                category="files",
                kind="integrity",
                severity="medium" if any(current_files[path].category in {"config", "startup"} for path in added) else "low",
                title=f"{len(added)} monitored file(s) appeared",
                baseline_value=str(len(baseline.files)),
                current_value=str(len(current.files)),
                note=", ".join(added[:3]),
            )
        )

    changed_count = len(changed)
    removed_count = len(removed)
    added_count = len(added)
    summary = f"Integrity drift: {changed_count} changed, {removed_count} missing, {added_count} new."
    return DriftReport(
        baseline_report=str(baseline_path),
        current_report=str(current_path),
        report_type="integrity",
        summary=summary,
        findings=findings,
        notes=[summary, f"Baseline: {baseline.baseline_path or 'not supplied'}"],
    )


def _compare_incident_reports(baseline_path: Path, current_path: Path, baseline: IncidentReport, current: IncidentReport) -> DriftReport:
    baseline_families = {finding.log_family for finding in baseline.findings if finding.log_family}
    current_families = {finding.log_family for finding in current.findings if finding.log_family}
    added_families = sorted(current_families - baseline_families)
    removed_families = sorted(baseline_families - current_families)
    findings: list[DriftFinding] = []
    if added_families:
        findings.append(
            DriftFinding(
                id="drift-incident-new-families",
                category="logs",
                kind="incident",
                severity="medium",
                title=f"{len(added_families)} new log family/families appeared",
                baseline_value=", ".join(sorted(baseline_families)) or "-",
                current_value=", ".join(sorted(current_families)) or "-",
                note=", ".join(added_families[:3]),
            )
        )
    if removed_families:
        findings.append(
            DriftFinding(
                id="drift-incident-removed-families",
                category="logs",
                kind="incident",
                severity="info",
                title=f"{len(removed_families)} log family/families disappeared",
                baseline_value=", ".join(sorted(baseline_families)) or "-",
                current_value=", ".join(sorted(current_families)) or "-",
                note=", ".join(removed_families[:3]),
            )
        )
    if baseline.blocked_ips != current.blocked_ips:
        findings.append(
            DriftFinding(
                id="drift-incident-blocked-ips",
                category="containment",
                kind="incident",
                severity="high",
                title="Blocked IP list changed",
                baseline_value=", ".join(baseline.blocked_ips) or "-",
                current_value=", ".join(current.blocked_ips) or "-",
                note=f"{len(current.blocked_ips)} current blocked IPs",
            )
        )

    summary = f"Incident drift: {len(current.findings)} current findings, {len(current.blocked_ips)} blocked IPs."
    return DriftReport(
        baseline_report=str(baseline_path),
        current_report=str(current_path),
        report_type="incident",
        summary=summary,
        findings=findings,
        notes=[summary],
    )


def _compare_doctor_reports(baseline_path: Path, current_path: Path, baseline: DoctorReport, current: DoctorReport) -> DriftReport:
    baseline_checks = {check.name: check for check in baseline.checks}
    current_checks = {check.name: check for check in current.checks}
    findings: list[DriftFinding] = []
    for name in sorted(set(baseline_checks) & set(current_checks)):
        baseline_check = baseline_checks[name]
        current_check = current_checks[name]
        if baseline_check.status != current_check.status or baseline_check.summary != current_check.summary:
            severity = "high" if "warn" in {baseline_check.status, current_check.status} else "medium"
            findings.append(
                DriftFinding(
                    id=f"drift-doctor-{name.lower().replace(' ', '-')}",
                    category="config",
                    kind="doctor",
                    severity=severity,
                    title=f"{name} changed",
                    baseline_value=f"{baseline_check.status}: {baseline_check.summary}",
                    current_value=f"{current_check.status}: {current_check.summary}",
                    note=current_check.details.get("path") or baseline_check.details.get("path") or "",
                )
            )

    removed = sorted(set(baseline_checks) - set(current_checks))
    added = sorted(set(current_checks) - set(baseline_checks))
    if removed:
        findings.append(
            DriftFinding(
                id="drift-doctor-removed",
                category="config",
                kind="doctor",
                severity="medium",
                title=f"{len(removed)} check(s) disappeared",
                baseline_value=", ".join(removed),
                current_value=", ".join(sorted(current_checks)),
                note=", ".join(removed[:3]),
            )
        )
    if added:
        findings.append(
            DriftFinding(
                id="drift-doctor-added",
                category="config",
                kind="doctor",
                severity="low",
                title=f"{len(added)} check(s) appeared",
                baseline_value=", ".join(sorted(baseline_checks)),
                current_value=", ".join(added),
                note=", ".join(added[:3]),
            )
        )

    summary = f"Doctor drift: {len(findings)} change(s) across config and runtime checks."
    return DriftReport(
        baseline_report=str(baseline_path),
        current_report=str(current_path),
        report_type="doctor",
        summary=summary,
        findings=findings,
        notes=[summary],
    )


def analyze_report_drift(baseline_path: Path, current_path: Path) -> DriftReport:
    baseline = _load_model(Path(baseline_path))
    current = _load_model(Path(current_path))

    if isinstance(baseline, ScanResult) and isinstance(current, ScanResult):
        return _compare_scan_reports(Path(baseline_path), Path(current_path), baseline, current)
    if isinstance(baseline, IntegrityReport) and isinstance(current, IntegrityReport):
        return _compare_integrity_reports(Path(baseline_path), Path(current_path), baseline, current)
    if isinstance(baseline, IncidentReport) and isinstance(current, IncidentReport):
        return _compare_incident_reports(Path(baseline_path), Path(current_path), baseline, current)
    if isinstance(baseline, DoctorReport) and isinstance(current, DoctorReport):
        return _compare_doctor_reports(Path(baseline_path), Path(current_path), baseline, current)

    raise ValueError("Baseline and current reports must be the same PsyberShield report type.")

